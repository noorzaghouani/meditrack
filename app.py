"""MediTrack — Application de gestion de cabinet médical."""
import json
import logging
import os
import re
import secrets
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, String,
                        Text, UniqueConstraint, create_engine, delete, select,
                        text)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Configuration
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = AWS_REGION
os.environ["AWS_REGION"] = AWS_REGION
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///meditrack.db")
S3_BUCKET    = os.environ.get("S3_BUCKET", "")
KMS_KEY_ID   = os.environ.get("KMS_KEY_ID", "")
UPLOAD_DIR   = os.environ.get("UPLOAD_DIR", "uploads")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "")
SNS_TOPIC_ARN    = os.environ.get("SNS_TOPIC_ARN", "")
MFA_DEMO     = os.environ.get("MFA_DEMO", "0") == "1"
SEED_PASSWORD= os.environ.get("SEED_PASSWORD")
if not SEED_PASSWORD:
    raise RuntimeError("SEED_PASSWORD manquante : définissez-la dans le fichier .env")

# AWS Cognito
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID    = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET= os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_DOMAIN       = os.environ.get("COGNITO_DOMAIN", "")
COGNITO_REGION       = os.environ.get("AWS_REGION", "us-east-1")
APP_URL              = os.environ.get("APP_URL", "http://localhost:8080")

# CloudWatch
CLOUDWATCH_LOG_GROUP = os.environ.get("CLOUDWATCH_LOG_GROUP", "")

# Emails
EMAIL_ADMIN      = os.environ.get("EMAIL_ADMIN",      "admin@meditrack.local")
EMAIL_DR_SABER   = os.environ.get("EMAIL_DR_SABER",   "dr.saber@meditrack.local")
EMAIL_DR_TAYSSIR = os.environ.get("EMAIL_DR_TAYSSIR", "dr.tayssir@meditrack.local")
EMAIL_SECRETAIRE = os.environ.get("EMAIL_SECRETAIRE", "secretaire@meditrack.local")
EMAIL_NOOR       = os.environ.get("EMAIL_NOOR",       "noor@meditrack.local")
EMAIL_MAMOUN     = os.environ.get("EMAIL_MAMOUN",     "mamoun@meditrack.local")

MAX_FAILED = int(os.environ.get("LOGIN_MAX_FAILED", 5))
LOCK_MINUTES = int(os.environ.get("LOCK_MINUTES", 15))
MFA_TTL_MIN = int(os.environ.get("MFA_TTL_MIN", 5))
MFA_MAX_TRIES = int(os.environ.get("MFA_MAX_TRIES", 3))
MFA_RESEND_SEC = int(os.environ.get("MFA_RESEND_SEC", 30))

MAX_UPLOAD = 5 * 1024 * 1024
ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
ROLES = ("patient", "secretaire", "medecin", "admin")
MFA_ROLES = {"medecin", "secretaire", "admin"}
ROLE_LABELS = {"patient": "Patient", "secretaire": "Secrétaire",
               "medecin": "Médecin", "admin": "Administrateur"}
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,50}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if __name__ == "__main__":
        SECRET_KEY = secrets.token_hex(32)
    else:
        raise RuntimeError("SECRET_KEY manquante : definissez-la (meme valeur pour tous les workers).")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


def now():
    """Heure UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Journal d'audit
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_h)
audit_logger.propagate = False

# CloudWatch Logs
if CLOUDWATCH_LOG_GROUP:
    try:
        import boto3
        import watchtower
        _cw_logs_client = boto3.client("logs", region_name=AWS_REGION)
        _cw_handler = watchtower.CloudWatchLogHandler(
            boto3_client=_cw_logs_client,
            log_group_name=CLOUDWATCH_LOG_GROUP,
            log_stream_name="audit",
        )
        _cw_handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(_cw_handler)
    except Exception as _cw_err:
        print(f"[WARN] CloudWatch handler non initialisé : {_cw_err}", file=sys.stderr)


def audit(event, outcome="success", actor=None, **extra):
    """Événement d'audit JSON."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "outcome": outcome,
        "user": actor or session.get("username", "anonymous"),
        "role": session.get("role", "-"),
        "ip": request.remote_addr,
        "xff": (request.headers.get("X-Forwarded-For") or "")[:200],
        **extra,
    }
    audit_logger.info(json.dumps(record, ensure_ascii=False))


# Base de données
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine, expire_on_commit=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    fullname = Column(String(100), nullable=False)
    email = Column(String(120), nullable=False, default="")
    role = Column(String(20), nullable=False)
    pwhash = Column(String(255), nullable=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)


class CareLink(Base):
    """Rattachement médecin ↔ patient."""
    __tablename__ = "care_links"
    __table_args__ = (UniqueConstraint("doctor_id", "patient_id"),)
    id = Column(Integer, primary_key=True)
    doctor_id = Column(ForeignKey("users.id"), nullable=False)
    patient_id = Column(ForeignKey("users.id"), nullable=False)


class MfaChallenge(Base):
    __tablename__ = "mfa_challenges"
    id = Column(Integer, primary_key=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    code_hash = Column(String(255), nullable=False)
    created = Column(DateTime, nullable=False, default=now)
    expires = Column(DateTime, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    used = Column(Boolean, nullable=False, default=False)


class Appointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True)
    patient_id = Column(ForeignKey("users.id"), nullable=False)
    doctor_id = Column(ForeignKey("users.id"), nullable=False)
    when = Column(String(20), nullable=False)
    reason = Column(String(200), nullable=False)


class Note(Base):
    """Note médicale."""
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    patient_id = Column(ForeignKey("users.id"), nullable=False)
    doctor_id = Column(ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created = Column(DateTime, default=now)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    patient_id = Column(ForeignKey("users.id"), nullable=False)
    filename = Column(String(200), nullable=False)
    key = Column(String(300), nullable=False)
    created = Column(DateTime, default=now)


def init_db():
    # Verrou PostgreSQL pour démarrage multi-workers.
    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_lock(727274)"))
        try:
            Base.metadata.create_all(conn)
            conn.commit()
            _seed()
        finally:
            if engine.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_unlock(727274)"))
                conn.commit()


def _seed():
    with Session() as db:
        if db.scalar(select(User).limit(1)):
            return
        pw = generate_password_hash(SEED_PASSWORD)
        
        spec = [
            ("admin",      "Admin APP",          "admin",      EMAIL_ADMIN),
            ("dr.saber",   "Dr Saber ZAGHOUANI", "medecin",    EMAIL_DR_SABER),
            ("dr.tayssir", "Dr Tayssir",         "medecin",    EMAIL_DR_TAYSSIR),
            ("secretaire", "Eya WANES",          "secretaire", EMAIL_SECRETAIRE),
            ("noor",       "Nour zgh",           "patient",    EMAIL_NOOR),
            ("mamoun",     "Mamoun",             "patient",    EMAIL_MAMOUN),
        ]
        users = [User(username=u, fullname=n, role=r, pwhash=pw,
                      email=em) for u, n, r, em in spec]
        db.add_all(users)
        db.flush()
        by = {u.username: u for u in users}
        db.add_all([
            CareLink(doctor_id=by["dr.saber"].id, patient_id=by["noor"].id),
            CareLink(doctor_id=by["dr.tayssir"].id, patient_id=by["mamoun"].id),

            Appointment(patient_id=by["noor"].id, doctor_id=by["dr.saber"].id,
                        when="2026-12-02 09:30", reason="Consultation"),
            Appointment(patient_id=by["mamoun"].id, doctor_id=by["dr.tayssir"].id,
                        when="2026-12-02 10:30", reason="Contrôle annuel"),
       
            Note(patient_id=by["noor"].id, doctor_id=by["dr.saber"].id,
                 content=" tension normale, RAS."),
            Note(patient_id=by["mamoun"].id, doctor_id=by["dr.tayssir"].id,
                 content=" allergie suivi."),
            
        ])
        db.commit()


# ---------------------------------------------------------- stockage documents
def store_file(key, fileobj):
    if S3_BUCKET:
        import boto3
        extra = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": KMS_KEY_ID} if KMS_KEY_ID \
            else {"ServerSideEncryption": "AES256"}
        boto3.client("s3", region_name=AWS_REGION).upload_fileobj(fileobj, S3_BUCKET, key, ExtraArgs=extra)
    else:
        path = os.path.join(UPLOAD_DIR, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fileobj.save(path)


def fetch_file(key, filename):
    if S3_BUCKET:
        import io

        import boto3
        buf = io.BytesIO()
        boto3.client("s3", region_name=AWS_REGION).download_fileobj(S3_BUCKET, key, buf)
        buf.seek(0)
        return send_file(buf, download_name=filename, as_attachment=True)
    return send_file(os.path.join(UPLOAD_DIR, key), download_name=filename, as_attachment=True)


# Sécurité web
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["ROLE_LABELS"] = ROLE_LABELS


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent, expected = request.form.get("csrf"), session.get("csrf")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            audit("csrf_failure", "denied", path=request.path)
            abort(400)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    # Masquer le serveur.
    resp.headers["Server"] = "MediTrack"
    resp.headers.pop("X-Powered-By", None)
    return resp


def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "uid" not in session:
                return redirect(url_for("login"))
            if roles and session["role"] not in roles:
                audit("access_denied", "denied", path=request.path)
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def http_error(e):
    msgs = {400: "Requête invalide.", 403: "Accès refusé : vous n'avez pas les droits nécessaires.",
            404: "Page introuvable.", 413: "Fichier trop volumineux (5 Mo maximum)."}
    return render_template("error.html", code=e.code, message=msgs.get(e.code, "Erreur.")), e.code


# Outils métier
def password_problems(pw):
    """Politique de mot de passe."""
    problems = []
    if len(pw) < 12:
        problems.append("12 caractères minimum.")
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]|_"))
    if classes < 3:
        problems.append("Utilisez au moins 3 types de caractères (minuscules, majuscules, chiffres, symboles).")
    return problems


def mfa_required(user):
    return user.role in MFA_ROLES or user.mfa_enabled


def mask_email(email):
    if "@" not in email:
        return "votre adresse e-mail"
    name, dom = email.split("@", 1)
    return f"{name[:1]}***@{dom}"


def linked_patient_ids(db, doctor_id):
    return set(db.scalars(select(CareLink.patient_id).where(CareLink.doctor_id == doctor_id)))


def can_access_patient(db, patient_id):
    """Contrôle d'accès ABAC."""
    role, uid = session["role"], session["uid"]
    if role == "patient":
        return patient_id == uid
    if role == "medecin":
        return patient_id in linked_patient_ids(db, uid)
    return False


def deliver_mfa_code(user, code):
    """Envoi du code MFA uniquement à l'adresse e-mail de l'utilisateur (SES ou SNS filtré)."""
    if SES_SENDER_EMAIL or SNS_TOPIC_ARN:
        if not user.email or "@" not in user.email:
            audit("mfa_send_failed", "failure", actor=user.username, error="invalid_email")
            return False
    if SES_SENDER_EMAIL:
        try:
            import boto3
            boto3.client("ses", region_name=AWS_REGION).send_email(
                Source=SES_SENDER_EMAIL,
                Destination={"ToAddresses": [user.email]},
                Message={
                    "Subject": {"Data": "MediTrack - code de verification", "Charset": "UTF-8"},
                    "Body": {
                        "Text": {
                            "Data": (
                                f"Code de connexion pour {user.username} : {code}\n"
                                f"Valable {MFA_TTL_MIN} minutes. Ne le communiquez à personne."
                            ),
                            "Charset": "UTF-8",
                        }
                    },
                },
            )
            return True
        except Exception as exc:  # noqa: BLE001
            audit("mfa_send_failed", "failure", actor=user.username, error=type(exc).__name__)
            return False
    if SNS_TOPIC_ARN:
        try:
            import boto3
            boto3.client("sns", region_name=AWS_REGION).publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="MediTrack - code de verification",
                Message=(
                    f"Code de connexion pour {user.username} : {code}\n"
                    f"Valable {MFA_TTL_MIN} minutes. Ne le communiquez à personne."
                ),
                MessageAttributes={
                    "email": {
                        "DataType": "String",
                        "StringValue": user.email,
                    }
                },
            )
            return True
        except Exception as exc:  # noqa: BLE001
            audit("mfa_send_failed", "failure", actor=user.username, error=type(exc).__name__)
            return False
    if MFA_DEMO:
        audit("mfa_code_demo", actor=user.username, code=code, warning="DEMO uniquement")
        return True
    audit("mfa_send_failed", "failure", actor=user.username, error="no_delivery_channel")
    return False


def start_mfa(user):
    code = f"{secrets.randbelow(10**6):06d}"
    with Session() as db:
        db.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user.id))
        db.add(MfaChallenge(user_id=user.id, code_hash=generate_password_hash(code),
                            expires=now() + timedelta(minutes=MFA_TTL_MIN)))
        db.commit()
    ok = deliver_mfa_code(user, code)
    audit("mfa_sent" if ok else "mfa_not_sent", "success" if ok else "failure", actor=user.username)
    return ok


def complete_login(user):
    session.clear()
    session.permanent = True
    session.update(uid=user.id, username=user.username, role=user.role, fullname=user.fullname)
    audit("login")


DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


# Routes
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "uid" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        generic = "Identifiants incorrects ou compte temporairement verrouillé."
        with Session() as db:
            user = db.scalar(select(User).where(User.username == username))
            if user and user.locked_until and user.locked_until > now():
                check_password_hash(DUMMY_HASH, password)
                audit("login_blocked_locked", "denied", attempted_user=username[:50])
                flash(generic, "error")
                return render_template("login.html", cognito_enabled=bool(COGNITO_CLIENT_ID and COGNITO_DOMAIN))
            ok = check_password_hash(user.pwhash if user else DUMMY_HASH, password) and user is not None
            if not ok:
                if user:
                    user.failed_attempts = (user.failed_attempts or 0) + 1
                    if user.failed_attempts >= MAX_FAILED:
                        user.locked_until = now() + timedelta(minutes=LOCK_MINUTES)
                        user.failed_attempts = 0
                        audit("account_locked", "failure", attempted_user=username[:50],
                              minutes=LOCK_MINUTES)
                    db.commit()
                audit("login_failed", "failure", attempted_user=username[:50])
                flash(generic, "error")
                return render_template("login.html", cognito_enabled=bool(COGNITO_CLIENT_ID and COGNITO_DOMAIN))
            user.failed_attempts = 0
            user.locked_until = None
            db.commit()
            db.expunge(user)
        if mfa_required(user):
            session.clear()
            if not start_mfa(user):
                flash("Envoi du code de vérification impossible. Contactez l'administrateur.", "error")
                return render_template("login.html", cognito_enabled=bool(COGNITO_CLIENT_ID and COGNITO_DOMAIN))
            session["pending_uid"] = user.id
            session["pending_email"] = mask_email(user.email)
            return redirect(url_for("mfa"))
        complete_login(user)
        return redirect(url_for("dashboard"))
    return render_template("login.html", cognito_enabled=bool(COGNITO_CLIENT_ID and COGNITO_DOMAIN))


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = re.sub(r"\D", "", request.form.get("code", ""))[:6]
        with Session() as db:
            user = db.get(User, uid)
            ch = db.scalar(select(MfaChallenge).where(MfaChallenge.user_id == uid)
                           .order_by(MfaChallenge.id.desc()))
            if not ch or ch.used or ch.expires < now():
                audit("mfa_failed", "failure", actor=user.username, reason="expired_or_used")
                session.clear()
                flash("Code expiré. Reconnectez-vous pour en recevoir un nouveau.", "error")
                return redirect(url_for("login"))
            ch.attempts += 1
            if len(code) == 6 and check_password_hash(ch.code_hash, code):
                ch.used = True
                db.commit()
                db.expunge(user)
                complete_login(user)
                audit("mfa_success")
                return redirect(url_for("dashboard"))
            left = MFA_MAX_TRIES - ch.attempts
            if left <= 0:
                ch.used = True
            db.commit()
            audit("mfa_failed", "failure", actor=user.username, reason="bad_code")
            if left <= 0:
                audit("mfa_exhausted", "denied", actor=user.username)
                session.clear()
                flash("Trop d'essais. Reconnectez-vous pour recevoir un nouveau code.", "error")
                return redirect(url_for("login"))
            flash(f"Code incorrect. Il vous reste {left} essai(s).", "error")
    return render_template("mfa.html", email=session.get("pending_email", ""), ttl=MFA_TTL_MIN)


@app.route("/mfa/resend", methods=["POST"])
def mfa_resend():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    with Session() as db:
        user = db.get(User, uid)
        ch = db.scalar(select(MfaChallenge).where(MfaChallenge.user_id == uid)
                       .order_by(MfaChallenge.id.desc()))
        if ch and (now() - ch.created).total_seconds() < MFA_RESEND_SEC:
            flash(f"Patientez {MFA_RESEND_SEC} secondes avant de redemander un code.", "error")
            return redirect(url_for("mfa"))
        db.expunge(user)
    if start_mfa(user):
        flash("Un nouveau code a été envoyé.", "ok")
    else:
        flash("Envoi du code impossible.", "error")
    return redirect(url_for("mfa"))


@app.route("/logout", methods=["POST"])
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- Cognito OAuth2
@app.route("/auth/cognito")
def cognito_login():
    """Redirige vers la Hosted UI de Cognito pour authentification."""
    if not (COGNITO_CLIENT_ID and COGNITO_DOMAIN):
        flash("Connexion AWS Cognito non configurée.", "error")
        return redirect(url_for("login"))
    params = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": f"{APP_URL}/auth/cognito/callback",
        "scope": "openid email profile",
    }
    return redirect(f"https://{COGNITO_DOMAIN}/oauth2/authorize?{urllib.parse.urlencode(params)}")


@app.route("/auth/cognito/callback")
def cognito_callback():
    """Reçoit le code OAuth2, échange contre un JWT, ouvre la session Flask."""
    code  = request.args.get("code")
    error = request.args.get("error")
    if error or not code:
        audit("cognito_login_failed", "failure", reason=error or "no_code")
        flash("Authentification Cognito échouée.", "error")
        return redirect(url_for("login"))

    import base64
    import jwt as pyjwt
    import requests as http_req
    from jwt import PyJWKClient

    # --- Échange du code contre les tokens ---
    token_url   = f"https://{COGNITO_DOMAIN}/oauth2/token"
    auth_header = base64.b64encode(
        f"{COGNITO_CLIENT_ID}:{COGNITO_CLIENT_SECRET}".encode()
    ).decode()
    try:
        resp = http_req.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"{APP_URL}/auth/cognito/callback",
            },
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=10,
        )
        tokens = resp.json()
    except Exception as exc:
        audit("cognito_token_exchange_failed", "failure", error=type(exc).__name__)
        flash("Erreur lors de l'échange du token Cognito.", "error")
        return redirect(url_for("login"))

    id_token = tokens.get("id_token")
    if not id_token:
        audit("cognito_no_id_token", "failure")
        flash("Token Cognito absent.", "error")
        return redirect(url_for("login"))

    # --- Vérification du JWT avec les clés publiques du User Pool ---
    try:
        jwks_url    = (f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com"
                       f"/{COGNITO_USER_POOL_ID}/.well-known/jwks.json")
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims      = pyjwt.decode(
            id_token, signing_key.key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
        )
    except Exception as exc:
        audit("cognito_jwt_invalid", "failure", error=type(exc).__name__)
        flash("Token Cognito invalide ou expiré.", "error")
        return redirect(url_for("login"))

    # --- Recherche de l'utilisateur local par email ou username Cognito ---
    email            = claims.get("email", "")
    cognito_username = claims.get("cognito:username",
                                  claims.get("preferred_username", ""))
    with Session() as db:
        user = db.scalar(
            select(User).where(
                (User.email == email) | (User.username == cognito_username)
            )
        )
        if not user:
            audit("cognito_user_not_found", "denied", email=email[:100])
            flash("Compte non trouvé dans MediTrack. Contactez l'administrateur.", "error")
            return redirect(url_for("login"))
        if user.locked_until and user.locked_until > now():
            audit("cognito_login_blocked", "denied", actor=user.username)
            flash("Compte temporairement verrouillé.", "error")
            return redirect(url_for("login"))
        db.expunge(user)

    complete_login(user)
    audit("cognito_login_success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required()
def dashboard():
    role, uid = session["role"], session["uid"]
    ctx = {}
    with Session() as db:
        users = {u.id: u for u in db.scalars(select(User))}
        names = {i: u.fullname for i, u in users.items()}
        if role == "patient":
            ctx["appointments"] = db.scalars(select(Appointment).where(Appointment.patient_id == uid)
                                             .order_by(Appointment.when)).all()
            ctx["notes"] = db.scalars(select(Note).where(Note.patient_id == uid)
                                      .order_by(Note.id.desc())).all()
            ctx["documents"] = db.scalars(select(Document).where(Document.patient_id == uid)
                                          .order_by(Document.id.desc())).all()
        elif role == "secretaire":     # agenda : oui. notes et documents medicaux : NON.
            ctx["appointments"] = db.scalars(select(Appointment).order_by(Appointment.when)).all()
            ctx["patients"] = [u for u in users.values() if u.role == "patient"]
            ctx["doctors"] = [u for u in users.values() if u.role == "medecin"]
        elif role == "medecin":        # ABAC : uniquement les patients rattaches
            pids = linked_patient_ids(db, uid)
            ctx["patients"] = [users[i] for i in sorted(pids) if i in users]
            ctx["appointments"] = db.scalars(select(Appointment).where(Appointment.doctor_id == uid)
                                             .order_by(Appointment.when)).all()
            ctx["notes"] = db.scalars(select(Note).where(Note.patient_id.in_(pids))
                                      .order_by(Note.id.desc())).all() if pids else []
            ctx["documents"] = db.scalars(select(Document).where(Document.patient_id.in_(pids))
                                          .order_by(Document.id.desc())).all() if pids else []
        elif role == "admin":          # comptes et rattachements : oui. donnees medicales : NON.
            ctx["users"] = sorted(users.values(), key=lambda u: (ROLES.index(u.role), u.username))
            ctx["doctors"] = [u for u in users.values() if u.role == "medecin"]
            ctx["patients"] = [u for u in users.values() if u.role == "patient"]
            ctx["links"] = db.scalars(select(CareLink)).all()
            ctx["locked_ids"] = {u.id for u in users.values() if u.locked_until and u.locked_until > now()}
    audit("view_dashboard")
    return render_template("dashboard.html", names=names, **ctx)


@app.route("/appointments", methods=["POST"])
@login_required("secretaire")
def add_appointment():
    when = request.form.get("when", "").replace("T", " ")[:16]
    reason = request.form.get("reason", "").strip()[:200]
    try:
        datetime.strptime(when, "%Y-%m-%d %H:%M")
        pid, did = int(request.form["patient_id"]), int(request.form["doctor_id"])
    except (ValueError, KeyError):
        flash("Données de rendez-vous invalides.", "error")
        return redirect(url_for("dashboard"))
    if not reason:
        flash("Le motif est obligatoire.", "error")
        return redirect(url_for("dashboard"))
    with Session() as db:
        p, d = db.get(User, pid), db.get(User, did)
        if not p or p.role != "patient" or not d or d.role != "medecin":
            abort(400)
        db.add(Appointment(patient_id=pid, doctor_id=did, when=when, reason=reason))
        db.commit()
    audit("create_appointment", patient_id=pid, doctor_id=did)
    flash("Rendez-vous ajouté.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/notes", methods=["POST"])
@login_required("medecin")
def add_note():
    content = request.form.get("content", "").strip()[:5000]
    try:
        pid = int(request.form["patient_id"])
    except (ValueError, KeyError):
        abort(400)
    if not content:
        flash("La note est vide.", "error")
        return redirect(url_for("dashboard"))
    with Session() as db:
        if not can_access_patient(db, pid):
            audit("abac_denied", "denied", action="create_note", patient_id=pid)
            abort(403)
        db.add(Note(patient_id=pid, doctor_id=session["uid"], content=content))
        db.commit()
    audit("create_medical_note", patient_id=pid)
    flash("Note enregistrée.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/documents", methods=["POST"])
@login_required("patient", "medecin")
def upload_document():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("dashboard"))
    name = secure_filename(f.filename)
    if not name or os.path.splitext(name)[1].lower() not in ALLOWED_EXT:
        audit("upload_rejected", "denied", filename=name[:100])
        flash("Type de fichier non autorisé (pdf, png, jpg, txt).", "error")
        return redirect(url_for("dashboard"))
    try:
        patient_id = session["uid"] if session["role"] == "patient" else int(request.form["patient_id"])
    except (ValueError, KeyError):
        abort(400)
    with Session() as db:
        if not can_access_patient(db, patient_id):
            audit("abac_denied", "denied", action="upload_document", patient_id=patient_id)
            abort(403)
        key = f"patients/{patient_id}/{secrets.token_hex(8)}_{name}"
        store_file(key, f)
        db.add(Document(patient_id=patient_id, filename=name, key=key))
        db.commit()
    audit("upload_document", patient_id=patient_id, key=key)
    flash("Document envoyé.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:doc_id>")
@login_required("patient", "medecin")
def download_document(doc_id):
    with Session() as db:
        doc = db.get(Document, doc_id)
        allowed = bool(doc) and can_access_patient(db, doc.patient_id)
    if not allowed:
        audit("download_denied", "denied", doc_id=doc_id)
        abort(403)
    audit("download_document", doc_id=doc_id)
    return fetch_file(doc.key, doc.filename)


# ------------------------------------------------------------ compte et admin
@app.route("/password", methods=["GET", "POST"])
@login_required()
def change_password():
    if request.method == "POST":
        current = request.form.get("current", "")
        new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
        with Session() as db:
            user = db.get(User, session["uid"])
            problems = []
            if not check_password_hash(user.pwhash, current):
                problems.append("Mot de passe actuel incorrect.")
            if new != confirm:
                problems.append("La confirmation ne correspond pas.")
            if new == current:
                problems.append("Le nouveau mot de passe doit être différent.")
            problems += password_problems(new)
            if problems:
                audit("password_change_failed", "failure")
                for p in problems:
                    flash(p, "error")
                return render_template("password.html")
            user.pwhash = generate_password_hash(new)
            db.commit()
        audit("password_changed")
        flash("Mot de passe modifié.", "ok")
        return redirect(url_for("dashboard"))
    return render_template("password.html")


@app.route("/admin/users", methods=["POST"])
@login_required("admin")
def admin_create_user():
    f = request.form
    username = f.get("username", "").strip().lower()
    fullname = f.get("fullname", "").strip()[:100]
    email = f.get("email", "").strip()[:120]
    role, password = f.get("role", ""), f.get("password", "")
    problems = []
    if not USERNAME_RE.match(username):
        problems.append("Identifiant : 3 à 50 caractères (a-z, 0-9, . _ -).")
    if not fullname:
        problems.append("Le nom complet est obligatoire.")
    if not EMAIL_RE.match(email):
        problems.append("Adresse e-mail invalide.")
    if role not in ROLES:
        problems.append("Rôle invalide.")
    problems += password_problems(password)
    with Session() as db:
        if not problems and db.scalar(select(User).where(User.username == username)):
            problems.append("Cet identifiant existe déjà.")
        if not problems:
            db.add(User(username=username, fullname=fullname, email=email, role=role,
                        pwhash=generate_password_hash(password),
                        mfa_enabled=bool(f.get("mfa"))))
            db.commit()
    if problems:
        audit("create_user_failed", "failure", new_user=username[:50])
        for p in problems:
            flash(p, "error")
    else:
        audit("create_user", new_user=username, new_role=role)
        flash(f"Compte « {username} » créé.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/links", methods=["POST"])
@login_required("admin")
def admin_add_link():
    try:
        did, pid = int(request.form["doctor_id"]), int(request.form["patient_id"])
    except (ValueError, KeyError):
        abort(400)
    with Session() as db:
        d, p = db.get(User, did), db.get(User, pid)
        if not d or d.role != "medecin" or not p or p.role != "patient":
            abort(400)
        if db.scalar(select(CareLink).where(CareLink.doctor_id == did, CareLink.patient_id == pid)):
            flash("Ce rattachement existe déjà.", "error")
            return redirect(url_for("dashboard"))
        db.add(CareLink(doctor_id=did, patient_id=pid))
        db.commit()
    audit("create_care_link", doctor_id=did, patient_id=pid)
    flash("Rattachement créé.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/links/<int:link_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_link(link_id):
    with Session() as db:
        link = db.get(CareLink, link_id)
        if not link:
            abort(404)
        db.delete(link)
        db.commit()
    audit("delete_care_link", link_id=link_id)
    flash("Rattachement supprimé.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@login_required("admin")
def admin_unlock(user_id):
    with Session() as db:
        user = db.get(User, user_id)
        if not user:
            abort(404)
        user.locked_until, user.failed_attempts = None, 0
        db.commit()
    audit("unlock_account", target_id=user_id)
    flash("Compte déverrouillé.", "ok")
    return redirect(url_for("dashboard"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

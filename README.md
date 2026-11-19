# MediTrack : application de démonstration (projet Sécurité dans les Clouds)

Application Flask pour un cabinet médical. Elle sert de « vitrine » : la note porte sur la
sécurité de l'infrastructure AWS autour, pas sur l'application.

## Comptes de démonstration (données 100 % fictives)

Mot de passe de tous les comptes : défini par la variable `SEED_PASSWORD` dans le fichier `.env` (**ne jamais le mettre en dur dans le code**).

| Identifiant | Rôle | MFA | Accès |
|---|---|---|---|
| `patient1` | Patient | facultatif | ses rendez-vous, notes, documents |
| `patient2` | Patient | facultatif | idem (autres données) |
| `dr.martin` | Médecin | obligatoire | uniquement **patient1** (rattaché) |
| `dr.durand` | Médecin | obligatoire | uniquement **patient2** (rattaché) |
| `secretaire` | Secrétaire | obligatoire | agenda de tous ; **aucune** donnée médicale |
| `admin` | Administrateur | obligatoire | comptes et rattachements ; **aucune** donnée médicale |

## Test local (Docker)

    docker compose down -v        # repartir d'une base vide
    docker compose up --build
    # http://localhost:8080

**Code MFA en local** (`MFA_DEMO=1` dans docker-compose.yml) : le code à 6 chiffres n'est pas envoyé,
il s'affiche dans les journaux. Dans un second terminal :

    docker compose logs app | grep mfa_code_demo

(prenez la dernière ligne, champ `"code"`). Le mode démo est **réservé aux tests** : ne l'activez pas sur l'EC2.

## Sécurité applicative (à citer dans le rapport)

- **Authentification** : mots de passe hachés (scrypt), politique (12 caractères, 3 types), cookies HttpOnly/SameSite, session de 30 min.
- **MFA** : code à usage unique de 6 chiffres envoyé par e-mail (SNS) ; expire en 5 min, stocké haché, 3 essais, renvoi limité (30 s). Obligatoire pour médecin, secrétaire, admin.
- **Verrouillage** : 5 échecs → compte verrouillé 15 min ; message identique pour compte inconnu / verrouillé / mauvais mot de passe (pas d'énumération). Déverrouillage par l'admin.
- **RBAC** : chaque route déclare ses rôles ; refus journalisé (`access_denied`).
- **ABAC** : patient = ses données ; médecin = seulement les patients rattachés (table `care_links`, gérée par l'admin) ; refus journalisé (`abac_denied`).
- **Séparation des tâches** : l'admin ne voit aucune donnée médicale ; la secrétaire non plus.
- **Web** : CSRF, CSP stricte (sans `unsafe-inline`), `X-Frame-Options`, `nosniff`, `Cache-Control: no-store`, requêtes SQL paramétrées, upload limité (5 Mo, extensions autorisées).
- **Conteneur** : utilisateur non-root. **S3** : accès par le rôle IAM de l'EC2, aucune clé dans le code.

## Déploiement sur l'EC2

    sudo dnf install -y docker && sudo systemctl enable --now docker
    cd meditrack && sudo docker build -t meditrack .
    sudo docker run -d --name meditrack --restart unless-stopped -p 80:8080 \
      -e DATABASE_URL='postgresql+psycopg2://USER:MDP@ENDPOINT-RDS:5432/meditrack' \
      -e SECRET_KEY="$(openssl rand -hex 32)" \
      -e SEED_PASSWORD='UnMotDePasseFort!2026' \
      -e S3_BUCKET='nom-du-bucket-documents' \
      -e SNS_TOPIC_ARN='arn:aws:sns:us-east-1:123456789012:meditrack-mfa' \
      -e COOKIE_SECURE=1 \
      meditrack

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | **obligatoire** (sinon l'application refuse de démarrer) ; identique pour tous les workers |
| `DATABASE_URL` | RDS PostgreSQL (sans elle : SQLite éphémère, pour un premier test) |
| `S3_BUCKET` / `KMS_KEY_ID` | documents dans S3 (chiffrement SSE-S3, ou SSE-KMS si `KMS_KEY_ID`) |
| `SNS_TOPIC_ARN` | envoi réel du code MFA par e-mail |
| `MFA_DEMO` | `1` = code écrit dans les logs (tests locaux uniquement) |
| `COOKIE_SECURE` | `1` derrière HTTPS (CloudFront) |
| `LOGIN_MAX_FAILED`, `LOCK_MINUTES`, `MFA_TTL_MIN`, `MFA_MAX_TRIES` | réglages de sécurité |

Sans `SNS_TOPIC_ARN` **et** sans `MFA_DEMO`, les comptes à MFA ne peuvent pas se connecter (sécurité par défaut).
L'EC2 a besoin de la permission `sns:Publish` sur le topic (via son rôle IAM). À vérifier dans le Learner Lab.

## Journaux d'audit (→ CloudWatch)

Une ligne JSON par événement sur stdout, par exemple :

    {"ts": "...", "event": "login_failed", "outcome": "failure", "user": "anonymous", "ip": "...", "attempted_user": "admin"}

Événements : `login`, `login_failed`, `account_locked`, `login_blocked_locked`, `mfa_sent`, `mfa_failed`,
`mfa_exhausted`, `mfa_success`, `access_denied`, `abac_denied`, `download_denied`, `csrf_failure`,
`upload_document`, `download_document`, `create_medical_note`, `create_user`, `create_care_link`, `password_changed`, ...

Détection du brute force : *metric filter* CloudWatch sur `"login_failed"` (ou `"account_locked"`) + alarme → SNS → e-mail.
Journaux vers CloudWatch : pilote Docker `--log-driver=awslogs --log-opt awslogs-group=/meditrack/app --log-opt awslogs-region=us-east-1`.

## Limites connues (à mentionner dans « risques résiduels »)

- **MFA par e-mail via SNS** : plus faible que TOTP/passkey. Et un topic SNS envoie à **tous ses abonnés** : acceptable pour la démo, pas en production (cible : Cognito + TOTP ou WebAuthn).
- Pas de réinitialisation de mot de passe par e-mail ; pas de scan antivirus des fichiers ; pas de limitation de débit applicative (assurée par le WAF et, en option, nginx).
- Le rôle admin applicatif n'est pas le rôle admin AWS : celui-ci passe par IAM et Session Manager.

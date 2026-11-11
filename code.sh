#!/usr/bin/env bash
#
# Synchronise plusieurs CRL pour OpenLDAP.
# Prérequis de configuration (une seule fois) :
#   - exécuter ce script en root ;
#   - configurer olcTLSCACertificateFile avec le bundle des CA ;
#   - configurer olcTLSCACertificatePath avec CRL_LINK ci-dessous ;
#   - définir olcTLSCRLCheck à all (ou peer) après la configuration initiale ;
#   - autoriser SASL EXTERNAL sur ldapi:/// pour modifier cn=config ;
#   - adapter les sources et l'âge maximal de chaque source à la politique des émetteurs.
#
# Chaque source : URL|certificat_émetteur|PEM_ou_DER|nom_fichier|âge_max_en_jours
# Les certificats émetteurs doivent être locaux et contenir le certificat qui
# a signé la CRL.

set -uo pipefail
umask 027

LDAP_URI="ldapi:///"
SLAPD_SERVICE="slapd"
CRL_GROUP="openldap"
CRL_BASE="/var/lib/openldap/crl-cache"
CRL_LINK="${CRL_BASE}/current"
CRL_MODE="all"

CRL_SOURCES=(
  # "https://pki.example.net/root.crl|/etc/ldap/certs/root-ca.pem|DER|root.crl.pem|7"
  # "https://pki.example.net/issuing.crl|/etc/ldap/certs/issuing-ca.pem|PEM|issuing.crl.pem|2"
)

log() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

set_crl_mode() {
  local mode="$1"
  printf 'dn: cn=config\nchangetype: modify\nreplace: olcTLSCRLCheck\nolcTLSCRLCheck: %s\n' \
    "$mode" |
    ldapmodify -Q -Y EXTERNAL -H "$LDAP_URI"
}

restart_slapd() {
  systemctl restart "$SLAPD_SERVICE"
}

fail_open() {
  log "ERREUR: $*"
  if ! set_crl_mode none; then
    log "CRITIQUE: impossible de désactiver olcTLSCRLCheck via $LDAP_URI"
    exit 2
  fi
  if ! restart_slapd; then
    log "CRITIQUE: CRL désactivées dans cn=config, mais le redémarrage de slapd a échoué"
    exit 2
  fi
  log "Contrôle des CRL désactivé (olcTLSCRLCheck=none)."
  exit 1
}

cleanup() {
  if [[ -n "${STAGE_DIR:-}" && -d "$STAGE_DIR" ]]; then
    rm -rf -- "$STAGE_DIR"
  fi
}
trap cleanup EXIT

if (( ${#CRL_SOURCES[@]} == 0 )); then
  log "ERREUR: aucune source CRL configurée; aucun changement appliqué."
  exit 2
fi

if ! command -v openssl >/dev/null ||
   ! command -v curl >/dev/null ||
   ! command -v ldapmodify >/dev/null ||
   ! command -v systemctl >/dev/null ||
   ! command -v flock >/dev/null ||
   ! command -v chgrp >/dev/null ||
   ! command -v date >/dev/null; then
  fail_open "outil requis manquant (openssl, curl, ldapmodify, systemctl, flock, chgrp ou date)."
fi

if ! mkdir -p -- "$CRL_BASE"; then
  fail_open "impossible de créer $CRL_BASE."
fi
if ! chgrp "$CRL_GROUP" "$CRL_BASE" || ! chmod 0750 "$CRL_BASE"; then
  fail_open "impossible de donner l'accès à slapd via le groupe $CRL_GROUP."
fi

if ! exec 9>"${CRL_BASE}/.refresh.lock"; then
  fail_open "impossible d'ouvrir le verrou d'exécution."
fi
if ! flock -n 9; then
  log "Une autre synchronisation est déjà en cours; aucune modification effectuée."
  exit 0
fi

STAGE_DIR="$(mktemp -d "${CRL_BASE}/.crlgen.XXXXXX")" ||
  fail_open "impossible de créer le répertoire temporaire."
chmod 0750 "$STAGE_DIR" ||
  fail_open "impossible de protéger le répertoire temporaire."
chgrp "$CRL_GROUP" "$STAGE_DIR" ||
  fail_open "impossible d'attribuer le répertoire temporaire au groupe $CRL_GROUP."

declare -A SEEN_FILES=()
for source in "${CRL_SOURCES[@]}"; do
  IFS='|' read -r url issuer_cert input_format filename max_age_days <<< "$source"

  if [[ -z "$url" || -z "$issuer_cert" || -z "$input_format" ||
        -z "$filename" || -z "$max_age_days" ]]; then
    fail_open "entrée CRL incomplète: $source"
  fi
  if [[ ! "$filename" =~ ^[A-Za-z0-9._-]+$ || "$filename" == "." || "$filename" == ".." ]]; then
    fail_open "nom de fichier CRL invalide: $filename"
  fi
  if [[ -n "${SEEN_FILES[$filename]:-}" ]]; then
    fail_open "nom de fichier CRL utilisé plusieurs fois: $filename"
  fi
  SEEN_FILES["$filename"]=1
  if [[ ! "$max_age_days" =~ ^[0-9]+$ ]]; then
    fail_open "âge maximal invalide pour $url: $max_age_days"
  fi
  if (( ${#max_age_days} > 5 )); then
    fail_open "âge maximal déraisonnable pour $url: $max_age_days jours"
  fi
  max_age_days=$((10#$max_age_days))
  if (( max_age_days < 1 || max_age_days > 36500 )); then
    fail_open "âge maximal hors limites pour $url: $max_age_days jours"
  fi
  if [[ ! -r "$issuer_cert" ]]; then
    fail_open "certificat émetteur absent ou illisible: $issuer_cert"
  fi

  input_format="${input_format^^}"
  if [[ "$input_format" != "PEM" && "$input_format" != "DER" ]]; then
    fail_open "format d'entrée invalide pour $url: $input_format (PEM ou DER attendu)"
  fi

  raw_file="${STAGE_DIR}/${filename}.download"
  crl_file="${STAGE_DIR}/${filename}"
  if ! curl --fail --location --silent --show-error --max-time 60 \
      --retry 2 --output "$raw_file" "$url"; then
    fail_open "téléchargement échoué: $url"
  fi
  if ! openssl crl -inform "$input_format" -in "$raw_file" \
      -outform PEM -out "$crl_file"; then
    fail_open "conversion ou lecture de la CRL échouée: $url"
  fi
  rm -f -- "$raw_file"

  if ! openssl crl -in "$crl_file" -noout >/dev/null 2>&1; then
    fail_open "CRL illisible ou incomplète: $url"
  fi
  if ! openssl crl -in "$crl_file" -noout -verify -CAfile "$issuer_cert" -no-CApath; then
    fail_open "signature de la CRL invalide pour $url"
  fi

  crl_issuer="$(openssl crl -in "$crl_file" -noout -issuer -nameopt RFC2253 2>/dev/null)" ||
    fail_open "impossible de lire l'émetteur de la CRL: $url"
  ca_subject="$(openssl x509 -in "$issuer_cert" -noout -subject -nameopt RFC2253 2>/dev/null)" ||
    fail_open "certificat émetteur invalide: $issuer_cert"
  crl_issuer="${crl_issuer#issuer=}"
  ca_subject="${ca_subject#subject=}"
  if [[ "$crl_issuer" != "$ca_subject" ]]; then
    fail_open "l'émetteur de la CRL ne correspond pas au certificat configuré: $url"
  fi

  last_update="$(openssl crl -in "$crl_file" -noout -lastupdate 2>/dev/null)"
  next_update="$(openssl crl -in "$crl_file" -noout -nextupdate 2>/dev/null)"
  last_update="${last_update#lastUpdate=}"
  next_update="${next_update#nextUpdate=}"
  if [[ -z "$last_update" || -z "$next_update" ]]; then
    fail_open "CRL sans lastUpdate ou nextUpdate: $url"
  fi
  last_epoch="$(date -u -d "$last_update" +%s 2>/dev/null)" ||
    fail_open "date lastUpdate illisible pour $url"
  next_epoch="$(date -u -d "$next_update" +%s 2>/dev/null)" ||
    fail_open "date nextUpdate illisible pour $url"
  now_epoch="$(date -u +%s)"
  if (( last_epoch > now_epoch )); then
    fail_open "CRL datée dans le futur: $url"
  fi
  if (( next_epoch < now_epoch )); then
    fail_open "CRL expirée: $url"
  fi
  if (( now_epoch - last_epoch > max_age_days * 86400 )); then
    fail_open "CRL trop ancienne (limite ${max_age_days} jours): $url"
  fi
done

if ! openssl rehash "$STAGE_DIR"; then
  fail_open "impossible de créer les liens de hachage OpenSSL."
fi
if ! chgrp -R "$CRL_GROUP" "$STAGE_DIR"; then
  fail_open "impossible d'attribuer les CRL au groupe $CRL_GROUP."
fi

OLD_CRL_DIR=""
if [[ -L "$CRL_LINK" ]]; then
  OLD_CRL_DIR="$(readlink -f -- "$CRL_LINK" 2>/dev/null || true)"
elif [[ -e "$CRL_LINK" ]]; then
  fail_open "$CRL_LINK existe et n'est pas un lien symbolique; arrêt sans remplacement."
fi

NEW_CRL_DIR="$STAGE_DIR"
TEMP_LINK="${CRL_BASE}/.current.$$"
if ! ln -s -- "$NEW_CRL_DIR" "$TEMP_LINK" ||
   ! mv -Tf -- "$TEMP_LINK" "$CRL_LINK"; then
  rm -f -- "$TEMP_LINK"
  fail_open "impossible de publier le jeu de CRL validé."
fi
STAGE_DIR=""

if ! set_crl_mode "$CRL_MODE"; then
  fail_open "impossible d'activer olcTLSCRLCheck=$CRL_MODE."
fi
if ! restart_slapd; then
  fail_open "le redémarrage de slapd a échoué après la mise à jour des CRL."
fi

if [[ -n "$OLD_CRL_DIR" &&
      "$OLD_CRL_DIR" == "${CRL_BASE}"/.crlgen.* &&
      "$OLD_CRL_DIR" != "$NEW_CRL_DIR" ]]; then
  rm -rf -- "$OLD_CRL_DIR"
fi

log "CRL validées et publiées; olcTLSCRLCheck=$CRL_MODE, slapd redémarré."
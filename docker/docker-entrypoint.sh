#!/bin/bash
set -e

umask 0022

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
#  (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#   "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
function file_env() {
  local var="$1"
  local fileVar="${var}_FILE"
  local def="${2:-}"
  if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
    echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
    exit 1
  fi
  local val="$def"
  if [ "${!var:-}" ]; then
    val="${!var}"
  elif [ "${!fileVar:-}" ]; then
    val="$(< "${!fileVar}")"
  fi
  export "$var"="$val"
  unset "$fileVar"
}

# envs=(
#   XYZ_API_TOKEN
# )
# haveConfig=
# for e in "${envs[@]}"; do
#   file_env "$e"
#   if [ -z "$haveConfig" ] && [ -n "${!e}" ]; then
#     haveConfig=1
#   fi
# done

# return true if specified directory is empty
function directory_empty() {
  [ -n "$(find "${1}"/ -prune -empty)" ]
}

function random_token() {
  tr -cd '[:alnum:]' </dev/urandom | fold -w32 | head -n1
}

SERVICE_TIMEOUT=${SERVICE_TIMEOUT:-300s} # wait for dependencies

echo Running: "$@"

export DNS3L_URL=${DNS3L_URL:-"https://localhost"}
export DNS3L_EMAIL=${DNS3L_EMAIL:-'["info@example.com"]'}
export DNS3L_AUTH_URL=${DNS3L_AUTH_URL:-"https://auth:5554/auth"}

export DNS3L_RTZN=${DNS3L_RTZN:-'[{"root":"foo.example.com","autodns":"null","acmedns":"otc","ca":["*"]}]'}

export DNS_OTC_AK=${DNS_OTC_AK:-$(random_token)}
export DNS_OTC_SK=${DNS_OTC_SK:-$(random_token)}
export DNS_OTC_REGION=${DNS_OTC_REGION:-"eu-de"}

export STEP_RA_URL=${STEP_RA_URL:-"https://sra:9443"}
export STEP_RA_FINGERPRINT=${STEP_RA_FINGERPRINT:-"foobar"}

export DNS3L_DATABASE=${DNS3L_DATABASE:-"dns3l"}
export DNS3L_DB_USER=${DNS3L_DB_USER:-"dns3l"}
export DNS3L_DB_PASS=${DNS3L_DB_PASS:-$(random_token)}
export DNS3L_DB_HOST=${DNS3L_DB_HOST:-"db"}

production=false
if [[ ${ENVIRONMENT,,} == "production" ]]; then
  production=true
fi
renewal=true
if [[ ${DNS3L_RENEWAL,,} == "false" ]]; then
  renewal=false
fi

# Avoid destroying bootstrapping by simple start/stop
if [[ ! -e ${DNS3LPATH}/.bootstrapped ]]; then
  ### list none idempotent code blocks, here...

  touch ${DNS3LPATH}/.bootstrapped
fi

###
### DNS3L DB bootstrapping...
###

if [ "${production}" == "false" -a -n "${MARIADB_ROOT_PASSWORD}" ]; then
  echo "Bootstrapping DNS3L Database..."
  set +e
  /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
    echo "quit" | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}" -D"${DNS3L_DATABASE}"
  if [ "$?" != "0" ]; then # create DB
    set -e
    echo "Create ${DNS3L_DATABASE}..."
    /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
      cat <<EOSQL | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}"
CREATE DATABASE IF NOT EXISTS ${DNS3L_DATABASE};
CREATE USER IF NOT EXISTS ${DNS3L_DB_USER}@'%' IDENTIFIED BY '${DNS3L_DB_PASS}';
GRANT ALL ON ${DNS3L_DATABASE}.* TO ${DNS3L_DB_USER}@'%';
FLUSH PRIVILEGES;
EOSQL
  else # change password (optionally)
    set -e
    echo "Change password ${DNS3L_DB_PASS}..."
    /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
      cat <<EOSQL | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}"
ALTER USER IF EXISTS ${DNS3L_DB_USER}@'%' IDENTIFIED BY '${DNS3L_DB_PASS}';
FLUSH PRIVILEGES;
EOSQL
  fi
fi

###
### DNS3L bootstrapping...
###

echo "Creating DNS3L configuration..."

if [ -r /etc/dns3ld.conf.yml -a -s /etc/dns3ld.conf.yml ]; then
  ln -fs /etc/dns3ld.conf.yml ${DNS3LPATH}/config.yaml
else
  /dckrz -template ${DNS3LPATH}/config.yaml.tmpl:${DNS3LPATH}/config.yaml

  # Template usage is waiting for deps...
  /dckrz -wait ${STEP_RA_URL} -timeout ${SERVICE_TIMEOUT} -skip-tls-verify -wait-http-status-code 404 -- \
    step ca bootstrap -f --ca-url ${STEP_RA_URL} --fingerprint ${STEP_RA_FINGERPRINT}
  # Run --install as root or https://github.com/dns3l/dns3l-core/issues/16
  #
  /dckrz -wait ${STEP_RA_URL} -timeout ${SERVICE_TIMEOUT} -skip-tls-verify -wait-http-status-code 404 -- \
    sudo step ca bootstrap -f --ca-url ${STEP_RA_URL} --fingerprint ${STEP_RA_FINGERPRINT} --install
  /dckrz -wait ${DNS3L_AUTH_URL}/.well-known/openid-configuration -skip-tls-verify -timeout ${SERVICE_TIMEOUT} -- echo "Ok. DexIDP is there."
fi

/dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- echo "Ok. MariaDB is there."
/dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- /app/dns3ld dbcreate

if [[ `basename ${1}` == "dns3ld" ]]; then # prod
  if [ "${renewal}" == "false" ]; then
    exec /app/dns3ld --renew=false -s :8880 -c ${DNS3LPATH}/config.yaml </dev/null #>/dev/null 2>&1
  else
    exec "$@" </dev/null #>/dev/null 2>&1
  fi
else # dev
    /app/dns3ld -s :8880 -c ${DNS3LPATH}/config.yaml || true
fi

# fallthrough...
exec "$@"

#!/bin/bash
set -e

# Executed by the entrypoint with dropped privileges.

umask 0022

function random_token() {
  tr -cd '[:alnum:]' </dev/urandom | fold -w32 | head -n1
}

SERVICE_TIMEOUT=${SERVICE_TIMEOUT:-300s} # wait for dependencies

echo Running: "$@"

export DNS3L_AUTH_URL=${DNS3L_AUTH_URL:-"https://auth:5554/auth"}

export DNS3L_DATABASE=${DNS3L_DATABASE:-"dns3l"}
export DNS3L_DB_USER=${DNS3L_DB_USER:-"dns3l"}
export DNS3L_DB_PASS=${DNS3L_DB_PASS:-$(random_token)}
export DNS3L_DB_HOST=${DNS3L_DB_HOST:-"db"}

export MARIADB_ARGS=${MARIADB_ARGS:-""}

production=false
if [[ ${ENVIRONMENT,,} == "production" ]]; then
  production=true
fi
renewal=true
if [[ ${DNS3L_RENEWAL,,} == "false" ]]; then
  renewal=false
fi

###
### DNS3L DB bootstrapping...
###

if [ "${production}" == "false" -a -n "${MARIADB_ROOT_PASSWORD}" ]; then
  echo "Bootstrapping DNS3L Database..."
  set +e
  /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
    echo "quit" | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}" -D"${DNS3L_DATABASE}" ${MARIADB_ARGS}
  if [ "$?" != "0" ]; then # create DB
    set -e
    echo "Create ${DNS3L_DATABASE}..."
    /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
      cat <<EOSQL | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}" ${MARIADB_ARGS}
CREATE DATABASE IF NOT EXISTS ${DNS3L_DATABASE};
CREATE USER IF NOT EXISTS ${DNS3L_DB_USER}@'%' IDENTIFIED BY '${DNS3L_DB_PASS}';
GRANT ALL ON ${DNS3L_DATABASE}.* TO ${DNS3L_DB_USER}@'%';
FLUSH PRIVILEGES;
EOSQL
  else # change password (optionally)
    set -e
    echo "Change password..."
    /dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- \
      cat <<EOSQL | mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -h"${DNS3L_DB_HOST}" ${MARIADB_ARGS}
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
  /dckrz -wait ${DNS3L_AUTH_URL}/.well-known/openid-configuration -skip-tls-verify -timeout ${SERVICE_TIMEOUT} -- echo "Ok. DexIDP is there."
fi

/dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- echo "Ok. MariaDB is there."
/dckrz -wait tcp://${DNS3L_DB_HOST}:3306 -timeout ${SERVICE_TIMEOUT} -- /app/dns3ld dbcreate

if [[ `basename ${1}` == "dns3ld" ]]; then # prod
  if [ "${renewal}" == "true" ]; then
    exec "$@" </dev/null #>/dev/null 2>&1
  else
    exec /app/dns3ld --renew=false -s :8880 -c ${DNS3LPATH}/config.yaml </dev/null #>/dev/null 2>&1
  fi
else # dev
    /app/dns3ld -s :8880 -c ${DNS3LPATH}/config.yaml || true
fi

# fallthrough...
exec "$@"

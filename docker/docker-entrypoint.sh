#!/bin/bash
set -e

export DNS3L_FQDN=${DNS3L_FQDN:-localhost}

# make frontnet auth endpoint(s) available via backnet (now idempotent)
ingress=$(getent hosts ingress | cut -f1 -d' ')
if [ -n "$ingress" ]; then
  entry="$ingress ${DNS3L_FQDN[*]}"
  if ! grep "$entry" /etc/hosts >/dev/null; then
    echo "$entry" | tee -a /etc/hosts >/dev/null
  fi
else
  echo Oooops. Discovering ingress IP failed.
fi

su dns3ld -c "/run-dns3ld.sh $*" # executes the rest with dropped privileges

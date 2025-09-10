#!/bin/bash
set -e

export DNS3L_FQDN=${DNS3L_FQDN:-localhost}

# make frontnet auth endpoint(s) available via backnet (now idempotent).
# retry if not immediately working.
while true; do
  ingress=$(getent hosts ingress | cut -f1 -d' ')
  if [ -n "$ingress" ]; then
    entry="$ingress ${DNS3L_FQDN[*]}"
    if ! grep "$entry" /etc/hosts >/dev/null; then
      echo "$entry" | tee -a /etc/hosts >/dev/null
      echo Successfully patched hosts file with ingress IP and fqdns.
    else
      echo Hosts file already patched.
    fi
    break
  else
    echo Oooops. Discovering ingress IP failed. Probably the ingress is not yet up. Will retry soon.
  fi
  sleep 30
done &

su dns3ld -c "/run-dns3ld.sh $*" # executes the rest with dropped privileges

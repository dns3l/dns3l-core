#!/bin/bash
set -e

export DNS3L_FQDN=${DNS3L_FQDN:-localhost}

# Avoid destroying bootstrapping by simple start/stop
if [[ ! -e /.bootstrapped ]]; then
  ### list none idempotent code blocks, here...

  # make frontnet auth endpoint(s) available via backnet
  ingress=$(getent hosts ingress | cut -f1 -d' ')
  if [ -n "$ingress" ]; then
    for h in ${DNS3L_FQDN}; do
      echo "$ingress $h" | tee -a /etc/hosts >/dev/null
    done
  else
    echo Oooops. Discovering ingress IP failed.
  fi

  touch /.bootstrapped
fi

su dns3ld -c "/run-dns3ld.sh $*" # executes the rest with dropped privileges

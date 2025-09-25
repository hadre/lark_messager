#!/bin/sh
set -eu

FIRST_DEPLOYMENT_VALUE=${FIRST_DEPLOYMENT:-false}

if [ "$FIRST_DEPLOYMENT_VALUE" = "true" ]; then
  echo "[entrypoint] FIRST_DEPLOYMENT=true detected; running init_system"
  /usr/local/bin/init_system
  echo "[entrypoint] Initialisation complete"
else
  echo "[entrypoint] FIRST_DEPLOYMENT=$FIRST_DEPLOYMENT_VALUE; skipping init_system"
fi

exec "$@"

#!/bin/bash
set -e
cd /opt/auto_conf && \
    python make_conf.py >/dev/stderr 2>&1 || exit 1

/usr/bin/apisix init >/dev/stderr 2>&1 && \
/usr/bin/apisix init_etcd >/dev/stderr 2>&1 || exit 1

exec "$@"

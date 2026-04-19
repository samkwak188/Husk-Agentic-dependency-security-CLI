#!/bin/bash
set -euo pipefail

cd /sandbox

cat > package.json <<'EOF'
{"name":"husk-sandbox-target","private":true}
EOF

INSTALL_TARGET="${1:-file:///sandbox/pkg.tgz}"
export npm_config_package_lock=false
export npm_config_fund=false
export npm_config_audit=false

strace -f -e trace=network,process,file,write,read -s 4096 -o /sandbox/trace.log \
  npm install --ignore-scripts=false --no-save "$INSTALL_TARGET" 2>&1 | tee /sandbox/install.log || true

env > /sandbox/env_snapshot.txt

echo "HUSK_TRACE_COMPLETE"

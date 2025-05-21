#!/bin/bash
set -euo pipefail

# Install Go 1.24.2
GO_VERSION=1.24.2
wget -nv "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"

# Update PATH for current session and future sessions
export PATH="/usr/local/go/bin:$PATH"
if ! grep -q '/usr/local/go/bin' /etc/profile; then
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile
fi

# Verify installation
/usr/local/go/bin/go version

# Pre-fetch Go modules so that tests can run offline
/usr/local/go/bin/go mod download

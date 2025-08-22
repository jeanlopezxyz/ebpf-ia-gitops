#!/bin/bash
set -euo pipefail

# Script to generate TLS certificates for container registry
# This creates a proper CA and server certificate for secure HTTPS access

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs/registry"
REGISTRY_HOST="registry.container-registry.svc.cluster.local"
REGISTRY_IP="192.168.67.2"

echo "🔐 Generating TLS certificates for container registry..."

# Create certificate directory
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca.pem -subj "/CN=Container Registry CA"

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Create certificate signing request
openssl req -subj "/CN=${REGISTRY_HOST}" -sha256 -new -key server-key.pem -out server.csr

# Create extensions file for server certificate
cat > server-extfile.cnf <<EOF
subjectAltName = DNS:${REGISTRY_HOST},DNS:registry,IP:${REGISTRY_IP},IP:127.0.0.1,DNS:localhost
extendedKeyUsage = serverAuth
EOF

# Generate server certificate
openssl x509 -req -days 3650 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem -extfile server-extfile.cnf -CAcreateserial

# Clean up temporary files
rm server.csr server-extfile.cnf ca.srl

# Set appropriate permissions
chmod 400 ca-key.pem server-key.pem
chmod 444 ca.pem server.pem

echo "✅ Certificates generated successfully:"
echo "   📁 Certificate directory: ${CERT_DIR}"
echo "   📜 CA Certificate: ca.pem"
echo "   🔑 CA Key: ca-key.pem"
echo "   📜 Server Certificate: server.pem"
echo "   🔑 Server Key: server-key.pem"
echo ""
echo "📋 Next steps:"
echo "   1. Update registry values to enable TLS"
echo "   2. Create Kubernetes secrets with certificates"
echo "   3. Sync ArgoCD applications"

# Display certificate info
echo ""
echo "🔍 Certificate details:"
openssl x509 -in server.pem -text -noout | grep -A5 "Subject Alternative Name" || echo "   Subject: ${REGISTRY_HOST}"
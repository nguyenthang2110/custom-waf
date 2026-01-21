#!/bin/bash
# Generate self-signed certificate for testing HTTPS/TLS

set -e

CERT_DIR="configs/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

echo "🔐 Generating self-signed certificate for WAF HTTPS..."

# Create directory if not exists
mkdir -p "$CERT_DIR"

# Generate certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 365 \
  -subj "/C=VN/ST=HCM/L=HoChiMinh/O=WAF-Project/OU=Security/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"

echo "✅ Certificate generated successfully!"
echo "   📄 Certificate: $CERT_FILE"
echo "   🔑 Private Key: $KEY_FILE"
echo ""
echo "⚠️  This is a SELF-SIGNED certificate for TESTING only!"
echo "   For production, use certificates from a trusted CA (Let's Encrypt, etc.)"

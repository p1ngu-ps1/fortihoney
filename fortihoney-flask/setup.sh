#!/bin/bash
#
# FortiHoney Setup Script - For Beginners!
# This script will guide you through setting up the honeypot
#

set -e  # Exit on any error

echo "=============================================="
echo "🍯 FortiHoney Setup Wizard"
echo "=============================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed!"
    echo "Install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed!"
    echo "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker is installed"
echo ""

# Generate API key if .env doesn't exist
if [ ! -f .env ]; then
    echo "🔑 Generating secure API key..."

    # Generate random API key
    API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || \
              openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)

    # Create .env file
    cat > .env << EOF
# FortiHoney Configuration
GO_ENV=production
FORTIHONEY_API_KEY=${API_KEY}
EOF

    echo "✅ API key generated and saved to .env"
    echo ""
    echo "🔐 Your API Key: ${API_KEY}"
    echo "   Save this somewhere safe! You'll need it to access logs via API."
    echo ""
else
    echo "✅ .env file already exists"
    API_KEY=$(grep FORTIHONEY_API_KEY .env | cut -d'=' -f2)
    echo "🔐 Your API Key: ${API_KEY}"
    echo ""
fi

# Create logs directory
echo "📁 Creating logs directory..."
mkdir -p logs
chmod 755 logs
echo "✅ Logs directory created"
echo ""

# SSL Certificate Setup
echo "🔒 SSL Certificate Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Do you want to generate a self-signed SSL certificate?"
echo "(Recommended for testing, but use a real certificate for production)"
echo ""
read -p "Generate self-signed certificate? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Generating self-signed SSL certificate..."

    mkdir -p nginx/ssl

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=FortiHoney/CN=fortihoney.local" \
        2>/dev/null

    echo "✅ Self-signed certificate generated"
    echo "   ⚠️  Browsers will show a warning (this is normal for self-signed certs)"
else
    echo ""
    echo "ℹ️  To use your own SSL certificate:"
    echo "   1. Copy your certificate to: nginx/ssl/cert.pem"
    echo "   2. Copy your private key to: nginx/ssl/key.pem"
    echo ""

    if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
        echo "⚠️  WARNING: SSL certificate not found!"
        echo "   Creating a temporary self-signed cert..."

        mkdir -p nginx/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=FortiHoney/CN=fortihoney.local" \
            2>/dev/null
    fi
fi

echo ""
echo "=============================================="
echo "✅ Setup Complete!"
echo "=============================================="
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Start FortiHoney:"
echo "   docker compose up -d"
echo ""
echo "2. Check logs:"
echo "   docker compose logs -f fortihoney"
echo ""
echo "3. View captured data:"
echo "   tail -f logs/fortihoney.json"
echo ""
echo "4. Access via API:"
echo "   curl -H \"Authorization: Bearer ${API_KEY}\" \\"
echo "     http://localhost:3000/api/v1/stats"
echo ""
echo "5. Wazuh Dashboard (after startup):"
echo "   http://YOUR_SERVER_IP:5601"
echo "   Username: admin"
echo "   Password: SecurePassword123!"
echo ""
echo "=============================================="
echo "🔐 Security Reminders:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "• Keep your API key secret"
echo "• Use a real SSL certificate in production"
echo "• Monitor logs regularly"
echo "• Update the Wazuh default password"
echo "• Configure your firewall (allow only 80/443)"
echo "=============================================="
echo ""
echo "Ready to start? Run: docker compose up -d"
echo ""

#!/bin/bash

# Output Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[+] Starting Stealth Honeypot Setup (FortiHoney + Wazuh)...${NC}"
echo -e "[+] Based on pcasaspere/fortihoney"

# 1. Dependency Check
echo "[+] Checking for Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Installing Docker...${NC}"
    curl -fsSL https://get.docker.com | sh
fi

# 2. Directory Structure
echo "[+] Creating data directories..."
mkdir -p data logs certs wazuh_config/rules wazuh_config/decoders
chmod -R 777 logs data

# 3. Generate Stealth SSL Certificate
if [ ! -f "certs/fortihoney.crt" ]; then
    echo "[+] Generating 'Stealth' SSL Certificate (Fake Fortinet)..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout certs/fortihoney.key -out certs/fortihoney.crt \
      -subj "/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=FortiGate/CN=FortiGate-Firewall"
fi

# 4. GeoIP Configuration
# Note: FortiHoney uses ip-api.com for geolocation (no local database required)
# The free tier allows 45 requests/minute, which is sufficient for honeypot usage

# 5. Kernel Tuning (Required for Wazuh)
echo "[+] Tuning kernel parameters (vm.max_map_count)..."
sudo sysctl -w vm.max_map_count=262144

# 6. Build and Deploy
echo "[+] Building and starting containers..."
docker compose up -d --build

echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   DEPLOYMENT COMPLETE - STEALTH MODE ACTIVE${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "Access via IP directly to avoid Phishing detection."
echo -e "Honeypot:                  ${GREEN}https://$(curl -s ifconfig.me):443${NC}"
echo -e "Wazuh Dashboard:           ${GREEN}https://$(curl -s ifconfig.me):8443${NC}"
echo -e "----------------------------------------------------------------"
echo -e "DICA: Your browser will show a 'Connection not private' warning."
echo -e "DICA: This is NORMAL and EXPECTED for a firewall honeypot.${NC}"
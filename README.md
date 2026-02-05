# 🛡️ FortiHoney + Wazuh Enterprise Deception Suite

This project implements a high-fidelity Honeypot that simulates a **Fortinet FortiGate SSL VPN** login portal. It is natively integrated with **Wazuh** for real-time monitoring, attack geolocation, and threat intelligence.

**Based on the original project:** [pcasaspere/fortihoney](https://github.com/pcasaspere/fortihoney)

## 🚀 Quick Installation Guide (VPS)

### 1. Prerequisites
- A VPS running **Linux (Ubuntu recommended)**.
- Minimum **4GB RAM** (8GB recommended for full Wazuh performance).
- Ports **443** (Honeypot) and **8443** (Wazuh Dashboard) open in your VPS firewall.

### 2. Deploy in 3 Steps
On your VPS terminal:

```bash
# 1. Clone your repository
git clone https://github.com/YOUR_USER/YOUR_REPO.git
cd YOUR_REPO

# 2. Grant execution permissions
chmod +x deploy.sh

# 3. Run the automated setup
./deploy.sh
```

---

## 🔐 Credentials and Access Management

### 1. Accessing the Control Panel (Wazuh)
After deployment, wait **3 to 5 minutes** for Wazuh to initialize all services.
- **URL:** `https://YOUR-VPS-IP:8443`
- **Default Username:** `admin`
- **Default Password:** `Admin@123`

### 2. Changing the Wazuh Password (CRITICAL)
Since your IP will be exposed to Shodan, attackers will attempt to access your Wazuh panel. Change the password immediately:
1. Log in to the Dashboard.
2. Go to **Settings** -> **Internal Users**.
3. Select the `admin` user and click **Change Password**.

### 3. Honeypot Credentials (The Bait)
- **The Honeypot accepts any username and password.**
- It will log the attempt and respond with `Permission Denied` to keep the attacker trying (brute-forcing).
- **Level 10 Alert:** The system triggers a high-priority alert if the following sensitive usernames are tried: `admin`, `root`, `fortinet`, `support`.

---

## 🕵️ Stealth Mode and Shodan
This project is pre-configured to be indexed as a **real target**:
- **Headers:** The server identifies itself as `httpd` (common in embedded network devices).
- **SSL:** Uses a self-signed certificate issued to `O=Fortinet, OU=FortiGate`.
- **Anti-Bot:** Includes a `robots.txt` to prevent Google indexing, focusing only on security scanners (Shodan/Censys).

---

## 📊 Monitoring Attacks
To view raw JSON logs (being processed by Wazuh):
```bash
tail -f logs/fortihoney.json
```

To view the local SQLite database:
```bash
sqlite3 data/fortihoney_fortihoney_production.sqlite "SELECT * FROM logs ORDER BY created_at DESC LIMIT 10;"
```

---

## 🛠️ Maintenance
- **Restart services:** `docker compose restart`
- **View error logs:** `docker compose logs -f`
- **Update GeoIP:** Replace the file in `fortihoney/files/GeoLite2-City.mmdb` and restart the `fortihoney` container.

---
**Disclaimer:** This software is for research and cyber defense purposes only. The deployment of honeypots in corporate networks must follow your organization's compliance and security policies.
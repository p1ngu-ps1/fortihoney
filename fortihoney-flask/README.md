# 🍯 FortiHoney - FortiGate Honeypot

Production-ready honeypot that mimics FortiGate SSL-VPN. Logs ALL attacks with CVE detection.

## Quick Start

```bash
./setup.sh              # Generate API key + SSL cert
docker compose up -d    # Start honeypot
```

## 🎯 What's Logged

**Everything that hits the honeypot:**
- ✅ Login attempts (username, password, IP, country)
- ✅ Path scanning (all URLs tried)
- ✅ CVE exploitation attempts (5 critical CVEs detected)
- ✅ API probes
- ✅ All HTTP requests with full headers & body

## 🔥 CVE Detection

Automatically detects these critical CVEs:
- **CVE-2018-13379** - Path traversal (credentials theft)
- **CVE-2022-40684** - Authentication bypass
- **CVE-2022-42475** - Heap overflow (RCE)
- **CVE-2023-27997** - XORtigate (RCE)
- **CVE-2024-21762** - Out-of-bounds write (RCE)

## 🎮 Admin Panel (Hacker Style)

Access the web panel to view logs in style:

```
https://YOUR_SERVER_IP/admin/panel
```

**Authentication:** Use your API key in browser
- Add extension: [ModHeader](https://modheader.com/)
- Set header: `Authorization: Bearer YOUR_API_KEY`

Or access directly in code:
```javascript
fetch('https://YOUR_SERVER_IP/admin/panel', {
    headers: { 'Authorization': 'Bearer YOUR_API_KEY' }
})
```

**Features:**
- Matrix rain effect background
- Real-time log viewer with auto-refresh
- CVE attempt highlighting
- Top attacking IPs & countries
- Event type statistics
- Hacker/crack tool aesthetic (black/green terminal style)

## 🔑 Get Your API Key

```bash
cat .env | grep FORTIHONEY_API_KEY
```

## 📊 View Logs

**Web Panel (Recommended):**
```
https://YOUR_SERVER_IP/admin/panel
```

**Command Line:**
```bash
# Real-time logs
tail -f logs/fortihoney.json | jq

# Docker logs
docker compose logs -f

# Filter CVE attempts
grep "cve_attempts" logs/fortihoney.json | jq
```

**API Access:**
```bash
# Get statistics
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/v1/stats

# Get recent logs
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/v1/logs?limit=10

# Filter by event type
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:3000/api/v1/logs?event_type=login_attempt&limit=50"
```

## 🛡️ FortiGate Paths Implemented

**Core SSL-VPN:**
- `/remote/login` - Login page (GET)
- `/remote/logincheck` - Login submission (POST)
- `/remote/logout` - Logout endpoint
- `/remote/info` - Info endpoint (returns salt)
- `/remote/fgt_lang` - Language file (CVE-2018-13379 detection)
- `/remote/hostcheck_validate` - Host check validation
- `/remote/hostcheck_periodic` - Periodic host check
- `/sslvpn/portal.html` - Portal page

**API Endpoints:**
- `/api/v2/cmdb/<path>` - Configuration API
- `/api/v2/monitor/<path>` - Monitor API
- `/login` - API login

**Static Files:**
- `/favicon.ico`, `/css/*`, `/js/*`, `/fonts/*`
- `/styles.css`, `/robots.txt`

**Catch-All:**
- Any other path is logged as `path_probe`

## 📝 Example Log Entry

```json
{
  "event_type": "login_attempt",
  "ip": "203.0.113.42",
  "country": "CN",
  "asn": "AS4134 CHINANET-BACKBONE",
  "user_agent": "Mozilla/5.0...",
  "method": "POST",
  "path": "/remote/logincheck",
  "username": "admin",
  "password": "password123",
  "suspicious": false,
  "cve_attempts": null,
  "timestamp": "2026-02-06T00:30:00.000000Z"
}
```

**CVE Attempt Example:**
```json
{
  "event_type": "cve_2018_13379_attempt",
  "ip": "198.51.100.50",
  "path": "/remote/fgt_lang",
  "query_string": "lang=/../../../../dev/cmdb/sslvpn_websession",
  "suspicious": true,
  "cve_attempts": [{
    "cve_id": "CVE-2018-13379",
    "description": "Path traversal vulnerability",
    "severity": "CRITICAL"
  }],
  "timestamp": "2026-02-06T00:31:00.000000Z"
}
```

## 🔧 Commands

```bash
# Start
docker compose up -d

# Stop
docker compose down

# Restart
docker compose restart

# View logs
docker compose logs -f

# Run tests
./test.sh
```

## 🔥 SSL Certificate

**Self-signed (Testing):**
```bash
./setup.sh  # Auto-generates
```

**Let's Encrypt (Production):**
```bash
sudo certbot certonly --standalone -d your-domain.com
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
docker compose restart nginx
```

## 🌐 Firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 🚨 Troubleshooting

**Port in use:**
```bash
sudo lsof -i :3000
```

**Logs not writing:**
```bash
sudo chown -R 1000:1000 logs/
```

**API 401 error:**
```bash
cat .env | grep FORTIHONEY_API_KEY
```

**Admin panel not loading:**
- Make sure you're using HTTPS (not HTTP)
- Check API key is correct
- Use ModHeader extension or curl with Authorization header

## 📋 What Makes This Different

✅ **Real FortiGate paths** - Mimics actual FortiGate SSL-VPN
✅ **CVE detection** - Detects 5 critical CVEs automatically
✅ **Comprehensive logging** - Logs EVERYTHING (not just logins)
✅ **Hacker-style panel** - Matrix theme, crack tool aesthetic
✅ **Production security** - Rate limiting, input validation, API auth
✅ **Easy setup** - 2 commands to run

## 🎯 Use Cases

- Capture attacker credentials
- Detect CVE exploitation attempts
- Monitor scanning behavior
- Threat intelligence gathering
- Security research
- Wazuh/SIEM integration

## ⚖️ License

MIT License - Use for defensive security purposes only.

**Legal Notice:** This is a HONEYPOT. Ensure you have authorization to deploy on your network and comply with local laws.

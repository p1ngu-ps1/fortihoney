# 🍯 FortiHoney - FortiGate Honeypot

Production-ready honeypot that mimics FortiGate SSL-VPN login. Logs all attacks to JSON.

## Quick Start

```bash
./setup.sh              # Generate API key + SSL cert
docker compose up -d    # Start honeypot
```

## View Logs

```bash
# Real-time logs
tail -f logs/fortihoney.json | jq

# Docker logs
docker compose logs -f

# Get API key
cat .env | grep FORTIHONEY_API_KEY
```

## API Access

```bash
# Get statistics
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/v1/stats

# Get recent logs
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/v1/logs?limit=10
```

## What Gets Logged

Every interaction is logged to `logs/fortihoney.json`:

```json
{
  "event_type": "login_attempt",
  "ip": "203.0.113.42",
  "country": "CN",
  "username": "admin",
  "password": "password123",
  "timestamp": "2026-02-05T15:30:00Z"
}
```

Logged events:
- Login attempts (username, password, IP, country)
- Path scanning (URLs attackers try)
- HTTP requests (all requests)
- Suspicious patterns (auto-flagged)

## Security Features

- Input sanitization
- Rate limiting (20 req/min per IP)
- API authentication (Bearer token)
- Non-root Docker container
- Read-only filesystem (except logs)
- Security headers (CSP, X-Frame-Options, etc.)

## Commands

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

## SSL Certificate

The setup script generates a self-signed certificate. For production, use Let's Encrypt:

```bash
sudo certbot certonly --standalone -d your-domain.com
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
docker compose restart nginx
```

## Firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## Troubleshooting

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

## License

MIT License - Use for defensive security purposes only.

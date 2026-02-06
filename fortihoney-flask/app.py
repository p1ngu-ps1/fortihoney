#!/usr/bin/env python3
"""
FortiHoney - Secure FortiGate Honeypot
Mimics real FortiGate SSL-VPN with comprehensive logging and CVE detection.

Security Features:
- Rate limiting per IP
- Input validation and sanitization
- Secure headers (CSP, X-Frame-Options, etc.)
- Request logging with CVE pattern detection
- API authentication with bearer tokens
- Protection against common attacks
"""

import os
import json
import secrets
import hashlib
import re
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from typing import Optional

from flask import Flask, request, render_template, redirect, jsonify, make_response, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__)

# Security: Load secret API key from environment
API_SECRET_KEY = os.getenv('FORTIHONEY_API_KEY', secrets.token_urlsafe(32))
if not os.getenv('FORTIHONEY_API_KEY'):
    print("⚠️  WARNING: FORTIHONEY_API_KEY not set. Using random key (will change on restart)")
    print(f"🔑 Generated API Key: {API_SECRET_KEY}")

# Trust proxy headers (X-Real-IP, X-Forwarded-For)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Disable Flask debug mode in production
app.config['DEBUG'] = os.getenv('GO_ENV') != 'production'
app.config['ENV'] = 'production' if os.getenv('GO_ENV') == 'production' else 'development'

# JSON log file path
LOG_FILE = '/app/logs/fortihoney.json' if os.getenv('GO_ENV') == 'production' else './logs/fortihoney.json'

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ============================================================================
# SECURITY: RATE LIMITING
# ============================================================================

rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW = 60

def is_rate_limited(ip: str) -> bool:
    """Check if IP has exceeded rate limit."""
    now = datetime.now()
    rate_limit_store[ip] = [
        timestamp for timestamp in rate_limit_store[ip]
        if now - timestamp < timedelta(seconds=RATE_LIMIT_WINDOW)
    ]

    if len(rate_limit_store[ip]) >= RATE_LIMIT_REQUESTS:
        return True

    rate_limit_store[ip].append(now)
    return False

# ============================================================================
# SECURITY: INPUT VALIDATION & SANITIZATION
# ============================================================================

def sanitize_input(text: str, max_length: int = 256) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not text:
        return ""
    text = text[:max_length]
    text = text.replace('\x00', '')
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
    return text.strip()

# ============================================================================
# CVE DETECTION PATTERNS
# ============================================================================

CVE_PATTERNS = {
    'CVE-2018-13379': {
        'pattern': r'/remote/fgt_lang.*\.\./|/dev/cmdb/|sslvpn_websession',
        'description': 'Path traversal vulnerability',
        'severity': 'CRITICAL'
    },
    'CVE-2022-40684': {
        'pattern': r'Report Runner',
        'description': 'Authentication bypass via manipulated headers',
        'severity': 'CRITICAL',
        'check_headers': True
    },
    'CVE-2022-42475': {
        'pattern': r'POST.*sslvpn|heap.*overflow',
        'description': 'Heap-based buffer overflow',
        'severity': 'CRITICAL'
    },
    'CVE-2023-27997': {
        'pattern': r'XORtigate|sslvpnd',
        'description': 'XORtigate heap overflow',
        'severity': 'CRITICAL'
    },
    'CVE-2024-21762': {
        'pattern': r'chunk.*size|out.*bounds',
        'description': 'Out-of-bounds write',
        'severity': 'CRITICAL'
    }
}

def detect_cve_attempt(path: str, query_string: str, headers: dict, body: str = '') -> list:
    """Detect CVE exploitation attempts."""
    detected_cves = []
    check_string = f"{path} {query_string} {body}".lower()

    for cve_id, cve_info in CVE_PATTERNS.items():
        if re.search(cve_info['pattern'], check_string, re.IGNORECASE):
            detected_cves.append({
                'cve_id': cve_id,
                'description': cve_info['description'],
                'severity': cve_info['severity']
            })

        # Check headers for specific CVEs
        if cve_info.get('check_headers'):
            forwarded = headers.get('Forwarded', '').lower()
            user_agent = headers.get('User-Agent', '').lower()
            if '127.0.0.1' in forwarded or 'report runner' in user_agent:
                detected_cves.append({
                    'cve_id': cve_id,
                    'description': cve_info['description'],
                    'severity': cve_info['severity']
                })

    return detected_cves

def is_suspicious_request(path: str, query_string: str, user_agent: str, headers: dict) -> bool:
    """Detect suspicious scanning/attack patterns."""
    suspicious_patterns = [
        # Path traversal
        '../', '..\\', '/etc/', '/proc/', '/var/', '/dev/cmdb/',
        # Common exploits
        '.env', '.git', '.aws', 'wp-admin', 'phpmyadmin',
        'shell', 'cmd', 'exec', 'eval', 'base64',
        # SQL injection
        "' OR ", '" OR ', 'UNION SELECT', 'DROP TABLE',
        # XSS
        '<script', 'javascript:', 'onerror=',
        # Path traversal (encoded)
        '%2e%2e', '....',
        # ROP/shellcode indicators
        '\\x90', '%u', 'shellcode', 'payload',
        # Common scanning
        '/api/', '/admin/', '/config/', '/backup/',
    ]

    check_string = (path + query_string + user_agent).lower()

    # Check forwarded headers for CVE-2022-40684
    if '127.0.0.1' in headers.get('Forwarded', '').lower():
        return True

    return any(pattern.lower() in check_string for pattern in suspicious_patterns)

# ============================================================================
# SECURITY: GEOLOCATION
# ============================================================================

geo_cache = {}

def get_geo_data(ip: str) -> dict:
    """Get geolocation data for IP using ip-api.com."""
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,as',
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                result = {
                    'country': data.get('country', '--'),
                    'country_code': data.get('countryCode', '--'),
                    'asn': data.get('as', '--')
                }
                geo_cache[ip] = result
                return result
    except Exception as e:
        app.logger.warning(f"GeoIP lookup failed for {ip}: {e}")

    return {'country': '--', 'country_code': '--', 'asn': '--'}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def get_real_ip() -> str:
    """Extract real client IP."""
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_to_json(log_entry: dict):
    """Append log entry to JSON file."""
    try:
        log_entry['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        with open(LOG_FILE, 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')
    except Exception as e:
        app.logger.error(f"Failed to write log: {e}")

def log_request(event_type: str, details: dict):
    """Log any request/event to JSON."""
    ip = get_real_ip()
    geo = get_geo_data(ip)

    # Get request body for POST requests
    body = ''
    if request.method == 'POST':
        try:
            body = request.get_data(as_text=True)[:1024]  # Limit body size
        except:
            body = ''

    # Detect CVE attempts
    cve_attempts = detect_cve_attempt(
        request.path,
        request.query_string.decode('utf-8', errors='ignore'),
        dict(request.headers),
        body
    )

    # Check if suspicious
    suspicious = is_suspicious_request(
        request.path,
        request.query_string.decode('utf-8', errors='ignore'),
        request.headers.get('User-Agent', ''),
        dict(request.headers)
    ) or len(cve_attempts) > 0

    log_entry = {
        'event_type': event_type,
        'ip': ip,
        'country': geo['country_code'],
        'asn': geo['asn'],
        'user_agent': request.headers.get('User-Agent', '')[:512],
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode('utf-8', errors='ignore')[:512],
        'headers': {
            'Forwarded': request.headers.get('Forwarded', ''),
            'X-Forwarded-For': request.headers.get('X-Forwarded-For', ''),
            'Referer': request.headers.get('Referer', '')[:512],
        },
        'suspicious': suspicious,
        'cve_attempts': cve_attempts if cve_attempts else None,
        **details
    }

    # Add body for POST requests
    if body:
        log_entry['body'] = body

    log_to_json(log_entry)

    # Debug output
    if app.config['DEBUG']:
        print(f"\n{'='*50}")
        print(f"[{event_type.upper()}] {ip} - {request.method} {request.path}")
        print(f"Country: {geo['country_code']} | ASN: {geo['asn']}")
        if cve_attempts:
            print(f"⚠️  CVE ATTEMPTS: {[c['cve_id'] for c in cve_attempts]}")
        if suspicious:
            print(f"⚠️  SUSPICIOUS REQUEST")
        if details:
            print(f"Details: {json.dumps(details, indent=2)}")
        print(f"{'='*50}\n")

# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

@app.before_request
def security_checks():
    """Run security checks on every request."""
    ip = get_real_ip()

    # Rate limiting
    if is_rate_limited(ip):
        log_request('rate_limit_exceeded', {
            'action': 'blocked',
            'limit': RATE_LIMIT_REQUESTS,
            'window_seconds': RATE_LIMIT_WINDOW
        })
        return jsonify({'error': 'Rate limit exceeded'}), 429

    # Log all requests (except some static files to reduce noise)
    if not request.path.endswith(('.png', '.jpg', '.ico', '.woff', '.woff2')):
        log_request('http_request', {
            'referer': request.headers.get('Referer', '')[:512],
        })

@app.after_request
def security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ============================================================================
# API AUTHENTICATION
# ============================================================================

def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401

        token = auth_header.replace('Bearer ', '', 1)

        if not secrets.compare_digest(token, API_SECRET_KEY):
            log_request('api_auth_failed', {
                'action': 'blocked',
                'token_hash': hashlib.sha256(token.encode()).hexdigest()[:16]
            })
            return jsonify({'error': 'Invalid API key'}), 403

        return f(*args, **kwargs)

    return decorated_function

# ============================================================================
# ROUTES: FORTIGATE SSL-VPN PATHS
# ============================================================================

@app.route('/')
def home():
    """Root page - redirect to login."""
    return redirect('/remote/login', code=307)

@app.route('/remote/login', methods=['GET'])
def login_page():
    """Display FortiGate login page."""
    error_message = request.cookies.get('flash_error', '')
    return render_template('login.html', error=error_message)

@app.route('/remote/logincheck', methods=['POST'])
def login_check():
    """Handle login form submission."""
    username = sanitize_input(request.form.get('username', ''), max_length=128)
    password = sanitize_input(request.form.get('credential', ''), max_length=128)

    log_request('login_attempt', {
        'username': username,
        'password': password,
        'form_data': {k: v[:128] for k, v in request.form.items() if k not in ['credential']}
    })

    response = make_response(redirect('/remote/login', code=303))
    response.set_cookie(
        'flash_error',
        'Error: Permission denied.',
        max_age=5,
        httponly=True,
        samesite='Strict'
    )
    return response

@app.route('/remote/logout', methods=['GET'])
def logout():
    """FortiGate logout endpoint."""
    log_request('logout_attempt', {})
    return redirect('/remote/login', code=307)

@app.route('/remote/info', methods=['GET'])
def remote_info():
    """FortiGate info endpoint (returns salt)."""
    log_request('info_request', {})
    # Return realistic response
    return jsonify({
        'ret': 1,
        'salt': secrets.token_hex(16)
    })

@app.route('/remote/fgt_lang', methods=['GET'])
def fgt_lang():
    """FortiGate language file endpoint."""
    lang = request.args.get('lang', 'en')

    # Detect CVE-2018-13379 path traversal attempt
    if '../' in lang or '/dev/cmdb/' in lang.lower():
        log_request('cve_2018_13379_attempt', {
            'attempted_lang': lang,
            'cve': 'CVE-2018-13379',
            'severity': 'CRITICAL'
        })
        return "Access denied", 403

    # Return minimal JavaScript
    return """
    var fgt_lang = {
        "error": "Error",
        "sslvpn_login_permission_denied": "Permission denied",
        "Username": "Username",
        "sslvpn_portal::Password": "Password"
    };
    """, 200, {'Content-Type': 'application/javascript'}

@app.route('/remote/hostcheck_validate', methods=['GET', 'POST'])
def hostcheck_validate():
    """FortiGate host check validation."""
    log_request('hostcheck_validate', {
        'enc_param': request.args.get('enc', '')
    })
    return jsonify({'ret': 1})

@app.route('/remote/hostcheck_periodic', methods=['GET'])
def hostcheck_periodic():
    """FortiGate periodic host check."""
    log_request('hostcheck_periodic', {})
    return jsonify({'ret': 1})

@app.route('/sslvpn/portal.html', methods=['GET'])
def portal():
    """SSL VPN portal (post-login page)."""
    log_request('portal_access', {})
    return redirect('/remote/login', code=307)

# ============================================================================
# ROUTES: FORTIGATE API ENDPOINTS (v2)
# ============================================================================

@app.route('/api/v2/cmdb/<path:api_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_cmdb(api_path):
    """FortiGate Configuration API."""
    log_request('api_cmdb_request', {
        'api_path': api_path,
        'api_version': 'v2'
    })
    return jsonify({'error': 'Authentication required'}), 401

@app.route('/api/v2/monitor/<path:api_path>', methods=['GET', 'POST'])
def api_monitor(api_path):
    """FortiGate Monitor API."""
    log_request('api_monitor_request', {
        'api_path': api_path,
        'api_version': 'v2'
    })
    return jsonify({'error': 'Authentication required'}), 401

@app.route('/login', methods=['POST'])
def api_login():
    """API login endpoint."""
    username = request.form.get('username', '')
    password = request.form.get('secretkey', '')

    log_request('api_login_attempt', {
        'username': sanitize_input(username),
        'password': sanitize_input(password)
    })
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# ROUTES: STATIC FILES
# ============================================================================

@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    return send_from_directory('static/favicon', 'favicon.ico')

@app.route('/css/<path:filename>')
def css_files(filename):
    """Serve CSS files."""
    return send_from_directory('static/css', filename)

@app.route('/js/<path:filename>')
def js_files(filename):
    """Serve JavaScript files."""
    return send_from_directory('static/js', filename)

@app.route('/fonts/<path:filename>')
def font_files(filename):
    """Serve font files."""
    return send_from_directory('static/fonts', filename)

@app.route('/styles.css')
def styles():
    """Serve main stylesheet."""
    return send_from_directory('static', 'styles.css')

@app.route('/robots.txt')
def robots():
    """Serve robots.txt."""
    return send_from_directory('static', 'robots.txt')

# ============================================================================
# ROUTES: STATIC LOGS VIEWER (HACKER STYLE)
# ============================================================================

@app.route('/logs', methods=['GET'])
def logs_viewer():
    """Static page for viewing logs (hacker aesthetic)."""
    return render_template('logs_viewer.html')

@app.route('/api/logs/data', methods=['GET'])
def logs_data():
    """Serve raw JSON log data for the static viewer (no auth required)."""
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify([])

        logs = []
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except:
                    continue

        # Return last 500 logs (newest first)
        return jsonify(list(reversed(logs[-500:])))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# ROUTES: SECURE API (for log retrieval)
# ============================================================================

@app.route('/api/v1/logs', methods=['GET'])
@require_api_key
def get_logs():
    """Retrieve logs with filtering."""
    try:
        limit = min(int(request.args.get('limit', 100)), 1000)
        event_type = request.args.get('event_type', None)

        logs = []
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())

                    if event_type and log.get('event_type') != event_type:
                        continue

                    logs.append(log)

                    if len(logs) >= limit:
                        break
                except json.JSONDecodeError:
                    continue

        logs.reverse()

        return jsonify({
            'success': True,
            'count': len(logs),
            'logs': logs[:limit]
        })

    except FileNotFoundError:
        return jsonify({'error': 'No logs found'}), 404
    except Exception as e:
        app.logger.error(f"API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get statistics about logged events."""
    try:
        stats = {
            'total_events': 0,
            'event_types': defaultdict(int),
            'top_ips': defaultdict(int),
            'top_countries': defaultdict(int),
            'cve_attempts': defaultdict(int),
            'suspicious_requests': 0
        }

        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    stats['total_events'] += 1
                    stats['event_types'][log.get('event_type', 'unknown')] += 1
                    stats['top_ips'][log.get('ip', 'unknown')] += 1
                    stats['top_countries'][log.get('country', 'unknown')] += 1

                    if log.get('suspicious'):
                        stats['suspicious_requests'] += 1

                    if log.get('cve_attempts'):
                        for cve in log['cve_attempts']:
                            stats['cve_attempts'][cve['cve_id']] += 1

                except json.JSONDecodeError:
                    continue

        return jsonify({
            'success': True,
            'total_events': stats['total_events'],
            'event_types': dict(stats['event_types']),
            'top_ips': dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:20]),
            'top_countries': dict(sorted(stats['top_countries'].items(), key=lambda x: x[1], reverse=True)[:20]),
            'cve_attempts': dict(stats['cve_attempts']),
            'suspicious_requests': stats['suspicious_requests']
        })

    except FileNotFoundError:
        return jsonify({'error': 'No logs found'}), 404
    except Exception as e:
        app.logger.error(f"API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# CATCH-ALL FOR SCANNING/CVE ATTEMPTS
# ============================================================================

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """Log all other path attempts."""
    log_request('path_probe', {
        'attempted_path': path[:512],
    })
    return "404 Not Found", 404

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler."""
    return "404 Not Found", 404

@app.errorhandler(500)
def internal_error(e):
    """Custom 500 handler."""
    app.logger.error(f"Internal error: {e}")
    return "500 Internal Server Error", 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("="*60)
    print("🍯 FortiHoney - Secure FortiGate Honeypot")
    print("="*60)
    print(f"Environment: {app.config['ENV']}")
    print(f"Log file: {LOG_FILE}")
    print(f"API Key: {API_SECRET_KEY[:16]}...{API_SECRET_KEY[-8:]}")
    print("="*60)
    print("Security Features Enabled:")
    print("  ✓ Rate limiting (20 req/min per IP)")
    print("  ✓ Input sanitization")
    print("  ✓ CVE detection (5 critical CVEs)")
    print("  ✓ Security headers")
    print("  ✓ API authentication")
    print("  ✓ GeoIP logging")
    print("  ✓ Comprehensive request logging")
    print("="*60)
    print("FortiGate Paths Implemented:")
    print("  ✓ /remote/login, /remote/logincheck")
    print("  ✓ /remote/logout, /remote/info")
    print("  ✓ /remote/fgt_lang (CVE-2018-13379 detection)")
    print("  ✓ /remote/hostcheck_*")
    print("  ✓ /api/v2/cmdb/*, /api/v2/monitor/*")
    print("  ✓ Static files (CSS, JS, fonts)")
    print("="*60)

    if app.config['DEBUG']:
        app.run(host='0.0.0.0', port=3000, debug=True)
    else:
        print("⚠️  Use gunicorn for production: gunicorn -w 4 -b 0.0.0.0:3000 app:app")

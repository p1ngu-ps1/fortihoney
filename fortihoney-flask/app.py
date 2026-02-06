#!/usr/bin/env python3
"""
FortiHoney - Secure FortiGate Honeypot
Logs all login attempts and suspicious requests to JSON for Wazuh SIEM integration.

Security Features:
- Rate limiting per IP
- Input validation and sanitization
- Secure headers (CSP, X-Frame-Options, etc.)
- No sensitive data exposure
- Request logging with anomaly detection
- API authentication with bearer tokens
- Protection against common attacks (XSS, injection, etc.)
"""

import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from typing import Optional

from flask import Flask, request, render_template, redirect, jsonify, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__)

# Security: Load secret API key from environment (never hardcode!)
API_SECRET_KEY = os.getenv('FORTIHONEY_API_KEY', secrets.token_urlsafe(32))
if not os.getenv('FORTIHONEY_API_KEY'):
    print("⚠️  WARNING: FORTIHONEY_API_KEY not set. Using random key (will change on restart)")
    print(f"🔑 Generated API Key: {API_SECRET_KEY}")

# Trust proxy headers (X-Real-IP, X-Forwarded-For) - required behind nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Disable Flask debug mode in production (security critical!)
app.config['DEBUG'] = os.getenv('GO_ENV') != 'production'
app.config['ENV'] = 'production' if os.getenv('GO_ENV') == 'production' else 'development'

# JSON log file path
LOG_FILE = '/app/logs/fortihoney.json' if os.getenv('GO_ENV') == 'production' else './logs/fortihoney.json'

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ============================================================================
# SECURITY: RATE LIMITING
# ============================================================================

# Simple in-memory rate limiter (per IP)
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 20  # Max requests per window
RATE_LIMIT_WINDOW = 60    # Time window in seconds

def is_rate_limited(ip: str) -> bool:
    """Check if IP has exceeded rate limit."""
    now = datetime.now()
    # Clean old entries
    rate_limit_store[ip] = [
        timestamp for timestamp in rate_limit_store[ip]
        if now - timestamp < timedelta(seconds=RATE_LIMIT_WINDOW)
    ]

    # Check limit
    if len(rate_limit_store[ip]) >= RATE_LIMIT_REQUESTS:
        return True

    # Record this request
    rate_limit_store[ip].append(now)
    return False

# ============================================================================
# SECURITY: INPUT VALIDATION & SANITIZATION
# ============================================================================

def sanitize_input(text: str, max_length: int = 256) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not text:
        return ""

    # Truncate to max length
    text = text[:max_length]

    # Remove null bytes (common in injection attempts)
    text = text.replace('\x00', '')

    # Strip control characters except newline/tab
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')

    return text.strip()

def is_suspicious_request(path: str, user_agent: str) -> bool:
    """Detect suspicious scanning/attack patterns."""
    suspicious_patterns = [
        # Common exploit attempts
        '../', '..\\', '/etc/', '/proc/', '/var/',
        '.env', '.git', '.aws', 'wp-admin', 'phpmyadmin',
        'shell', 'cmd', 'exec', 'eval', 'base64',
        # SQL injection patterns
        "' OR ", '" OR ', 'UNION SELECT', 'DROP TABLE',
        # XSS patterns
        '<script', 'javascript:', 'onerror=',
        # Path traversal
        '%2e%2e', '....',
    ]

    check_string = (path + user_agent).lower()
    return any(pattern.lower() in check_string for pattern in suspicious_patterns)

# ============================================================================
# SECURITY: GEOLOCATION (with caching)
# ============================================================================

geo_cache = {}  # Simple in-memory cache

def get_geo_data(ip: str) -> dict:
    """Get geolocation data for IP using ip-api.com (with caching)."""
    # Check cache first
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        # Use ip-api.com (free, no key required)
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
                # Cache result
                geo_cache[ip] = result
                return result
    except Exception as e:
        app.logger.warning(f"GeoIP lookup failed for {ip}: {e}")

    # Return defaults on failure
    return {'country': '--', 'country_code': '--', 'asn': '--'}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def get_real_ip() -> str:
    """Extract real client IP (handles proxy headers)."""
    # Check X-Real-IP first (set by nginx)
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')

    # Check X-Forwarded-For
    if request.headers.get('X-Forwarded-For'):
        # Take first IP in chain
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()

    # Fallback to direct connection
    return request.remote_addr

def log_to_json(log_entry: dict):
    """Append log entry to JSON file (Wazuh integration)."""
    try:
        # Add timestamp
        log_entry['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # Write to file (append mode)
        with open(LOG_FILE, 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')
    except Exception as e:
        app.logger.error(f"Failed to write log: {e}")

def log_request(event_type: str, details: dict):
    """Log any request/event to JSON."""
    ip = get_real_ip()
    geo = get_geo_data(ip)

    log_entry = {
        'event_type': event_type,
        'ip': ip,
        'country': geo['country_code'],
        'asn': geo['asn'],
        'user_agent': request.headers.get('User-Agent', '')[:512],  # Truncate
        'method': request.method,
        'path': request.path,
        'suspicious': is_suspicious_request(request.path, request.headers.get('User-Agent', '')),
        **details
    }

    log_to_json(log_entry)

    # Print to console in development
    if app.config['DEBUG']:
        print(f"\n{'='*50}")
        print(f"[{event_type.upper()}] {ip} - {request.path}")
        print(f"Country: {geo['country_code']} | ASN: {geo['asn']}")
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

    # Log all requests (honeypot behavior - we want to see everything!)
    if request.path not in ['/favicon.ico']:  # Skip favicon spam
        log_request('http_request', {
            'query_string': request.query_string.decode('utf-8', errors='ignore')[:512],
            'referer': request.headers.get('Referer', '')[:512],
        })

@app.after_request
def security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy (strict)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "  # FortiGate JS needs inline
        "style-src 'self' 'unsafe-inline'; "   # FortiGate CSS needs inline
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # Referrer policy
    response.headers['Referrer-Policy'] = 'no-referrer'

    # Permissions policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    return response

# ============================================================================
# API AUTHENTICATION
# ============================================================================

def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from header
        auth_header = request.headers.get('Authorization', '')

        # Expected format: "Bearer <token>"
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401

        token = auth_header.replace('Bearer ', '', 1)

        # Constant-time comparison (prevent timing attacks)
        if not secrets.compare_digest(token, API_SECRET_KEY):
            log_request('api_auth_failed', {
                'action': 'blocked',
                'token_hash': hashlib.sha256(token.encode()).hexdigest()[:16]
            })
            return jsonify({'error': 'Invalid API key'}), 403

        return f(*args, **kwargs)

    return decorated_function

# ============================================================================
# ROUTES: HONEYPOT PAGES
# ============================================================================

@app.route('/')
def home():
    """Root page - redirect to login (realistic FortiGate behavior)."""
    return redirect('/remote/login', code=307)

@app.route('/remote/login', methods=['GET'])
def login_page():
    """Display FortiGate login page."""
    # Get flash error from cookie (if any)
    error_message = request.cookies.get('flash_error', '')

    return render_template('login.html', error=error_message)

@app.route('/remote/logincheck', methods=['POST'])
def login_check():
    """Handle login form submission (always fails - it's a honeypot!)."""
    # Get form data
    username = sanitize_input(request.form.get('username', ''), max_length=128)
    password = sanitize_input(request.form.get('credential', ''), max_length=128)

    # Log the login attempt
    log_request('login_attempt', {
        'username': username,
        'password': password,  # Store for threat intel (it's a honeypot!)
        'form_data': {k: v[:128] for k, v in request.form.items() if k not in ['credential']}
    })

    # Realistic FortiGate behavior: always redirect back with error
    response = make_response(redirect('/remote/login', code=307))

    # Set flash error cookie
    response.set_cookie(
        'flash_error',
        'Error: Permission denied.',
        max_age=5,  # Short-lived
        httponly=True,
        samesite='Strict'
    )

    return response

@app.route('/remote/fgt_lang')
def fgt_lang():
    """Fake FortiGate language endpoint (for realism)."""
    # Return minimal JavaScript that won't break the page
    return """
    var fgt_lang = {
        "error": "Error",
        "sslvpn_login_permission_denied": "Permission denied",
        "Username": "Username",
        "sslvpn_portal::Password": "Password"
    };
    """, 200, {'Content-Type': 'application/javascript'}

# Catch-all for suspicious path probing
@app.route('/<path:path>')
def catch_all(path):
    """Log all other path attempts (scanning behavior)."""
    log_request('path_probe', {
        'attempted_path': path[:512],
        'query': request.query_string.decode('utf-8', errors='ignore')[:512]
    })

    # Return 404 (don't reveal anything)
    return "404 Not Found", 404

# ============================================================================
# ROUTES: SECURE API (for log retrieval)
# ============================================================================

@app.route('/api/v1/logs', methods=['GET'])
@require_api_key
def get_logs():
    """
    Secure API endpoint to retrieve logs.
    Requires: Authorization: Bearer <API_KEY>

    Query params:
    - limit: Max number of logs to return (default: 100, max: 1000)
    - event_type: Filter by event type (login_attempt, path_probe, etc.)
    """
    try:
        # Parse query params
        limit = min(int(request.args.get('limit', 100)), 1000)
        event_type = request.args.get('event_type', None)

        # Read log file
        logs = []
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())

                    # Filter by event type if specified
                    if event_type and log.get('event_type') != event_type:
                        continue

                    logs.append(log)

                    # Stop if we hit limit
                    if len(logs) >= limit:
                        break
                except json.JSONDecodeError:
                    continue

        # Return most recent logs
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
    """
    Get statistics about logged events.
    Requires: Authorization: Bearer <API_KEY>
    """
    try:
        stats = {
            'total_events': 0,
            'event_types': defaultdict(int),
            'top_ips': defaultdict(int),
            'top_countries': defaultdict(int)
        }

        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    stats['total_events'] += 1
                    stats['event_types'][log.get('event_type', 'unknown')] += 1
                    stats['top_ips'][log.get('ip', 'unknown')] += 1
                    stats['top_countries'][log.get('country', 'unknown')] += 1
                except json.JSONDecodeError:
                    continue

        # Convert to sorted lists
        return jsonify({
            'success': True,
            'total_events': stats['total_events'],
            'event_types': dict(stats['event_types']),
            'top_ips': dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:20]),
            'top_countries': dict(sorted(stats['top_countries'].items(), key=lambda x: x[1], reverse=True)[:20])
        })

    except FileNotFoundError:
        return jsonify({'error': 'No logs found'}), 404
    except Exception as e:
        app.logger.error(f"API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler (don't reveal framework info)."""
    return "404 Not Found", 404

@app.errorhandler(500)
def internal_error(e):
    """Custom 500 handler (don't expose stack traces)."""
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
    print("  ✓ Security headers (CSP, X-Frame-Options, etc.)")
    print("  ✓ API authentication (Bearer token)")
    print("  ✓ GeoIP logging")
    print("  ✓ Comprehensive request logging")
    print("="*60)

    # Run with Werkzeug in development, use gunicorn in production
    if app.config['DEBUG']:
        app.run(host='0.0.0.0', port=3000, debug=True)
    else:
        print("⚠️  Use gunicorn for production: gunicorn -w 4 -b 0.0.0.0:3000 app:app")

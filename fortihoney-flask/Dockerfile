# ============================================================================
# Secure FortiHoney Dockerfile
#
# Security Features:
# - Non-root user (fortihoney)
# - Minimal Alpine base image
# - Read-only filesystem (except /app/logs)
# - No unnecessary packages
# - Security updates applied
# ============================================================================

FROM python:3.11-alpine

# Install security updates
RUN apk update && apk upgrade --no-cache

# Create non-root user (security best practice)
RUN addgroup -g 1000 fortihoney && \
    adduser -D -u 1000 -G fortihoney fortihoney

# Set working directory
WORKDIR /app

# Copy requirements first (better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && \
    chown -R fortihoney:fortihoney /app/logs

# Switch to non-root user (security critical!)
USER fortihoney

# Expose port 3000
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:3000/', timeout=2)" || exit 1

# Run with gunicorn (production-grade WSGI server)
# -w 4: 4 worker processes
# -b 0.0.0.0:3000: Bind to all interfaces on port 3000
# --access-logfile -: Log to stdout
# --error-logfile -: Log errors to stderr
# --log-level info: Info level logging
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:3000", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "app:app"]

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
import json
import threading
import time
from datetime import datetime, timedelta
import logging
import re
from fmc_push import (load_fmc_config, fmc_auth, create_fqdn, create_host, create_network, get_network_group_id, update_network_group,
                     deploy_changes, check_user_permissions, create_fqdn_alternative, check_pending_deployments,
                     get_deployment_history, get_all_network_groups, get_all_fqdns, remove_object_from_group,
                     delete_fqdn_object, add_object_to_group, search_objects, search_global, get_config_changes,
                     get_pending_changes)
import os
from oidc_auth import oidc_auth, init_oidc_routes
from werkzeug.middleware.proxy_fix import ProxyFix
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.fernet import Fernet
import hashlib
import base64
import socket
import ipaddress
import urllib.parse
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict
from functools import wraps
from flask_wtf.csrf import CSRFProtect

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security: Require SECRET_KEY to be set in environment
secret_key = os.getenv('FLASK_SECRET_KEY')
if not secret_key:
    logger.error("CRITICAL: FLASK_SECRET_KEY environment variable is not set!")
    logger.error("Please set FLASK_SECRET_KEY in your .env file to a secure random value")
    logger.error("Example: FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')")
    raise ValueError("FLASK_SECRET_KEY environment variable must be set for security")

app.secret_key = secret_key

# FIX #1: Enhanced Session Security Configuration
# Enforce secure cookies in production, allow HTTP only in development
is_production = os.getenv('FLASK_ENV', 'production') != 'development'
app.config['SESSION_COOKIE_NAME'] = 'fmc_manager_session'
app.config['SESSION_COOKIE_DOMAIN'] = None  # Let Flask determine the domain
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_SECURE'] = is_production  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
# Note: Using 'Lax' instead of 'Strict' for OIDC/OAuth2 compatibility
# 'Strict' can break OAuth flows where the user is redirected back from external provider
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('SESSION_LIFETIME', '3600')))
# Use HTTP in dev, HTTPS in production
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https' if is_production else 'http')

logger.info(f"Session security - Production mode: {is_production}, Secure cookies: {app.config['SESSION_COOKIE_SECURE']}")

# Trust proxy headers for HTTPS detection (behind nginx/traefik)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

logger.info(f"Flask app configured - Preferred URL scheme: {app.config['PREFERRED_URL_SCHEME']}")

# FIX #9: CSRF Protection - Initialize before OIDC to allow exemptions
csrf = CSRFProtect(app)
logger.info("✅ CSRF protection enabled")

# Initialize OIDC authentication (after CSRF so we can exempt the callback)
oidc_auth.init_app(app)
init_oidc_routes(app, csrf)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Enable XSS protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # FIX #10: Strengthened Content Security Policy
    # Note: 'unsafe-inline' is kept for now due to inline styles in templates
    # TODO: Migrate to external CSS/JS files and use nonces for better security
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests; "
        "block-all-mixed-content;"
    )

    # Referrer Policy - control information sent in Referer header
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy - restrict browser features
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # HTTPS enforcement (only if in production)
    if app.config['PREFERRED_URL_SCHEME'] == 'https':
        # Enforce HTTPS for 1 year
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response

# Request logging middleware
@app.before_request
def log_request_info():
    """Log all incoming requests for debugging"""
    logger.info(f"Request: {request.method} {request.url}")
    logger.info(f"  Remote addr: {request.remote_addr}")
    logger.info(f"  Headers: X-Forwarded-Proto={request.headers.get('X-Forwarded-Proto')}, X-Forwarded-Host={request.headers.get('X-Forwarded-Host')}")
    logger.info(f"  Session authenticated: {session.get('authenticated', False)}")
    logger.info(f"  OIDC enabled: {oidc_auth.enabled}")

# Global variables to store job status
job_status = {}
job_counter = 0
job_status_lock = threading.Lock()

# FIX #3: Encrypted Token Cache
# Initialize encryption cipher from secret key (must be base64-encoded 32 bytes)
fernet_key = base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode()).digest())
cipher_suite = Fernet(fernet_key)

# Token cache to avoid hitting FMC session limits
# Structure: {user_id:fmc_url: {'token': encrypted_token, 'expires': datetime_object}}
token_cache = {}
token_cache_lock = threading.Lock()

# Deployment status cache - cache results for 60 seconds
deployment_cache = {
    'data': None,
    'expires': datetime.min,
    'lock': threading.Lock()
}

# FIX #8: Rate Limiting Protection
# Structure: {ip_address: {'count': int, 'window_start': datetime}}
rate_limit_store = defaultdict(lambda: {'count': 0, 'window_start': datetime.now()})
rate_limit_lock = threading.Lock()

# Rate limiting configuration
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # requests per window
RATE_LIMIT_AUTH_MAX = 5  # authentication attempts per window
RATE_LIMIT_API_MAX = 30  # API calls per window

def rate_limit(max_requests=RATE_LIMIT_MAX_REQUESTS, window=RATE_LIMIT_WINDOW):
    """
    FIX #8: Rate limiting decorator to prevent brute force and DoS attacks

    Args:
        max_requests: Maximum number of requests allowed in the time window
        window: Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP (consider X-Forwarded-For for proxied requests)
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            else:
                client_ip = request.remote_addr

            current_time = datetime.now()

            with rate_limit_lock:
                client_data = rate_limit_store[client_ip]

                # Reset counter if window has elapsed
                time_elapsed = (current_time - client_data['window_start']).total_seconds()
                if time_elapsed > window:
                    client_data['count'] = 0
                    client_data['window_start'] = current_time

                # Check if limit exceeded
                if client_data['count'] >= max_requests:
                    logger.warning(f"Rate limit exceeded for IP {client_ip}: {client_data['count']} requests")
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'Too many requests. Please try again in {int(window - time_elapsed)} seconds.'
                    }), 429

                # Increment counter
                client_data['count'] += 1

            return f(*args, **kwargs)
        return wrapped
    return decorator

# FIX #4: SSRF Protection Strategy
# We use an allowlist approach: only URLs explicitly configured in FMC_LIST are allowed
# This allows legitimate internal FMC servers while blocking arbitrary external URLs
# Additional validation blocks truly dangerous targets (loopback, metadata services)

def get_allowed_fmc_urls():
    """Get list of allowed FMC URLs from configuration - acts as allowlist for SSRF prevention"""
    try:
        fmc_list = load_fmc_config()
        return {fmc.get("url") for fmc in fmc_list if fmc.get("url")}
    except Exception as e:
        logger.error(f"Error loading FMC configuration: {str(e)}")
        return set()

def get_safe_fmc_url(fmc_name):
    """
    Get FMC URL from configuration by name - SSRF safe.
    Returns None if FMC name not found or URL is invalid.
    This function acts as a security barrier by only returning URLs from the trusted config.
    """
    try:
        fmc_list = load_fmc_config()
        for fmc in fmc_list:
            if fmc.get("name") == fmc_name:
                url = fmc.get("url")
                # Validate the URL from config
                if url and validate_fmc_url(url):
                    return url
        return None
    except Exception as e:
        logger.error(f"Error getting safe FMC URL for {fmc_name}: {str(e)}")
        return None

def validate_uuid(uuid_string):
    """
    Validate that a string is a valid UUID format.
    This prevents injection attacks through ID parameters.
    Returns True if valid UUID, False otherwise.
    """
    import re
    if not uuid_string:
        return False
    # UUID format: 8-4-4-4-12 hex digits
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_pattern.match(str(uuid_string)))

def validate_fmc_url(url):
    """FIX #4: Enhanced SSRF Protection - Validate FMC URL with IP range checking"""
    if not url:
        return False

    # Sanitize URL input to prevent log injection
    safe_url = str(url).replace('\n', '').replace('\r', '')[:200]

    # SSRF Protection: Only allow URLs that are explicitly in our configuration
    allowed_urls = get_allowed_fmc_urls()
    if safe_url not in allowed_urls:
        logger.error(f"URL not in allowed FMC configuration: {safe_url}")
        return False

    try:
        parsed = urllib.parse.urlparse(safe_url)

        # Must be HTTPS
        if parsed.scheme != 'https':
            logger.error("URL must be HTTPS")
            return False

        # Must have a hostname
        if not parsed.hostname:
            logger.error("URL must contain a valid hostname")
            return False

        # Block URLs with query parameters or fragments
        if parsed.query or parsed.fragment:
            logger.error("URLs with query parameters or fragments are not allowed")
            return False

        # Validate port if specified
        if parsed.port and not (1 <= parsed.port <= 65535):
            logger.error(f"Invalid port: {parsed.port}")
            return False

        # FIX #4: DNS Resolution and IP Range Validation
        # Since URL is already in allowlist, we trust it's a legitimate internal FMC server
        # Only block truly dangerous targets (loopback, metadata services)
        try:
            hostname = parsed.hostname
            # Get all IP addresses for the hostname
            addr_info = socket.getaddrinfo(hostname, parsed.port or 443, socket.AF_UNSPEC, socket.SOCK_STREAM)

            for addr in addr_info:
                ip_str = addr[4][0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)

                    # Block loopback (prevents accessing localhost services)
                    if ip_obj.is_loopback:
                        logger.error(f"URL resolves to loopback address: {ip_str}")
                        return False

                    # Block link-local addresses (169.254.x.x, fe80::/10)
                    if ip_obj.is_link_local:
                        logger.error(f"URL resolves to link-local address: {ip_str}")
                        return False

                    # Block metadata service IPs (cloud provider metadata endpoints)
                    metadata_ips = [
                        ipaddress.ip_address('169.254.169.254'),  # AWS/Azure/GCP metadata
                        ipaddress.ip_address('fd00:ec2::254'),     # AWS IMDSv2 IPv6
                    ]
                    if ip_obj in metadata_ips:
                        logger.error(f"URL resolves to metadata service IP: {ip_str}")
                        return False

                except ValueError:
                    logger.error(f"Invalid IP address format: {ip_str}")
                    return False

        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {hostname}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"IP validation error: {str(e)}")
            return False

        return True

    except Exception as e:
        logger.error(f"URL validation error: {str(e)}")
        return False

def validate_object_name(name):
    """
    Validate object name - alphanumeric, underscore, dash, and period only.
    Returns (is_valid, error_message) tuple.
    """
    if not name:
        return False, "Object name is required"

    # Strip whitespace
    name = name.strip()

    # Length validation
    if len(name) < 1 or len(name) > 100:
        return False, "Object name must be between 1 and 100 characters"

    # Character validation - alphanumeric, underscore, dash, and period only
    # This prevents injection attacks through object names
    if not re.match(r'^[a-zA-Z0-9_.-]+$', name):
        return False, "Object name can only contain letters, numbers, underscores, dashes, and periods"

    # Prevent names that look like path traversal attempts
    if '..' in name or name.startswith('.') or name.startswith('-'):
        return False, "Object name cannot start with '.' or '-', or contain '..'"

    return True, ""

def sanitize_description(description):
    """
    Sanitize description field - remove HTML tags and limit special characters.
    Returns sanitized string.
    """
    if not description:
        return ""

    # Remove any HTML tags to prevent XSS
    description = re.sub(r'<[^>]*>', '', description)

    # Remove any potential script tags or event handlers (extra safety)
    description = re.sub(r'(?i)(javascript:|on\w+\s*=)', '', description)

    # Remove control characters except newlines and tabs
    description = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', description)

    # Limit length to prevent DoS
    max_length = 500
    if len(description) > max_length:
        description = description[:max_length]

    # Strip leading/trailing whitespace
    description = description.strip()

    return description

def validate_object_value(object_type, value):
    """
    FIX #2: Enhanced Input Validation
    Validate object value based on type (FQDN or Host) with strict RFC compliance.
    Returns (is_valid, error_message) tuple.
    """
    if not value:
        return False, "Object value is required"

    value = value.strip()

    if object_type == 'fqdn':
        # FQDN validation - RFC 1035 compliant
        # Total length must not exceed 253 characters (RFC 1035)
        if len(value) > 253:
            return False, "FQDN cannot exceed 253 characters (RFC 1035)"

        # FQDN must have at least 2 labels (e.g., example.com)
        labels = value.split('.')
        if len(labels) < 2:
            return False, "FQDN must have at least 2 labels (e.g., example.com)"

        # Validate each label
        for i, label in enumerate(labels):
            # Wildcard validation - only allowed as first label
            if label == '*':
                if i != 0:
                    return False, "Wildcard (*) only allowed as first label"
                continue

            # Each label must be between 1 and 63 characters (RFC 1035)
            if len(label) < 1 or len(label) > 63:
                return False, f"Label '{label}' must be between 1 and 63 characters"

            # Label must not start or end with hyphen
            if label.startswith('-') or label.endswith('-'):
                return False, f"Label '{label}' cannot start or end with hyphen"

            # Label must contain only alphanumeric characters and hyphens
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return False, f"Label '{label}' contains invalid characters. Only alphanumeric and hyphens allowed"

        # Additional security check: Prevent homograph attacks
        # Block labels that mix numbers and letters in suspicious ways
        for label in labels:
            if label == '*':
                continue
            # Check for suspicious patterns like "g00gle" or "micr0soft"
            if re.search(r'[0-9].*[a-zA-Z]|[a-zA-Z].*[0-9]', label):
                # Allow common patterns like "fmc-1" or "server2"
                if not re.match(r'^[a-zA-Z]+-\d+$|^[a-zA-Z]+\d+$', label):
                    logger.warning(f"Suspicious FQDN pattern detected: {label}")

        return True, ""

    elif object_type == 'host':
        # IPv4 address validation with additional checks
        try:
            # Use ipaddress module for proper validation
            ip_obj = ipaddress.IPv4Address(value)

            # Block special-use addresses
            if ip_obj.is_multicast:
                return False, "Multicast addresses are not allowed"
            if ip_obj.is_reserved:
                return False, "Reserved addresses are not allowed"
            if ip_obj.is_unspecified:
                return False, "Unspecified address (0.0.0.0) is not allowed"

            # Warn about private addresses (but allow them)
            if ip_obj.is_private:
                logger.info(f"Private IP address detected: {value}")

            return True, ""

        except ValueError:
            return False, "Invalid IPv4 address format. Use format like '192.168.1.1'"

    elif object_type == 'network':
        # IPv4 network validation with CIDR notation (e.g., 10.10.10.0/24)
        try:
            # Use ipaddress module for proper validation
            # strict=False allows host bits to be set (e.g., 10.10.10.1/24)
            # We'll normalize this to the proper network address (10.10.10.0/24)
            network_obj = ipaddress.IPv4Network(value, strict=False)

            # Validate network prefix length
            if network_obj.prefixlen < 1 or network_obj.prefixlen > 32:
                logger.warning(f"❌ Invalid network prefix length for '{value}': /{network_obj.prefixlen}")
                return False, "Network prefix length must be between 1 and 32"

            # Block special-use networks
            if network_obj.is_multicast:
                logger.warning(f"❌ Multicast network rejected: '{value}'")
                return False, "Multicast networks are not allowed"
            if network_obj.is_unspecified:
                logger.warning(f"❌ Unspecified network rejected: '{value}'")
                return False, "Unspecified network (0.0.0.0/0) is not allowed"

            # Warn about private networks (but allow them)
            if network_obj.is_private:
                logger.info(f"ℹ️  Private network detected: '{value}'")

            # Normalize the network address
            # If user enters 10.10.10.1/24, we'll use 10.10.10.0/24
            normalized_network = str(network_obj)
            if normalized_network != value:
                logger.info(f"✅ Network address will be normalized: '{value}' -> '{normalized_network}'")
            else:
                logger.info(f"✅ Network address is already in correct format: '{value}'")

            return True, ""

        except ValueError as e:
            logger.error(f"❌ Invalid network format entered: '{value}' - Error: {str(e)}")
            return False, f"Invalid IPv4 network format. Use CIDR notation like '10.10.10.0/24'. Error: {str(e)}"

    return False, f"Unknown object type: {object_type}"

def invalidate_cached_token(fmc_url, username):
    """
    Invalidate a cached token when we detect it's no longer valid (e.g., 401 error).
    This forces a fresh token to be generated on next request.

    Args:
        fmc_url: FMC URL
        username: FMC username (used in cache key)
    """
    # FIX #4: Use same cache key structure as get_cached_token
    cache_key = f"{fmc_url}:{username}"

    with token_cache_lock:
        if cache_key in token_cache:
            del token_cache[cache_key]
            logger.warning(f"🔄 Invalidated cached token for {fmc_url}")
            return True
    return False

def get_cached_token(fmc_url, username, password, force_refresh=False):
    """
    FIX #3: Enhanced Token Cache with ravpn-style refresh logic
    Get a cached token or create a new one if expired.
    Tokens are encrypted and scoped per FMC credentials (not per user).

    Implementation matches ravpn/app.py token management:
    - Reuses valid tokens until 1 minute before expiry
    - Thread-safe with locks
    - Encrypted storage for security

    IMPORTANT: FMC has a session limit per username (typically 1-5 tokens).
    Creating multiple tokens for the same FMC username will invalidate old tokens.
    Therefore, we cache by FMC credentials, not by web user session.

    Args:
        fmc_url: FMC URL
        username: FMC username
        password: FMC password
        force_refresh: If True, bypass cache and get a fresh token
    """
    # Validate URL to prevent SSRF
    if not validate_fmc_url(fmc_url):
        logger.error("Invalid or unsafe FMC URL rejected")
        return None

    # FIX #4: Cache tokens by FMC credentials, not by user session
    # This prevents background jobs from invalidating web user tokens
    # FMC has a session limit - multiple tokens for same username will invalidate each other
    cache_key = f"{fmc_url}:{username}"

    with token_cache_lock:
        # Check if we have a valid cached token (unless force_refresh is True)
        # Like ravpn: Reuse token if it's valid and not expiring soon (1 min buffer)
        if not force_refresh and cache_key in token_cache:
            cached = token_cache[cache_key]
            # Tokens are valid for 30 minutes
            # Reuse until 1 minute before expiry (like ravpn's implementation)
            time_until_expiry = cached['expires'] - datetime.now()
            if time_until_expiry > timedelta(minutes=1):
                try:
                    # Decrypt the token
                    decrypted_token = cipher_suite.decrypt(cached['token']).decode('utf-8')
                    logger.info(f"🔄 Reusing cached token for {fmc_url} (expires in {time_until_expiry.total_seconds():.0f}s)")
                    return decrypted_token
                except Exception as e:
                    logger.error(f"Failed to decrypt cached token: {str(e)}")
                    # Clear invalid cache entry
                    del token_cache[cache_key]
            else:
                logger.info(f"⏰ Token expiring soon for {fmc_url} (expires in {time_until_expiry.total_seconds():.0f}s), getting new token")
                # Clear token that's about to expire
                del token_cache[cache_key]

        # Get a new token
        if force_refresh:
            logger.info(f"🔄 Force refreshing token for {fmc_url}")
        else:
            logger.info(f"🆕 Requesting new token for {fmc_url}")

        token = fmc_auth(fmc_url, username, password)
        if token:
            try:
                # Encrypt the token before caching
                encrypted_token = cipher_suite.encrypt(token.encode('utf-8'))

                # Cache the encrypted token for 30 minutes (matching FMC token lifetime)
                # We'll reuse it until 1 minute before expiry
                token_cache[cache_key] = {
                    'token': encrypted_token,
                    'expires': datetime.now() + timedelta(minutes=30)
                }
                logger.info(f"💾 Cached encrypted token for {fmc_url} (valid for 30 min)")
            except Exception as e:
                logger.error(f"Failed to encrypt token for caching: {str(e)}")

        return token

def validate_job_id(job_id):
    """
    FIX #5: SQL Injection Risk via Job ID
    Validate job ID format to prevent enumeration and injection attacks.
    Expected format: job_{counter}_{timestamp}
    """
    if not job_id or not isinstance(job_id, str):
        return False

    # Job ID pattern: job_{integer}_{10-digit-timestamp}
    job_id_pattern = r'^job_\d+_\d{10}$'
    if not re.match(job_id_pattern, job_id):
        logger.warning(f"Invalid job ID format rejected: {job_id}")
        return False

    # Additional length check to prevent extremely long IDs
    if len(job_id) > 50:
        logger.warning(f"Job ID too long: {job_id}")
        return False

    return True

def cleanup_old_jobs():
    """
    FIX #6: Memory Leak in Job Status
    Clean up jobs older than 24 hours to prevent memory leaks.
    Also cleans up old token cache entries.
    """
    with job_status_lock:
        cutoff = datetime.now() - timedelta(hours=24)
        jobs_to_remove = []

        for job_id, job_data in job_status.items():
            try:
                start_time_str = job_data.get('start_time')
                if start_time_str:
                    start_time = datetime.fromisoformat(start_time_str)
                    if start_time < cutoff:
                        jobs_to_remove.append(job_id)
            except (ValueError, TypeError):
                # If we can't parse the date, remove the malformed entry
                logger.warning(f"Removing job with invalid timestamp: {job_id}")
                jobs_to_remove.append(job_id)

        for job_id in jobs_to_remove:
            del job_status[job_id]

        if jobs_to_remove:
            logger.info(f"🧹 Cleaned up {len(jobs_to_remove)} old jobs")

    # Also clean up expired tokens from cache
    with token_cache_lock:
        current_time = datetime.now()
        tokens_to_remove = []

        for cache_key, cached_data in token_cache.items():
            if current_time >= cached_data['expires']:
                tokens_to_remove.append(cache_key)

        for cache_key in tokens_to_remove:
            del token_cache[cache_key]

        if tokens_to_remove:
            logger.info(f"🧹 Cleaned up {len(tokens_to_remove)} expired tokens")

    # FIX #8: Clean up old rate limit entries
    with rate_limit_lock:
        current_time = datetime.now()
        ips_to_remove = []

        for ip_address, rate_data in rate_limit_store.items():
            time_elapsed = (current_time - rate_data['window_start']).total_seconds()
            # Remove entries older than 1 hour
            if time_elapsed > 3600:
                ips_to_remove.append(ip_address)

        for ip_address in ips_to_remove:
            del rate_limit_store[ip_address]

        if ips_to_remove:
            logger.info(f"🧹 Cleaned up {len(ips_to_remove)} old rate limit entries")

# FIX #6: Schedule periodic cleanup to prevent memory leaks
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_jobs, trigger="interval", hours=1, id='cleanup_job')
scheduler.start()
logger.info("✅ Scheduled cleanup job to run every hour")

def invalidate_token_cache(fmc_url):
    """Invalidate cached token for an FMC URL (called on 401 errors)"""
    with token_cache_lock:
        # Try to find and remove tokens for this URL (both user-specific and system-wide)
        keys_to_remove = [key for key in token_cache.keys() if fmc_url in key]
        for key in keys_to_remove:
            del token_cache[key]
            logger.info(f"🗑️  Invalidated expired token cache for {fmc_url}")

def check_single_fmc_deployment(fmc):
    """Check deployment status for a single FMC - designed for parallel execution"""
    try:
        # Validate FMC URL before using it
        if not validate_fmc_url(fmc.get("url")):
            return {
                'name': fmc.get('name', 'Unknown'),
                'url': fmc.get('url', ''),
                'connected': False,
                'pending_count': 0,
                'pending_devices': [],
                'total_devices': 0,
                'config_changes': [],
                'pending_deployments': [],
                'error': 'Invalid or unsafe URL'
            }

        token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
        if token:
            # Get pending deployment info
            pending_info = check_pending_deployments(fmc["url"], token)

            # If we get a 401 (token expired), invalidate cache and retry once
            if not pending_info.get('success') and 'error' in pending_info and '401' in str(pending_info.get('error')):
                logger.warning(f"Token expired for {fmc['url']}, invalidating cache and retrying")
                invalidate_token_cache(fmc["url"])
                token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
                if token:
                    pending_info = check_pending_deployments(fmc["url"], token)

            config_changes = get_config_changes(fmc["url"], token)

            # Get pending changes for each device
            pending_deployments = []
            for device in pending_info.get('pending_devices', []):
                if device.get('device_id'):
                    device_changes = get_pending_changes(fmc["url"], token, device['device_id'])
                    if device_changes.get('success'):
                        pending_deployments.append({
                            'deviceName': device.get('name'),
                            'deviceId': device.get('device_id'),
                            'changes': device_changes.get('changes', []),
                            'changeCount': len(device_changes.get('changes', []))
                        })

            return {
                'name': fmc['name'],
                'url': fmc['url'],
                'connected': True,
                'pending_count': pending_info.get('pending_count', 0),
                'pending_devices': pending_info.get('pending_devices', []),
                'total_devices': pending_info.get('total_devices', 0),
                'config_changes': config_changes if isinstance(config_changes, list) else [],
                'pending_deployments': pending_deployments,
                'error': None
            }
        else:
            return {
                'name': fmc['name'],
                'url': fmc['url'],
                'connected': False,
                'pending_count': 0,
                'pending_devices': [],
                'total_devices': 0,
                'config_changes': [],
                'pending_deployments': [],
                'error': 'Authentication failed'
            }
    except Exception as e:
        return {
            'name': fmc.get('name', 'Unknown'),
            'url': fmc.get('url', ''),
            'connected': False,
            'pending_count': 0,
            'pending_devices': [],
            'total_devices': 0,
            'config_changes': [],
            'pending_deployments': [],
            'error': str(e)
        }

def check_all_deployments():
    """Check deployment status across all configured FMC systems with caching and parallel execution"""
    # Check cache first
    with deployment_cache['lock']:
        if deployment_cache['data'] is not None and datetime.now() < deployment_cache['expires']:
            logger.info("🔄 Returning cached deployment status")
            return deployment_cache['data']

    # Cache miss - fetch fresh data
    logger.info("⏰ Cache expired or empty, fetching fresh deployment status")
    fmc_list = load_fmc_config()
    deployment_summary = {
        'total_fmcs': len(fmc_list),
        'fmc_status': [],
        'total_pending': 0,
        'has_pending': False
    }

    # Use ThreadPoolExecutor for parallel FMC checks
    with ThreadPoolExecutor(max_workers=min(len(fmc_list), 4)) as executor:
        # Submit all FMC checks in parallel
        future_to_fmc = {executor.submit(check_single_fmc_deployment, fmc): fmc for fmc in fmc_list}

        # Collect results as they complete
        for future in as_completed(future_to_fmc):
            try:
                fmc_status = future.result()
                deployment_summary['fmc_status'].append(fmc_status)

                if fmc_status.get('pending_count', 0) > 0:
                    deployment_summary['has_pending'] = True
                    deployment_summary['total_pending'] += fmc_status.get('pending_count', 0)
            except Exception as e:
                fmc = future_to_fmc[future]
                logger.error(f"Error processing FMC {fmc.get('name', 'Unknown')}: {e}")
                deployment_summary['fmc_status'].append({
                    'name': fmc.get('name', 'Unknown'),
                    'url': fmc.get('url', ''),
                    'connected': False,
                    'pending_count': 0,
                    'pending_devices': [],
                    'total_devices': 0,
                    'config_changes': [],
                    'pending_deployments': [],
                    'error': str(e)
                })

    # Update cache
    with deployment_cache['lock']:
        deployment_cache['data'] = deployment_summary
        deployment_cache['expires'] = datetime.now() + timedelta(seconds=60)
        logger.info("💾 Updated deployment cache (60 second TTL)")

    return deployment_summary


def process_single_fmc_object(fmc, object_type, object_value, object_name, description, group_name):
    """Process object creation on a single FMC - designed for parallel execution"""
    result = {
        'fmc_name': fmc['name'],
        'fmc_url': fmc['url'],
        'success': False,
        'steps': [],
        'message': '',
        'start_time': datetime.now().isoformat()
    }

    try:
        logger.info(f"Processing FMC: {fmc['name']}")

        # Step 1: Authentication
        result['steps'].append({'step': 'Authentication', 'status': 'running', 'message': 'Authenticating with FMC...'})

        # FIX #4: Use shared token cache (tokens now cached by FMC credentials, not user session)
        # This prevents token invalidation issues when background jobs and web requests run concurrently
        token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
        if not token:
            result['steps'][-1]['status'] = 'failed'
            result['steps'][-1]['message'] = 'Authentication failed'
            result['message'] = 'Authentication failed'
            return result

        result['steps'][-1]['status'] = 'completed'
        result['steps'][-1]['message'] = 'Authentication successful'

        # Step 2: Create Object (FQDN, Host, or Network)
        if object_type == "fqdn":
            object_display = "FQDN"
        elif object_type == "host":
            object_display = "Host"
        else:
            object_display = "Network"
        
        result['steps'].append({'step': f'Create {object_display}', 'status': 'running', 'message': f'Creating {object_display} {object_name}...'})
        logger.info(f"Creating {object_display} {object_name} on {fmc['name']} - URL: {fmc['url']}, Value: {object_value}")

        # Use cached token (shared across all requests)
        logger.info(f"Using authentication token for {object_display} creation...")
        if not token:
            result['steps'][-1]['status'] = 'failed'
            result['steps'][-1]['message'] = f'Authentication failed before {object_display} creation'
            result['message'] = 'Authentication failed'
            logger.error(f"Failed to get fresh token for {fmc['name']}")
            return result

        # Create the appropriate object type
        if object_type == "fqdn":
            object_result = create_fqdn(fmc["url"], token, object_name, object_value, description)
            if not object_result or not object_result.get("success"):
                # Try alternative creation method for FQDN
                logger.info(f"Primary FQDN creation failed for {fmc['name']}, trying alternative methods...")
                object_result = create_fqdn_alternative(fmc["url"], token, object_name, object_value, description)
        elif object_type == "host":
            object_result = create_host(fmc["url"], token, object_name, object_value, description)
        elif object_type == "network":
            object_result = create_network(fmc["url"], token, object_name, object_value, description)
        else:
            error_msg = f"Unknown object type: {object_type}"
            result['steps'][-1]['status'] = 'failed'
            result['steps'][-1]['message'] = error_msg
            result['message'] = error_msg
            logger.error(error_msg)
            return result

        if not object_result or not object_result.get("success"):
            error_msg = object_result.get("message", f"{object_display} creation failed") if object_result else f"{object_display} creation failed"
            result['steps'][-1]['status'] = 'failed'
            result['steps'][-1]['message'] = error_msg
            result['message'] = error_msg
            logger.error(f"{object_display} creation failed for {fmc['name']}: {error_msg}")
            return result

        # Extract object ID from successful result
        result['object_id'] = object_result.get("data", {}).get("id")
        if not result['object_id']:
            error_msg = f"{object_display} created but no ID returned"
            result['steps'][-1]['status'] = 'failed'
            result['steps'][-1]['message'] = error_msg
            result['message'] = error_msg
            logger.error(f"{object_display} creation failed for {fmc['name']}: {error_msg}")
            return result

        success_msg = object_result.get("message", f'{object_display} {object_name} created successfully')
        result['steps'][-1]['status'] = 'completed'
        result['steps'][-1]['message'] = success_msg
        logger.info(f"{object_display} created successfully for {fmc['name']}: {result['object_id']}")

        # Step 3: Add to Network Group (only if group_name provided)
        if group_name:
            logger.info(f"Attempting to add {object_display} {object_name} to group '{group_name}' on {fmc['name']}")
            result['steps'].append({'step': 'Add to Group', 'status': 'running', 'message': f'Adding to network group {group_name}...'})

            # Reuse the cached token from step 1 - it's still valid
            logger.info(f"Using authentication token for group operations...")

            group_id = get_network_group_id(fmc["url"], token, group_name)
            if not group_id:
                error_msg = f'Network group "{group_name}" not found on {fmc["name"]}'
                logger.error(error_msg)
                result['message'] = error_msg
                result['steps'][-1]['status'] = 'failed'
                result['steps'][-1]['message'] = error_msg
                # Don't return - mark as partial success if FQDN was created
                result['success'] = True  # FQDN was created successfully
                result['partial'] = True
            else:
                logger.info(f"Found group '{group_name}' with ID {group_id} on {fmc['name']}")
                group_result = update_network_group(fmc["url"], token, group_id, result['object_id'], group_name)
                if not group_result or not group_result.get("success"):
                    error_msg = group_result.get("message", "Failed to add to network group")
                    logger.error(f"Failed to add to group on {fmc['name']}: {error_msg}")
                    result['message'] = error_msg
                    result['steps'][-1]['status'] = 'failed'
                    result['steps'][-1]['message'] = error_msg
                    # Mark as partial success - FQDN was created
                    result['success'] = True
                    result['partial'] = True
                else:
                    logger.info(f"Successfully added {object_display} to group '{group_name}' on {fmc['name']}")
                    result['steps'][-1]['status'] = 'completed'
                    result['steps'][-1]['message'] = f'Added to network group {group_name} successfully'
                    result['success'] = True
        else:
            logger.info(f"No group specified for {object_display} {object_name} on {fmc['name']}")
            result['steps'].append({'step': 'Group Assignment', 'status': 'skipped', 'message': 'No group specified - object created only'})
            result['success'] = True

        # Step 4: Deploy (optional)
        result['steps'].append({'step': 'Deploy', 'status': 'completed', 'message': 'Deployment available in Deployments page'})

        result['success'] = True
        result['message'] = f'{object_display} processed successfully'
        result['end_time'] = datetime.now().isoformat()

    except Exception as e:
        logger.error(f"Error processing FMC {fmc['name']}: {e}")
        result['message'] = f'Error: {str(e)}'
        result['steps'].append({'step': 'Error', 'status': 'failed', 'message': str(e)})

    return result

def process_object_job(job_id, object_type, object_value, object_name, description=None, group_name=None):
    """Background job to process FQDN or Host object across all FMCs in parallel"""
    global job_status

    try:
        logger.info(f"⚙️  Starting background job {job_id}")
        logger.info(f"   Type: {object_type.upper()}")
        logger.info(f"   Name: {object_name}")
        logger.info(f"   Value: {object_value}")

        fmc_list = load_fmc_config()
        total_fmcs = len(fmc_list)

        with job_status_lock:
            job_status[job_id] = {
                'status': 'running',
                'progress': 0,
                'results': [],
                'start_time': datetime.now().isoformat(),
                'object_type': object_type,
                'object_value': object_value,
                'object_name': object_name,
                'description': description,
                'group_name': group_name
            }

        # Use ThreadPoolExecutor for parallel FMC processing
        with ThreadPoolExecutor(max_workers=min(len(fmc_list), 4)) as executor:
            # Submit all FMC jobs in parallel
            future_to_fmc = {
                executor.submit(process_single_fmc_object, fmc, object_type, object_value, object_name, description, group_name): fmc
                for fmc in fmc_list
            }

            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_fmc):
                try:
                    # Get the result from the completed future
                    result = future.result()
                    completed += 1

                    # Add result to job status with thread safety
                    with job_status_lock:
                        job_status[job_id]['results'].append(result)
                        # Update progress
                        progress = int((completed / total_fmcs) * 100)
                        job_status[job_id]['progress'] = progress

                    logger.info(f"✅ Completed processing {result['fmc_name']} ({completed}/{total_fmcs})")

                except Exception as e:
                    fmc = future_to_fmc[future]
                    logger.error(f"❌ Error processing FMC {fmc.get('name', 'Unknown')}: {e}")
                    error_result = {
                        'fmc_name': fmc.get('name', 'Unknown'),
                        'fmc_url': fmc.get('url', ''),
                        'success': False,
                        'steps': [{'step': 'Error', 'status': 'failed', 'message': str(e)}],
                        'message': f'Error: {str(e)}',
                        'start_time': datetime.now().isoformat(),
                        'end_time': datetime.now().isoformat()
                    }
                    with job_status_lock:
                        job_status[job_id]['results'].append(error_result)
        
        # FIX #7: Thread Safety - Atomic update of final job status
        deployment_status = check_all_deployments()

        with job_status_lock:
            job_status[job_id]['deployment_status'] = deployment_status
            job_status[job_id]['status'] = 'completed'
            job_status[job_id]['end_time'] = datetime.now().isoformat()

    except Exception as e:
        # FIX #7: Thread Safety - Atomic update of error status
        with job_status_lock:
            job_status[job_id]['status'] = 'error'
            job_status[job_id]['error'] = str(e)
            job_status[job_id]['end_time'] = datetime.now().isoformat()
        logger.error(f"Job {job_id} failed: {e}")

# FIX #12: Error Handlers - Prevent Information Disclosure
def get_safe_user_info():
    """
    Safely get user info, return None if not available.
    Works with or without OIDC enabled.
    """
    try:
        # Check if we're in a request context
        from flask import has_request_context
        if not has_request_context():
            return None

        # If OIDC is disabled, return a default user object
        if not oidc_auth.enabled:
            return {
                'name': 'Local User',
                'email': 'admin@local',
                'sub': 'local-user'
            }

        # If OIDC is enabled, get user from session
        return oidc_auth.get_user_info()
    except Exception as e:
        logger.debug(f"Could not get user info: {e}")
        return None

@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    logger.warning(f"Bad request: {error}")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Bad Request', 'message': 'The request could not be understood'}), 400
    return render_template('error.html',
                         error_code=400,
                         error_title='Bad Request',
                         error_message='The request could not be understood.',
                         user=get_safe_user_info()), 400

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors"""
    logger.warning(f"Forbidden access attempt: {error}")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Forbidden', 'message': 'You do not have permission to access this resource'}), 403
    return render_template('error.html',
                         error_code=403,
                         error_title='Access Denied',
                         error_message='You do not have permission to access this resource.',
                         user=get_safe_user_info()), 403

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    logger.info(f"404 Not Found: {request.url}")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Not Found', 'message': 'The requested resource was not found'}), 404
    return render_template('error.html',
                         error_code=404,
                         error_title='Page Not Found',
                         error_message='The requested page could not be found.',
                         user=get_safe_user_info()), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle 429 Rate Limit Exceeded errors"""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Rate Limit Exceeded', 'message': 'Too many requests. Please try again later.'}), 429
    return render_template('error.html',
                         error_code=429,
                         error_title='Too Many Requests',
                         error_message='You have made too many requests. Please wait and try again.',
                         user=get_safe_user_info()), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server errors - DO NOT expose stack traces"""
    logger.error(f"Internal server error: {error}", exc_info=True)
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
    return render_template('error.html',
                         error_code=500,
                         error_title='Internal Server Error',
                         error_message='An unexpected error occurred. Please try again later.',
                         user=get_safe_user_info()), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all uncaught exceptions - DO NOT expose details in production"""
    logger.error(f"Unhandled exception: {error}", exc_info=True)

    # Check if it's a known HTTP exception
    if hasattr(error, 'code'):
        return error

    # Return generic error in production
    if is_production:
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
        return render_template('error.html',
                             error_code=500,
                             error_title='Internal Server Error',
                             error_message='An unexpected error occurred. Please try again later.',
                             user=get_safe_user_info()), 500
    else:
        # Show details in development
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Internal Server Error', 'message': str(error)}), 500
        return render_template('error.html',
                             error_code=500,
                             error_title='Internal Server Error (Dev)',
                             error_message=str(error),
                             user=get_safe_user_info()), 500

@app.route('/')
@oidc_auth.require_auth
def index():
    """Main page with FQDN input form - deployment status loaded via AJAX for fast page load"""
    # Clean up old jobs periodically
    cleanup_old_jobs()
    # Return page immediately without blocking on deployment check
    return render_template('index.html', user=get_safe_user_info())

@app.route('/submit', methods=['POST'])
@oidc_auth.require_auth
@rate_limit(max_requests=RATE_LIMIT_API_MAX, window=RATE_LIMIT_WINDOW)
def submit_fqdn():
    """Submit FQDN or Host object for processing"""
    global job_counter
    
    # Check if it's an AJAX request
    is_ajax = request.headers.get('Content-Type') == 'application/json'
    
    if is_ajax:
        data = request.get_json()
        object_type = data.get('object_type', 'fqdn').strip()
        object_value = data.get('object_value', '').strip()
        object_name = data.get('object_name', '').strip()
        object_description = data.get('object_description', '').strip()
        group_name = data.get('group_name', '').strip()
    else:
        object_type = request.form.get('object_type', 'fqdn').strip()
        object_value = request.form.get('object_value', '').strip()
        object_name = request.form.get('object_name', '').strip()
        object_description = request.form.get('object_description', '').strip()
        group_name = request.form.get('group_name', '').strip()
    
    if not object_value:
        error_msg = f'Please enter a valid {"FQDN" if object_type == "fqdn" else "IP address"}'
        if is_ajax:
            return jsonify({'success': False, 'message': error_msg}), 400
        else:
            flash(error_msg, 'error')
            return redirect(url_for('index'))

    # Validate object type
    if object_type not in ['fqdn', 'host', 'network']:
        if is_ajax:
            return jsonify({'success': False, 'message': 'Invalid object type'}), 400
        else:
            flash('Invalid object type', 'error')
            return redirect(url_for('index'))

    # Validate object value based on type
    is_valid, error_msg = validate_object_value(object_type, object_value)
    if not is_valid:
        if is_ajax:
            return jsonify({'success': False, 'message': error_msg}), 400
        else:
            flash(error_msg, 'error')
            return redirect(url_for('index'))

    # Normalize network addresses after validation
    # This ensures we use the proper network address (e.g., 10.10.10.0/24 instead of 10.10.10.1/24)
    original_value = object_value  # Store for logging
    if object_type == 'network':
        try:
            network_obj = ipaddress.IPv4Network(object_value, strict=False)
            normalized_value = str(network_obj)
            if normalized_value != object_value:
                logger.info(f"🔄 Normalizing network address before job creation:")
                logger.info(f"   User entered: '{object_value}'")
                logger.info(f"   Will create as: '{normalized_value}'")
                object_value = normalized_value
            else:
                logger.info(f"✅ Network address is correctly formatted: '{object_value}'")
        except Exception as e:
            logger.warning(f"⚠️  Could not normalize network value '{object_value}': {e}")

    # Generate job ID and object name
    job_counter += 1
    job_id = f"job_{job_counter}_{int(time.time())}"

    # Create object name based on type if not provided
    if not object_name:
        if object_type == 'fqdn':
            object_name = object_value.replace(".", "_")
        elif object_type == 'host':
            object_name = f"Host_{object_value.replace('.', '_')}"
        else:  # network
            object_name = f"Network_{object_value.replace('.', '_').replace('/', '_')}"

    # Validate object name
    is_valid, error_msg = validate_object_name(object_name)
    if not is_valid:
        if is_ajax:
            return jsonify({'success': False, 'message': error_msg}), 400
        else:
            flash(error_msg, 'error')
            return redirect(url_for('index'))

    # Sanitize description
    if object_description:
        object_description = sanitize_description(object_description)

    logger.info(f"🚀 Creating job {job_id} for {object_type.upper()}")
    logger.info(f"   Object Name: {object_name}")
    logger.info(f"   Object Value: {object_value}")
    if object_type == 'network' and original_value != object_value:
        logger.info(f"   Original Input: {original_value}")
    logger.info(f"   Group: {group_name or 'None'}")
    logger.info(f"   Description: {object_description[:50] if object_description else 'None'}")

    # Start background thread
    thread = threading.Thread(target=process_object_job, args=(job_id, object_type, object_value, object_name, object_description, group_name))
    thread.daemon = True
    thread.start()
    
    if is_ajax:
        return jsonify({
            'success': True, 
            'message': f'{object_type.upper()} "{object_value}" processing started successfully!',
            'job_id': job_id,
            'object_type': object_type,
            'object_name': object_name,
            'object_value': object_value,
            'group_name': group_name,
            'status_url': url_for('job_status_page', job_id=job_id)
        })
    else:
        return redirect(url_for('job_status_page', job_id=job_id))

@app.route('/status/<job_id>')
@oidc_auth.require_auth
def job_status_page(job_id):
    """
    FIX #5: Job status page with ID validation
    """
    # Validate job ID format
    if not validate_job_id(job_id):
        logger.warning(f"Invalid job ID access attempt: {job_id}")
        flash('Invalid job ID format', 'error')
        return redirect(url_for('index'))

    if job_id not in job_status:
        flash('Job not found', 'error')
        return redirect(url_for('index'))

    return render_template('status.html', job_id=job_id, job_data=job_status[job_id], user=get_safe_user_info())

@app.route('/api/status/<job_id>')
@oidc_auth.require_auth
def job_status_api(job_id):
    """
    FIX #5: API endpoint for job status with ID validation
    """
    # Validate job ID format
    if not validate_job_id(job_id):
        logger.warning(f"Invalid job ID API access attempt: {job_id}")
        return jsonify({'error': 'Invalid job ID format'}), 400

    if job_id not in job_status:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify(job_status[job_id])

@app.route('/api/deployment-status')
@oidc_auth.require_auth
def deployment_status_api():
    """API endpoint for deployment status with optional cache bypass"""
    # Check if force refresh is requested
    force_refresh = request.args.get('force', 'false').lower() == 'true'

    if force_refresh:
        # Invalidate cache to force fresh data
        with deployment_cache['lock']:
            deployment_cache['data'] = None
            deployment_cache['expires'] = datetime.min
        logger.info("🔄 Cache invalidated - forcing fresh deployment check")

    deployment_status = check_all_deployments()
    return jsonify(deployment_status)


@app.route('/deployments')
@oidc_auth.require_auth
def deployments_page():
    """Deployment management page - uses cached data for fast load, refresh button forces fresh data"""
    # Use cached deployment status for initial load (will be fast if within 60s cache window)
    # The refresh button will force a page reload which respects cache invalidation
    deployment_status = check_all_deployments()
    return render_template('deployments.html', user=get_safe_user_info(), deployment_status=deployment_status)


@app.route('/api/deploy', methods=['POST'])
@oidc_auth.require_auth
@rate_limit(max_requests=RATE_LIMIT_API_MAX, window=RATE_LIMIT_WINDOW)
def deploy_to_devices():
    """Deploy changes to selected devices"""
    data = request.get_json()
    fmc_names = data.get('fmc_names', [])
    
    if not fmc_names:
        return jsonify({'error': 'No FMC systems specified'}), 400
    
    fmc_list = load_fmc_config()
    deployment_results = []
    
    for fmc in fmc_list:
        if fmc['name'] in fmc_names:
            try:
                # Validate FMC URL before deployment
                if not validate_fmc_url(fmc.get("url")):
                    deployment_results.append({
                        'fmc_name': fmc.get('name', 'Unknown'),
                        'success': False,
                        'message': 'Invalid or unsafe URL'
                    })
                    continue
                    
                token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
                if token:
                    success = deploy_changes(fmc["url"], token)
                    deployment_results.append({
                        'fmc_name': fmc['name'],
                        'success': success,
                        'message': 'Deployment initiated' if success else 'Deployment failed'
                    })
                else:
                    deployment_results.append({
                        'fmc_name': fmc['name'],
                        'success': False,
                        'message': 'Authentication failed'
                    })
            except Exception as e:
                deployment_results.append({
                    'fmc_name': fmc['name'],
                    'success': False,
                    'message': f'Error: {str(e)}'
                })
    
    return jsonify({'results': deployment_results})


@app.route('/objects')
@oidc_auth.require_auth
def objects_page():
    """Object management page"""
    return render_template('objects.html', user=get_safe_user_info())


@app.route('/api/objects/fqdns')
@oidc_auth.require_auth
def get_fqdns():
    """Get all FQDN objects from all FMCs"""
    fmc_list = load_fmc_config()
    all_fqdns = {}
    
    for fmc in fmc_list:
        try:
            # Validate FMC URL before making requests
            if not validate_fmc_url(fmc.get("url")):
                all_fqdns[fmc.get("name", "Unknown")] = []
                continue
                
            token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
            if token:
                result = get_all_fqdns(fmc["url"], token)

                # Check if we got a 401 error and retry with fresh token
                if not result.get("success") and "401" in result.get("message", ""):
                    logger.warning(f"Got 401 error for {fmc['name']}, retrying with fresh token...")
                    invalidate_cached_token(fmc["url"], fmc["username"])
                    token = get_cached_token(fmc["url"], fmc["username"], fmc["password"], force_refresh=True)
                    if token:
                        result = get_all_fqdns(fmc["url"], token)
                        logger.info(f"✅ Retry successful for {fmc['name']} after token refresh")

                if result["success"]:
                    all_fqdns[fmc["name"]] = result["data"]
                else:
                    all_fqdns[fmc["name"]] = []
            else:
                all_fqdns[fmc.get("name", "Unknown")] = []
        except Exception as e:
            logger.error(f"Error fetching FQDNs from {fmc.get('name', 'Unknown')}: {str(e)}")
            all_fqdns[fmc.get("name", "Unknown")] = []
    
    return jsonify(all_fqdns)


@app.route('/api/objects/groups')
@oidc_auth.require_auth
def get_groups():
    """Get all network groups from all FMCs"""
    fmc_list = load_fmc_config()
    all_groups = {}
    
    logger.info(f"Loading groups from {len(fmc_list)} configured FMC systems")
    
    for fmc in fmc_list:
        fmc_name = fmc.get("name", "Unknown")
        fmc_url = fmc.get("url", "")
        logger.info(f"Attempting to load groups from {fmc_name} ({fmc_url})")
        
        try:
            # Validate FMC URL before making requests
            if not validate_fmc_url(fmc_url):
                logger.error(f"❌ Invalid or unsafe URL for {fmc_name}: {fmc_url}")
                all_groups[fmc_name] = []
                continue
                
            token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
            if token:
                result = get_all_network_groups(fmc["url"], token)

                # Check if we got a 401 error and retry with fresh token
                if not result.get("success") and "401" in result.get("message", ""):
                    logger.warning(f"Got 401 error for {fmc_name}, retrying with fresh token...")
                    invalidate_cached_token(fmc["url"], fmc["username"])
                    token = get_cached_token(fmc["url"], fmc["username"], fmc["password"], force_refresh=True)
                    if token:
                        result = get_all_network_groups(fmc["url"], token)
                        logger.info(f"✅ Retry successful for {fmc_name} after token refresh")

                if result["success"]:
                    group_count = len(result["data"])
                    logger.info(f"✅ Retrieved {group_count} groups from {fmc_name}")
                    all_groups[fmc_name] = result["data"]
                else:
                    logger.error(f"❌ Failed to get groups from {fmc_name}: {result.get('message', 'Unknown error')}")
                    all_groups[fmc_name] = []
            else:
                logger.error(f"❌ Authentication failed for {fmc_name}")
                all_groups[fmc_name] = []
        except Exception as e:
            logger.error(f"❌ Exception while loading groups from {fmc_name}: {str(e)}")
            all_groups[fmc_name] = []
    
    total_groups = sum(len(groups) for groups in all_groups.values())
    logger.info(f"✅ Total groups loaded: {total_groups} across {len(all_groups)} FMC systems")
    
    return jsonify(all_groups)


@app.route('/api/objects/groups/<group_id>/objects', methods=['POST'])
@oidc_auth.require_auth
@rate_limit(max_requests=RATE_LIMIT_API_MAX, window=RATE_LIMIT_WINDOW)
def add_to_group(group_id):
    """Add object to network group"""
    data = request.get_json()
    fmc_name = data.get('fmc_name')
    object_id = data.get('object_id')
    object_type = data.get('object_type', 'FQDN')
    
    if not all([fmc_name, object_id]):
        return jsonify({"success": False, "message": "Missing required parameters"}), 400
    
    # Validate UUIDs to prevent injection attacks
    if not validate_uuid(group_id):
        return jsonify({"success": False, "message": "Invalid group ID format"}), 400
    if not validate_uuid(object_id):
        return jsonify({"success": False, "message": "Invalid object ID format"}), 400
    
    # SSRF Protection: Get safe URL from configuration allowlist
    safe_fmc_url = get_safe_fmc_url(fmc_name)
    if not safe_fmc_url:
        return jsonify({"success": False, "message": "FMC not found or URL invalid"}), 404
    
    # Find the FMC credentials
    fmc_list = load_fmc_config()
    target_fmc = next((fmc for fmc in fmc_list if fmc["name"] == fmc_name), None)
    
    if not target_fmc:
        return jsonify({"success": False, "message": "FMC not found"}), 404
    
    try:
        token = get_cached_token(safe_fmc_url, target_fmc["username"], target_fmc["password"])
        if not token:
            return jsonify({"success": False, "message": "Authentication failed"}), 401
        
        # Use the safe URL from allowlist for the API call
        result = add_object_to_group(safe_fmc_url, token, group_id, object_id, object_type)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/objects/groups/<group_id>/objects/<object_id>', methods=['DELETE'])
@oidc_auth.require_auth
@rate_limit(max_requests=RATE_LIMIT_API_MAX, window=RATE_LIMIT_WINDOW)
def remove_from_group(group_id, object_id):
    """Remove object from network group"""
    fmc_name = request.args.get('fmc_name')
    object_type = request.args.get('object_type', 'FQDN')
    
    if not fmc_name:
        return jsonify({"success": False, "message": "FMC name required"}), 400
    
    # Validate UUIDs to prevent injection attacks
    if not validate_uuid(group_id):
        return jsonify({"success": False, "message": "Invalid group ID format"}), 400
    if not validate_uuid(object_id):
        return jsonify({"success": False, "message": "Invalid object ID format"}), 400
    
    # SSRF Protection: Get safe URL from configuration allowlist
    safe_fmc_url = get_safe_fmc_url(fmc_name)
    if not safe_fmc_url:
        return jsonify({"success": False, "message": "FMC not found or URL invalid"}), 404
    
    # Find the FMC credentials
    fmc_list = load_fmc_config()
    target_fmc = next((fmc for fmc in fmc_list if fmc["name"] == fmc_name), None)
    
    if not target_fmc:
        return jsonify({"success": False, "message": "FMC not found"}), 404
    
    try:
        token = get_cached_token(safe_fmc_url, target_fmc["username"], target_fmc["password"])
        if not token:
            return jsonify({"success": False, "message": "Authentication failed"}), 401
        
        # Use the safe URL from allowlist for the API call
        result = remove_object_from_group(safe_fmc_url, token, group_id, object_id, object_type)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/objects/fqdns/<fqdn_id>', methods=['DELETE'])
@oidc_auth.require_auth
@rate_limit(max_requests=RATE_LIMIT_API_MAX, window=RATE_LIMIT_WINDOW)
def delete_fqdn(fqdn_id):
    """Delete FQDN object completely"""
    fmc_name = request.args.get('fmc_name')
    
    if not fmc_name:
        return jsonify({"success": False, "message": "FMC name required"}), 400
    
    # Validate UUID to prevent injection attacks
    if not validate_uuid(fqdn_id):
        return jsonify({"success": False, "message": "Invalid FQDN ID format"}), 400
    
    # SSRF Protection: Get safe URL from configuration allowlist
    safe_fmc_url = get_safe_fmc_url(fmc_name)
    if not safe_fmc_url:
        return jsonify({"success": False, "message": "FMC not found or URL invalid"}), 404
    
    # Find the FMC credentials
    fmc_list = load_fmc_config()
    target_fmc = next((fmc for fmc in fmc_list if fmc["name"] == fmc_name), None)
    
    if not target_fmc:
        return jsonify({"success": False, "message": "FMC not found"}), 404
    
    try:
        token = get_cached_token(safe_fmc_url, target_fmc["username"], target_fmc["password"])
        if not token:
            return jsonify({"success": False, "message": "Authentication failed"}), 401
        
        # Use the safe URL from allowlist for the API call
        result = delete_fqdn_object(safe_fmc_url, token, fqdn_id)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/objects/search')
@oidc_auth.require_auth
def search_objects_api():
    """Search for objects across all FMC systems"""
    search_term = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'object')  # 'object' or 'global'
    object_types = request.args.getlist('objectTypes')  # List of object types to filter

    if not search_term:
        return jsonify({"success": False, "message": "Search term is required"}), 400

    if len(search_term) < 2:
        return jsonify({"success": False, "message": "Search term must be at least 2 characters"}), 400

    # Sanitize search term to prevent injection attacks
    # Remove control characters and limit length
    search_term = re.sub(r'[\x00-\x1F\x7F]', '', search_term)
    if len(search_term) > 100:
        search_term = search_term[:100]
    
    fmc_list = load_fmc_config()
    search_results = {}
    
    for fmc in fmc_list:
        try:
            # Validate FMC URL before making search requests
            if not validate_fmc_url(fmc.get("url")):
                search_results[fmc.get("name", "Unknown")] = {
                    "success": False,
                    "message": "Invalid or unsafe FMC URL",
                    "items": [],
                    "total": 0
                }
                continue
                
            token = get_cached_token(fmc["url"], fmc["username"], fmc["password"])
            if not token:
                search_results[fmc["name"]] = {
                    "success": False,
                    "message": "Authentication failed",
                    "items": [],
                    "total": 0
                }
                continue

            # Choose search method based on type
            if search_type == 'global':
                result = search_global(fmc["url"], token, search_term)
            else:
                result = search_objects(fmc["url"], token, search_term, object_types if object_types else None)

            # Check if we got a 401 error (invalid token) and retry with fresh token
            if not result.get("success") and "401" in result.get("message", ""):
                logger.warning(f"Got 401 error for {fmc['name']}, retrying with fresh token...")
                invalidate_cached_token(fmc["url"], fmc["username"])
                token = get_cached_token(fmc["url"], fmc["username"], fmc["password"], force_refresh=True)

                if token:
                    # Retry the search with fresh token
                    if search_type == 'global':
                        result = search_global(fmc["url"], token, search_term)
                    else:
                        result = search_objects(fmc["url"], token, search_term, object_types if object_types else None)
                    logger.info(f"✅ Retry successful for {fmc['name']} after token refresh")
                else:
                    result = {
                        "success": False,
                        "message": "Authentication failed after retry",
                        "items": [],
                        "total": 0
                    }

            search_results[fmc["name"]] = result
            
        except Exception as e:
            search_results[fmc["name"]] = {
                "success": False,
                "message": str(e),
                "items": [],
                "total": 0
            }
    
    # Calculate totals
    total_items = sum(result.get("total", 0) for result in search_results.values())
    successful_fmcs = sum(1 for result in search_results.values() if result.get("success", False))
    
    return jsonify({
        "success": True,
        "search_term": search_term,
        "search_type": search_type,
        "total_items": total_items,
        "successful_fmcs": successful_fmcs,
        "total_fmcs": len(fmc_list),
        "results": search_results
    })


@app.route('/health')
def health_check():
    """Health check endpoint for Docker"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
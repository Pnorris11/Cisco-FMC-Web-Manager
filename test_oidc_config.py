#!/usr/bin/env python3
"""
OIDC Configuration Test Script

This script verifies your OIDC configuration is set up correctly
before running the application.
"""

import os
import sys
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_status(check, status, message=""):
    """Print a check status"""
    icon = "✅" if status else "❌"
    status_text = "PASS" if status else "FAIL"
    print(f"{icon} [{status_text}] {check}")
    if message:
        print(f"         → {message}")

def check_oidc_enabled():
    """Check if OIDC is enabled"""
    enabled = os.getenv('OIDC_ENABLED', 'false').lower() == 'true'
    print_status("OIDC Enabled", enabled,
                f"OIDC_ENABLED={os.getenv('OIDC_ENABLED', 'not set')}")
    return enabled

def check_required_vars():
    """Check required environment variables"""
    print_header("Required Configuration")

    required_vars = [
        ('OIDC_CLIENT_ID', 'OAuth Client ID'),
        ('OIDC_CLIENT_SECRET', 'OAuth Client Secret'),
        ('OIDC_DISCOVERY_URL', 'OIDC Discovery URL'),
        ('FLASK_SECRET_KEY', 'Flask Secret Key'),
        ('APP_BASE_URL', 'Application Base URL')
    ]

    all_present = True
    for var, description in required_vars:
        value = os.getenv(var)
        is_set = value is not None and value.strip() != ''

        if not is_set:
            print_status(description, False, f"{var} is not set")
            all_present = False
        else:
            # Show partial value for secrets
            if 'SECRET' in var or 'PASSWORD' in var:
                display_value = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
            else:
                display_value = value
            print_status(description, True, f"{var}={display_value}")

    return all_present

def check_discovery_url():
    """Check if OIDC discovery URL is accessible"""
    print_header("Discovery URL Validation")

    discovery_url = os.getenv('OIDC_DISCOVERY_URL')
    if not discovery_url:
        print_status("Discovery URL accessible", False, "URL not configured")
        return False

    try:
        # Parse URL
        parsed = urlparse(discovery_url)
        print_status("Valid URL format", True, f"{parsed.scheme}://{parsed.netloc}")

        # Check HTTPS
        is_https = parsed.scheme == 'https'
        print_status("Uses HTTPS", is_https,
                    "HTTPS is required for production" if not is_https else "")

        # Try to fetch discovery document
        print("\n  Fetching discovery document...")
        response = requests.get(discovery_url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            print_status("Discovery document accessible", True,
                        f"Status: {response.status_code}")

            # Check for required endpoints
            required_endpoints = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']
            for endpoint in required_endpoints:
                if endpoint in data:
                    print_status(f"  {endpoint}", True, data[endpoint])
                else:
                    print_status(f"  {endpoint}", False, "Not found in discovery document")

            return True
        else:
            print_status("Discovery document accessible", False,
                        f"Status: {response.status_code}")
            return False

    except requests.RequestException as e:
        print_status("Discovery document accessible", False, str(e))
        return False
    except Exception as e:
        print_status("Discovery URL validation", False, str(e))
        return False

def check_redirect_uri():
    """Check redirect URI configuration"""
    print_header("Redirect URI Configuration")

    app_base_url = os.getenv('APP_BASE_URL', 'http://localhost:5000')
    redirect_uri = os.getenv('OIDC_REDIRECT_URI', f"{app_base_url}/auth/callback")

    parsed = urlparse(redirect_uri)

    print_status("Redirect URI configured", True, redirect_uri)

    # Check for HTTPS in production
    if 'localhost' not in parsed.netloc and '127.0.0.1' not in parsed.netloc:
        is_https = parsed.scheme == 'https'
        print_status("Production uses HTTPS", is_https,
                    "HTTPS is strongly recommended for production")

    print(f"\n  ⚠️  Ensure this redirect URI is registered with your OIDC provider:")
    print(f"     {redirect_uri}")

    return True

def check_authorization_rules():
    """Check authorization rules configuration"""
    print_header("Authorization Rules")

    email_verified = os.getenv('OIDC_REQUIRE_EMAIL_VERIFIED', 'false').lower() == 'true'
    print_status("Require email verification", email_verified,
                f"OIDC_REQUIRE_EMAIL_VERIFIED={os.getenv('OIDC_REQUIRE_EMAIL_VERIFIED', 'false')}")

    allowed_domains = os.getenv('OIDC_ALLOWED_DOMAINS', '')
    if allowed_domains:
        domains = [d.strip() for d in allowed_domains.split(',')]
        print_status("Domain restrictions", True,
                    f"{len(domains)} domain(s): {', '.join(domains)}")
    else:
        print_status("Domain restrictions", False, "All domains allowed")

    allowed_groups = os.getenv('OIDC_ALLOWED_GROUPS', '')
    if allowed_groups:
        groups = [g.strip() for g in allowed_groups.split(',')]
        print_status("Group restrictions", True,
                    f"{len(groups)} group(s): {', '.join(groups)}")
    else:
        print_status("Group restrictions", False, "All authenticated users allowed")

    admin_groups = os.getenv('OIDC_ADMIN_GROUPS', '')
    if admin_groups:
        groups = [g.strip() for g in admin_groups.split(',')]
        print_status("Admin groups", True,
                    f"{len(groups)} group(s): {', '.join(groups)}")
    else:
        print_status("Admin groups", False, "No admin groups configured")

    return True

def check_session_config():
    """Check session configuration"""
    print_header("Session Configuration")

    session_lifetime = int(os.getenv('SESSION_LIFETIME', '3600'))
    hours = session_lifetime / 3600
    print_status("Session lifetime", True,
                f"{session_lifetime} seconds ({hours:.1f} hour(s))")

    cookie_secure = os.getenv('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    print_status("Secure cookies", cookie_secure,
                f"SESSION_COOKIE_SECURE={os.getenv('SESSION_COOKIE_SECURE', 'true')}")

    secret_key = os.getenv('FLASK_SECRET_KEY', '')
    if secret_key and secret_key != 'your-secret-key-here':
        print_status("Flask secret key", True, "Custom secret key configured")
    else:
        print_status("Flask secret key", False,
                    "Using default or empty secret key - change for production!")

    return True

def main():
    """Main test function"""
    print_header("OIDC Configuration Test")
    print("Testing OIDC configuration for FMC Manager")

    # Check if .env file exists
    if not os.path.exists('.env'):
        print("\n⚠️  Warning: .env file not found")
        print("   Create one from .env.example: cp .env.example .env")
        print()

    # Check if OIDC is enabled
    if not check_oidc_enabled():
        print("\n❌ OIDC is disabled. Set OIDC_ENABLED=true to enable authentication.")
        print("   The application will run without authentication.\n")
        return True

    print("\n✅ OIDC is enabled. Checking configuration...\n")

    # Run all checks
    checks = [
        ("Required Variables", check_required_vars),
        ("Discovery URL", check_discovery_url),
        ("Redirect URI", check_redirect_uri),
        ("Authorization Rules", check_authorization_rules),
        ("Session Configuration", check_session_config),
    ]

    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print_status(check_name, False, f"Error: {str(e)}")
            results.append((check_name, False))

    # Summary
    print_header("Summary")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    print(f"\n  Checks passed: {passed}/{total}\n")

    if passed == total:
        print("  ✅ Configuration looks good! You can start the application.")
        print("  Run: python app.py\n")
        return True
    else:
        print("  ❌ Some checks failed. Please review the configuration above.")
        print("  See OIDC_SETUP.md for detailed setup instructions.\n")
        return False

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}\n")
        sys.exit(1)

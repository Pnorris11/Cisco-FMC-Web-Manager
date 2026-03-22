"""
OIDC Authentication Module for FMC Manager

This module provides OpenID Connect authentication using Authlib.
Supports various OIDC providers including Azure AD, Okta, Keycloak, etc.
"""

import os
import logging
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
import json

logger = logging.getLogger(__name__)

class OIDCAuth:
    """OIDC Authentication Handler"""

    def __init__(self, app=None):
        self.app = app
        self.oauth = None
        self.oidc_client = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize OIDC authentication with Flask app"""
        self.app = app

        # OIDC Configuration from environment
        oidc_enabled_env = os.getenv('OIDC_ENABLED', 'false')
        self.enabled = oidc_enabled_env.lower() == 'true'

        logger.info(f"OIDC_ENABLED environment variable: {oidc_enabled_env}")
        logger.info(f"OIDC authentication enabled: {self.enabled}")

        if not self.enabled:
            logger.info("OIDC authentication is disabled - skipping initialization")
            return

        # Required OIDC settings
        self.client_id = os.getenv('OIDC_CLIENT_ID')
        self.client_secret = os.getenv('OIDC_CLIENT_SECRET')
        self.discovery_url = os.getenv('OIDC_DISCOVERY_URL')

        logger.info(f"OIDC_CLIENT_ID: {'(set)' if self.client_id else '(not set)'}")
        logger.info(f"OIDC_CLIENT_SECRET: {'(set)' if self.client_secret else '(not set)'}")
        logger.info(f"OIDC_DISCOVERY_URL: {self.discovery_url if self.discovery_url else '(not set)'}")

        # Optional settings with defaults
        self.redirect_uri = os.getenv('OIDC_REDIRECT_URI',
                                     f"{os.getenv('APP_BASE_URL', 'http://localhost:5000')}/auth/callback")
        self.scopes = os.getenv('OIDC_SCOPES', 'openid profile email').split()

        logger.info(f"OIDC Redirect URI: {self.redirect_uri}")
        logger.info(f"OIDC Scopes: {self.scopes}")

        # Authorization settings
        self.require_email_verified = os.getenv('OIDC_REQUIRE_EMAIL_VERIFIED', 'false').lower() == 'true'
        self.allowed_domains = self._parse_list(os.getenv('OIDC_ALLOWED_DOMAINS', ''))
        self.allowed_groups = self._parse_list(os.getenv('OIDC_ALLOWED_GROUPS', ''))
        self.admin_groups = self._parse_list(os.getenv('OIDC_ADMIN_GROUPS', ''))

        # Note: Session settings are configured in app.py to avoid conflicts
        # We don't override them here

        # Validate required settings
        if not all([self.client_id, self.client_secret, self.discovery_url]):
            logger.error("OIDC is enabled but missing required configuration (CLIENT_ID, CLIENT_SECRET, or DISCOVERY_URL)")
            self.enabled = False
            return

        # Initialize OAuth
        logger.info("Initializing OAuth client...")
        self.oauth = OAuth(app)

        try:
            # Register OIDC client with discovery
            logger.info("Registering OIDC client with discovery URL...")
            self.oidc_client = self.oauth.register(
                name='oidc',
                client_id=self.client_id,
                client_secret=self.client_secret,
                server_metadata_url=self.discovery_url,
                client_kwargs={
                    'scope': ' '.join(self.scopes),
                    'token_endpoint_auth_method': 'client_secret_post'
                }
            )

            logger.info(f"✅ OIDC authentication initialized successfully")
            logger.info(f"   Discovery URL: {self.discovery_url}")
            logger.info(f"   Client ID: {self.client_id[:10]}...")

        except Exception as e:
            logger.error(f"❌ Failed to initialize OIDC: {str(e)}", exc_info=True)
            self.enabled = False

    def _parse_list(self, value):
        """Parse comma-separated list from environment variable"""
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def is_authenticated(self):
        """Check if user is authenticated"""
        return 'user' in session and session.get('authenticated', False)

    def get_user_info(self):
        """Get current user information from session"""
        return session.get('user')

    def get_user_email(self):
        """Get current user's email"""
        user = self.get_user_info()
        return user.get('email') if user else None

    def is_admin(self):
        """Check if current user has admin privileges"""
        user = self.get_user_info()
        if not user:
            return False

        user_groups = user.get('groups', [])
        return any(group in self.admin_groups for group in user_groups)

    def login(self):
        """Initiate OIDC login flow"""
        logger.info(f"Login called - OIDC enabled: {self.enabled}")

        if not self.enabled:
            logger.info("OIDC is disabled, redirecting to index")
            return redirect(url_for('index'))

        if not self.oidc_client:
            logger.error("OIDC client is not initialized")
            return jsonify({'error': 'Authentication not configured'}), 503

        # Generate and store state for CSRF protection
        state = generate_token()
        session['oauth_state'] = state
        logger.info(f"Generated OAuth state: {state[:10]}...")

        # Store the original URL to redirect back after login
        next_url = request.args.get('next') or request.referrer or url_for('index')
        session['next_url'] = next_url
        logger.info(f"Next URL after login: {next_url}")

        # Use the configured redirect URI instead of generating it
        redirect_uri = self.redirect_uri
        logger.info(f"Redirect URI: {redirect_uri}")

        try:
            logger.info(f"Initiating OIDC authorize redirect...")
            return self.oidc_client.authorize_redirect(redirect_uri, state=state)
        except Exception as e:
            logger.error(f"OIDC login error: {str(e)}", exc_info=True)
            return jsonify({'error': 'Authentication service unavailable', 'details': str(e)}), 503

    def callback(self):
        """Handle OIDC callback"""
        if not self.enabled:
            logger.info("OIDC not enabled, redirecting to index")
            return redirect(url_for('index'))

        try:
            # Check for error response from OIDC provider
            error = request.args.get('error')
            if error:
                error_description = request.args.get('error_description', 'No description provided')
                logger.error(f"OIDC provider returned error: {error} - {error_description}")
                return jsonify({
                    'error': 'Authentication failed',
                    'details': error_description
                }), 400

            # Verify state parameter for CSRF protection
            state = request.args.get('state')
            stored_state = session.get('oauth_state')
            logger.info(f"State validation - Received: {state[:10]}..., Expected: {stored_state[:10] if stored_state else 'None'}...")

            if not state or state != stored_state:
                logger.error("OIDC callback state mismatch - possible CSRF attack")
                return jsonify({'error': 'Invalid state parameter'}), 400

            # Exchange authorization code for tokens
            logger.info("Exchanging authorization code for tokens...")
            token = self.oidc_client.authorize_access_token()
            logger.info("Successfully obtained access token")

            # Get user info from ID token or userinfo endpoint
            user_info = token.get('userinfo')
            if not user_info:
                logger.info("User info not in token, fetching from userinfo endpoint...")
                user_info = self.oidc_client.userinfo(token=token)

            logger.info(f"User info retrieved: {user_info.get('email', 'no-email')}")

            # Validate user
            if not self._validate_user(user_info):
                logger.warning(f"User validation failed for: {user_info.get('email', 'unknown')}")
                session.clear()
                return jsonify({'error': 'Access denied. Contact your administrator.'}), 403

            # Extract user information
            user = {
                'sub': user_info.get('sub'),
                'email': user_info.get('email'),
                'name': user_info.get('name') or user_info.get('preferred_username'),
                'email_verified': user_info.get('email_verified', False),
                'groups': user_info.get('groups', []),
                'roles': user_info.get('roles', []),
            }

            # Store user in session
            session['user'] = user
            session['authenticated'] = True
            session['id_token'] = token.get('id_token')
            session.permanent = True

            logger.info(f"✅ User logged in successfully: {user['email']}")

            # Clean up and redirect
            next_url = session.pop('next_url', url_for('index'))
            session.pop('oauth_state', None)

            logger.info(f"Redirecting to: {next_url}")
            return redirect(next_url)

        except Exception as e:
            logger.error(f"❌ OIDC callback error: {str(e)}", exc_info=True)
            session.clear()
            return jsonify({'error': 'Authentication failed', 'details': str(e)}), 500

    def logout(self):
        """Handle logout"""
        if not self.enabled:
            session.clear()
            return redirect(url_for('index'))

        # Get ID token for logout
        id_token = session.get('id_token')

        # Clear session
        user_email = self.get_user_email()
        session.clear()

        logger.info(f"User logged out: {user_email}")

        # Redirect to OIDC provider logout if supported
        logout_url = os.getenv('OIDC_LOGOUT_URL')
        if logout_url and id_token:
            post_logout_redirect = url_for('index', _external=True)
            return redirect(f"{logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={post_logout_redirect}")

        return redirect(url_for('index'))

    def _validate_user(self, user_info):
        """Validate user based on configured rules"""

        # Check email verification if required
        if self.require_email_verified:
            if not user_info.get('email_verified', False):
                logger.warning(f"Email not verified for user: {user_info.get('email')}")
                return False

        # Check allowed domains
        if self.allowed_domains:
            email = user_info.get('email', '')
            domain = email.split('@')[-1] if '@' in email else ''
            if domain not in self.allowed_domains:
                logger.warning(f"Domain not allowed: {domain}")
                return False

        # Check allowed groups
        if self.allowed_groups:
            user_groups = user_info.get('groups', [])
            if not any(group in self.allowed_groups for group in user_groups):
                logger.warning(f"User not in allowed groups: {user_groups}")
                return False

        return True

    def require_auth(self, f):
        """Decorator to require authentication for routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.enabled:
                # If OIDC is disabled, allow access
                return f(*args, **kwargs)

            if not self.is_authenticated():
                # Store the requested URL to redirect after login
                return redirect(url_for('auth_login', next=request.url))

            return f(*args, **kwargs)
        return decorated_function

    def require_admin(self, f):
        """Decorator to require admin privileges"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.enabled:
                # If OIDC is disabled, allow access
                return f(*args, **kwargs)

            if not self.is_authenticated():
                return redirect(url_for('auth_login', next=request.url))

            if not self.is_admin():
                return jsonify({'error': 'Admin privileges required'}), 403

            return f(*args, **kwargs)
        return decorated_function


# Global instance
oidc_auth = OIDCAuth()


def init_oidc_routes(app, csrf=None):
    """Initialize OIDC authentication routes

    Args:
        app: Flask application instance
        csrf: CSRFProtect instance (optional, but recommended to exempt callback)
    """

    @app.route('/auth/login')
    def auth_login():
        """Login endpoint - must NOT require authentication"""
        try:
            return oidc_auth.login()
        except Exception as e:
            logger.error(f"Login route error: {str(e)}", exc_info=True)
            return jsonify({'error': 'Login failed', 'details': str(e)}), 500

    @app.route('/auth/callback')
    def auth_callback():
        """OIDC callback endpoint - must NOT require authentication or CSRF protection"""
        try:
            logger.info(f"OIDC callback received - URL: {request.url}")
            logger.info(f"OIDC callback - Args: {request.args}")
            return oidc_auth.callback()
        except Exception as e:
            logger.error(f"Callback route error: {str(e)}", exc_info=True)
            return jsonify({'error': 'Authentication callback failed', 'details': str(e)}), 500

    # Exempt the callback route from CSRF protection
    if csrf:
        csrf.exempt(auth_callback)
        logger.info("✅ OIDC callback route exempted from CSRF protection")

    @app.route('/auth/logout')
    def auth_logout():
        """Logout endpoint"""
        try:
            return oidc_auth.logout()
        except Exception as e:
            logger.error(f"Logout route error: {str(e)}")
            session.clear()
            return redirect(url_for('index'))

    @app.route('/auth/user')
    def auth_user():
        """Get current user info (API endpoint)"""
        try:
            if not oidc_auth.is_authenticated():
                return jsonify({'authenticated': False}), 401

            user = oidc_auth.get_user_info()
            return jsonify({
                'authenticated': True,
                'user': {
                    'email': user.get('email'),
                    'name': user.get('name'),
                    'is_admin': oidc_auth.is_admin()
                }
            })
        except Exception as e:
            logger.error(f"Auth user route error: {str(e)}")
            return jsonify({'error': 'Failed to get user info'}), 500

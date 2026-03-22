# OIDC Authentication Setup Guide

This guide explains how to configure OpenID Connect (OIDC) authentication for the FMC Manager application.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Provider Configuration](#provider-configuration)
  - [Azure AD / Entra ID](#azure-ad--entra-id)
  - [Okta](#okta)
  - [Keycloak](#keycloak)
  - [Google](#google)
- [Configuration Reference](#configuration-reference)
- [Authorization Rules](#authorization-rules)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

The FMC Manager supports OIDC authentication, allowing you to integrate with enterprise identity providers such as:

- Microsoft Azure AD / Entra ID
- Okta
- Keycloak
- Google Workspace
- Any OIDC-compliant provider

## Features

- **SSO Integration**: Single Sign-On with your corporate identity provider
- **Group-based Access Control**: Control access based on group membership
- **Domain Restrictions**: Limit access to specific email domains
- **Email Verification**: Require verified email addresses
- **Admin Roles**: Define admin groups for elevated privileges
- **Secure Sessions**: HTTP-only, secure cookies with configurable lifetime
- **CSRF Protection**: Built-in state parameter validation

## Quick Start

1. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**

   Copy the example configuration:
   ```bash
   cp .env.example .env
   ```

   Update `.env` with your OIDC provider settings:
   ```bash
   OIDC_ENABLED=true
   OIDC_DISCOVERY_URL=https://your-provider/.well-known/openid-configuration
   OIDC_CLIENT_ID=your-client-id
   OIDC_CLIENT_SECRET=your-client-secret
   APP_BASE_URL=https://your-app-url.com
   ```

3. **Start the Application**

   ```bash
   python app.py
   ```

4. **Test Authentication**

   Navigate to `https://your-app-url.com` and you should be redirected to your OIDC provider's login page.

## Provider Configuration

### Azure AD / Entra ID

#### 1. Register Application

1. Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory → App registrations
2. Click "New registration"
3. Configure:
   - **Name**: FMC Manager
   - **Supported account types**: Accounts in this organizational directory only
   - **Redirect URI**: Web - `https://your-app-url.com/auth/callback`

#### 2. Configure Authentication

1. Under "Authentication", add redirect URI if not done during registration
2. Enable "ID tokens" under Implicit grant and hybrid flows
3. Save changes

#### 3. Get Client Credentials

1. Go to "Overview" and copy:
   - **Application (client) ID** → `OIDC_CLIENT_ID`
   - **Directory (tenant) ID** → Used in discovery URL
2. Go to "Certificates & secrets" → New client secret
   - Copy the secret value → `OIDC_CLIENT_SECRET`

#### 4. Configure Optional Claims (for groups)

1. Go to "Token configuration" → Add optional claim
2. Select "ID" token type
3. Add "groups" claim

#### 5. Environment Configuration

```bash
OIDC_ENABLED=true
OIDC_DISCOVERY_URL=https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration
OIDC_CLIENT_ID=your-application-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_LOGOUT_URL=https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/logout
OIDC_ALLOWED_DOMAINS=yourdomain.com
OIDC_ALLOWED_GROUPS=FMC-Users
OIDC_ADMIN_GROUPS=FMC-Admins
```

### Okta

#### 1. Create Application

1. Go to Okta Admin Console → Applications → Create App Integration
2. Select "OIDC - OpenID Connect"
3. Select "Web Application"
4. Configure:
   - **App integration name**: FMC Manager
   - **Sign-in redirect URIs**: `https://your-app-url.com/auth/callback`
   - **Sign-out redirect URIs**: `https://your-app-url.com`
   - **Assignments**: Select who should have access

#### 2. Get Credentials

1. Copy "Client ID" → `OIDC_CLIENT_ID`
2. Copy "Client secret" → `OIDC_CLIENT_SECRET`
3. Your Okta domain is `https://{your-domain}.okta.com`

#### 3. Configure Groups Claim

1. Go to Security → API → Authorization Servers
2. Edit "default" server → Claims → Add Claim
   - **Name**: groups
   - **Include in token type**: ID Token, Always
   - **Value type**: Groups
   - **Filter**: Regex: `.*`

#### 4. Environment Configuration

```bash
OIDC_ENABLED=true
OIDC_DISCOVERY_URL=https://{your-domain}.okta.com/.well-known/openid-configuration
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_LOGOUT_URL=https://{your-domain}.okta.com/oauth2/v1/logout
OIDC_ALLOWED_GROUPS=FMC-Users
OIDC_ADMIN_GROUPS=FMC-Admins
```

### Keycloak

#### 1. Create Client

1. Go to Keycloak Admin Console → Clients → Create
2. Configure:
   - **Client ID**: fmc-manager
   - **Client Protocol**: openid-connect
   - **Root URL**: `https://your-app-url.com`

#### 2. Configure Client Settings

1. **Access Type**: confidential
2. **Valid Redirect URIs**: `https://your-app-url.com/auth/callback`
3. **Base URL**: `/`
4. Save changes

#### 3. Get Credentials

1. Go to "Credentials" tab
2. Copy "Secret" → `OIDC_CLIENT_SECRET`

#### 4. Configure Mappers (for groups)

1. Go to "Mappers" tab → Create
2. Configure:
   - **Name**: groups
   - **Mapper Type**: Group Membership
   - **Token Claim Name**: groups
   - **Add to ID token**: ON

#### 5. Environment Configuration

```bash
OIDC_ENABLED=true
OIDC_DISCOVERY_URL=https://{keycloak-url}/realms/{realm-name}/.well-known/openid-configuration
OIDC_CLIENT_ID=fmc-manager
OIDC_CLIENT_SECRET=your-client-secret
OIDC_LOGOUT_URL=https://{keycloak-url}/realms/{realm-name}/protocol/openid-connect/logout
OIDC_ALLOWED_GROUPS=FMC-Users
OIDC_ADMIN_GROUPS=FMC-Admins
```

### Google

#### 1. Create OAuth 2.0 Client

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Select/Create Project → APIs & Services → Credentials
3. Create OAuth client ID:
   - **Application type**: Web application
   - **Authorized redirect URIs**: `https://your-app-url.com/auth/callback`

#### 2. Get Credentials

1. Copy "Client ID" → `OIDC_CLIENT_ID`
2. Copy "Client secret" → `OIDC_CLIENT_SECRET`

#### 3. Environment Configuration

```bash
OIDC_ENABLED=true
OIDC_DISCOVERY_URL=https://accounts.google.com/.well-known/openid-configuration
OIDC_CLIENT_ID=your-client-id.apps.googleusercontent.com
OIDC_CLIENT_SECRET=your-client-secret
OIDC_SCOPES=openid profile email
OIDC_ALLOWED_DOMAINS=yourdomain.com
```

**Note**: Google doesn't provide group information by default. You'll need to use Google Workspace APIs for group-based access control.

## Configuration Reference

### Required Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `OIDC_ENABLED` | Enable/disable OIDC | `true` or `false` |
| `OIDC_CLIENT_ID` | OAuth client ID from provider | `abc123...` |
| `OIDC_CLIENT_SECRET` | OAuth client secret from provider | `secret123...` |
| `OIDC_DISCOVERY_URL` | OIDC discovery endpoint | `https://provider/.well-known/openid-configuration` |

### Optional Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_BASE_URL` | Application base URL | `http://localhost:5000` |
| `OIDC_REDIRECT_URI` | OAuth redirect URI | `{APP_BASE_URL}/auth/callback` |
| `OIDC_SCOPES` | OAuth scopes (space-separated) | `openid profile email` |
| `OIDC_LOGOUT_URL` | Provider logout endpoint | None |
| `SESSION_COOKIE_SECURE` | Require HTTPS for cookies | `true` |
| `SESSION_LIFETIME` | Session lifetime in seconds | `3600` |

## Authorization Rules

### Email Verification

Require users to have verified email addresses:

```bash
OIDC_REQUIRE_EMAIL_VERIFIED=true
```

### Domain Restrictions

Limit access to specific email domains:

```bash
# Single domain
OIDC_ALLOWED_DOMAINS=company.com

# Multiple domains
OIDC_ALLOWED_DOMAINS=company.com,partner.com,subsidiary.com
```

### Group-Based Access Control

Control access based on group membership:

```bash
# Users must be in one of these groups to access the app
OIDC_ALLOWED_GROUPS=FMC-Users,Network-Team,Security-Team

# Users in these groups get admin privileges
OIDC_ADMIN_GROUPS=FMC-Admins,Network-Admins
```

**Note**: Group names must match the `groups` claim from your OIDC provider. Configure your provider to include group information in ID tokens.

### Combined Rules

All configured rules must pass for a user to be authenticated:

```bash
OIDC_REQUIRE_EMAIL_VERIFIED=true
OIDC_ALLOWED_DOMAINS=company.com
OIDC_ALLOWED_GROUPS=FMC-Users
OIDC_ADMIN_GROUPS=FMC-Admins
```

A user must:
1. Have a verified email address
2. Have an email from `company.com` domain
3. Be a member of the `FMC-Users` group
4. (Optional) Be in `FMC-Admins` group for admin access

## Testing

### Test Authentication Flow

1. **Start with OIDC disabled** to verify basic functionality:
   ```bash
   OIDC_ENABLED=false
   ```

2. **Enable OIDC** and test login:
   ```bash
   OIDC_ENABLED=true
   ```

3. **Test the flow**:
   - Navigate to the application
   - You should be redirected to your OIDC provider
   - Log in with your credentials
   - You should be redirected back and authenticated

### Check User Information

Add a test endpoint to verify user information is being received correctly:

```python
@app.route('/debug/user')
@oidc_auth.require_auth
def debug_user():
    """Debug endpoint to view user information"""
    return jsonify({
        'user': oidc_auth.get_user_info(),
        'is_admin': oidc_auth.is_admin()
    })
```

### Verify Authorization Rules

Test that your authorization rules are working:

1. **Email verification**: Try logging in with an unverified email
2. **Domain restrictions**: Try logging in with an email from a non-allowed domain
3. **Group restrictions**: Try logging in as a user not in allowed groups

## Troubleshooting

### Authentication Fails

**Symptom**: Redirected to login but authentication fails

**Solutions**:
1. Check that redirect URI matches exactly (including protocol, port, path)
2. Verify client ID and secret are correct
3. Check application logs for detailed error messages
4. Verify discovery URL is accessible

### State Parameter Mismatch

**Symptom**: "Invalid state parameter" error

**Solutions**:
1. Ensure cookies are enabled
2. Check that `FLASK_SECRET_KEY` is set and consistent
3. Verify your application URL is consistent (don't mix HTTP/HTTPS)

### No Group Information

**Symptom**: Users can't access app when `OIDC_ALLOWED_GROUPS` is set

**Solutions**:
1. Verify your OIDC provider is configured to include groups in ID token
2. Check the claim name (might be `roles` instead of `groups`)
3. Add logging to see what claims are being received
4. Some providers require special scopes or API permissions for groups

### Session Expires Too Quickly

**Symptom**: Users are logged out frequently

**Solutions**:
1. Increase `SESSION_LIFETIME`:
   ```bash
   SESSION_LIFETIME=7200  # 2 hours
   ```
2. Verify `SESSION_COOKIE_SECURE` is appropriate for your environment

### Cannot Access Application (403 Forbidden)

**Symptom**: Authentication succeeds but access is denied

**Solutions**:
1. Check authorization rules in logs
2. Verify user meets all configured requirements:
   - Email verification (if required)
   - Domain restrictions
   - Group membership
3. Temporarily remove authorization rules to test:
   ```bash
   OIDC_REQUIRE_EMAIL_VERIFIED=false
   OIDC_ALLOWED_DOMAINS=
   OIDC_ALLOWED_GROUPS=
   ```

### Provider-Specific Issues

#### Azure AD

- **Groups not appearing**: Enable "Group claims" in token configuration
- **Tenant issues**: Ensure you're using the correct tenant ID in URLs
- **App not found**: Check application is enabled and assigned to users

#### Okta

- **Groups claim missing**: Configure groups claim in authorization server
- **Domain issues**: Use your full Okta domain URL
- **Assignments**: Verify users are assigned to the application

#### Keycloak

- **Client not found**: Ensure client ID matches exactly
- **Realm issues**: Check realm name in discovery URL
- **Mapper problems**: Verify group mapper is configured correctly

## Security Considerations

1. **Always use HTTPS in production**:
   ```bash
   SESSION_COOKIE_SECURE=true
   APP_BASE_URL=https://your-app-url.com
   ```

2. **Strong secret key**:
   ```bash
   FLASK_SECRET_KEY=$(openssl rand -hex 32)
   ```

3. **Short session lifetime** for sensitive environments:
   ```bash
   SESSION_LIFETIME=1800  # 30 minutes
   ```

4. **Regular secret rotation**: Rotate `OIDC_CLIENT_SECRET` periodically

5. **Audit logging**: Monitor authentication logs for suspicious activity

## Support

For additional help:
- Check application logs for detailed error messages
- Review your OIDC provider's documentation
- Consult the [Authlib documentation](https://docs.authlib.org/)

## Examples

See `.env.example` for a complete configuration example.

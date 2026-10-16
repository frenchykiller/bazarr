# coding=utf-8

import os
import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlencode, quote

import requests

logger = logging.getLogger(__name__)


class OIDCStateStore:
    """Thread-safe TTL store for OIDC state, PKCE code verifiers, and callback URIs."""

    def __init__(self, default_ttl: int = 600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self.default_ttl = default_ttl

    def create_state(self, code_verifier: str, redirect_uri: str, ttl: Optional[int] = None) -> str:
        state = secrets.token_urlsafe(32)
        ttl_seconds = ttl if ttl is not None else self.default_ttl
        with self._lock:
            self._cache[state] = {
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "expires_at": datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
                "created_at": time.time(),
            }
        return state

    def validate_and_pop(self, state: str) -> Optional[Dict[str, Any]]:
        if not state:
            return None
        with self._lock:
            entry = self._cache.pop(state, None)
            if not entry:
                return None
            if datetime.now(timezone.utc) > entry["expires_at"]:
                return None
            return entry

    def cleanup_expired(self):
        with self._lock:
            now = datetime.now(timezone.utc)
            expired_keys = [k for k, v in self._cache.items() if now > v["expires_at"]]
            for k in expired_keys:
                self._cache.pop(k, None)


oidc_state_store = OIDCStateStore()


class OIDCDiscoveryCache:
    """Thread-safe cache for OIDC Provider Discovery documents."""

    def __init__(self, ttl: int = 3600):
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = threading.RLock()
        self.ttl = ttl

    def get_discovery(self, issuer_url: str) -> Dict[str, Any]:
        normalized_issuer = issuer_url.rstrip("/")
        now = time.time()
        with self._lock:
            if normalized_issuer in self._cache:
                doc, cached_at = self._cache[normalized_issuer]
                if now - cached_at < self.ttl:
                    return doc

        discovery_url = f"{normalized_issuer}/.well-known/openid-configuration"
        logger.info(f"Fetching OIDC discovery configuration from {discovery_url}")
        resp = requests.get(discovery_url, timeout=10)
        resp.raise_for_status()
        doc = resp.json()

        if not isinstance(doc, dict):
            raise ValueError("OIDC discovery response is not a valid JSON object")

        if "authorization_endpoint" not in doc or "token_endpoint" not in doc:
            raise ValueError("OIDC discovery missing required authorization_endpoint or token_endpoint")

        with self._lock:
            self._cache[normalized_issuer] = (doc, now)

        return doc

    def clear(self):
        with self._lock:
            self._cache.clear()


oidc_discovery_cache = OIDCDiscoveryCache()


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates RFC 7636 compliant PKCE code_verifier and S256 code_challenge."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def get_oidc_settings() -> Dict[str, Any]:
    """Retrieves OIDC configuration from environment variables."""
    issuer_url = os.environ.get("OIDC_ISSUER_URL", "").strip().rstrip("/")
    client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
    client_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "").strip()
    scopes = os.environ.get("OIDC_SCOPES", "openid profile email groups").strip()
    admin_group = os.environ.get("OIDC_ADMIN_GROUP", "").strip()
    display_name = os.environ.get("OIDC_DISPLAY_NAME", "Login with OIDC").strip()

    enabled_env = os.environ.get("OIDC_ENABLED", "").lower().strip()
    if enabled_env in ("true", "1", "yes"):
        enabled = True
    elif enabled_env in ("false", "0", "no"):
        enabled = False
    else:
        # Auto-enable if issuer and client_id are set
        enabled = bool(issuer_url and client_id)

    return {
        "enabled": enabled,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "admin_group": admin_group,
        "display_name": display_name or "Login with OIDC",
    }


def is_oidc_enabled() -> bool:
    """Checks if OIDC authentication is enabled."""
    return get_oidc_settings()["enabled"]


def get_oidc_config() -> Dict[str, Any]:
    """Returns public configuration for the frontend."""
    settings = get_oidc_settings()
    return {
        "enabled": settings["enabled"],
        "displayName": settings["display_name"],
    }


def resolve_redirect_uri(request=None, default_path: str = "/api/auth/oidc/callback") -> str:
    """
    Resolves the redirect URI.
    Uses OIDC_REDIRECT_URI if set; otherwise dynamically constructs it from Flask request.
    """
    settings = get_oidc_settings()
    if settings["redirect_uri"]:
        return settings["redirect_uri"]

    from app.config import base_url

    if request is not None:
        scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
        host = request.headers.get("X-Forwarded-Host", request.host)
        prefix = base_url.rstrip("/") if base_url else ""
        return f"{scheme}://{host}{prefix}{default_path}"

    prefix = base_url.rstrip("/") if base_url else ""
    return f"http://localhost:6767{prefix}{default_path}"


def build_authorization_url(request=None, callback_path: str = "/api/auth/oidc/callback") -> str:
    """
    Builds the OIDC Identity Provider authorization URL with PKCE (S256).
    """
    cfg = get_oidc_settings()
    if not cfg["enabled"] or not cfg["issuer_url"] or not cfg["client_id"]:
        raise ValueError("OIDC is not properly configured")

    discovery = oidc_discovery_cache.get_discovery(cfg["issuer_url"])
    auth_endpoint = discovery.get("authorization_endpoint")
    if not auth_endpoint:
        raise ValueError("OIDC discovery document missing authorization_endpoint")

    code_verifier, code_challenge = generate_pkce_pair()
    redirect_uri = resolve_redirect_uri(request=request, default_path=callback_path)

    state = oidc_state_store.create_state(code_verifier=code_verifier, redirect_uri=redirect_uri)

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    delimiter = "&" if "?" in auth_endpoint else "?"
    return f"{auth_endpoint}{delimiter}{urlencode(params)}"


def decode_id_token_claims(id_token: str) -> Dict[str, Any]:
    """Safely extracts claims from an unencrypted ID token payload without signature verification."""
    if not id_token or not isinstance(id_token, str):
        return {}
    parts = id_token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload_b64 = parts[1]
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        logger.warning(f"Failed to decode ID token payload: {e}")
        return {}


def exchange_code_for_tokens(code: str, code_verifier: str, redirect_uri: str) -> Dict[str, Any]:
    """Exchanges an authorization code at the OIDC token_endpoint using PKCE."""
    cfg = get_oidc_settings()
    discovery = oidc_discovery_cache.get_discovery(cfg["issuer_url"])
    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        raise ValueError("OIDC discovery document missing token_endpoint")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": cfg["client_id"],
        "code_verifier": code_verifier,
    }

    auth = None
    if cfg["client_secret"]:
        data["client_secret"] = cfg["client_secret"]
        auth = (cfg["client_id"], cfg["client_secret"])

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    logger.debug(f"Exchanging authorization code at {token_endpoint}")
    resp = requests.post(token_endpoint, data=data, auth=auth, headers=headers, timeout=15)
    resp.raise_for_status()
    tokens = resp.json()
    if not isinstance(tokens, dict):
        raise ValueError("Invalid token response from OIDC provider")
    return tokens


def fetch_userinfo(access_token: str) -> Dict[str, Any]:
    """Fetches user claims from userinfo_endpoint using the access_token."""
    if not access_token:
        return {}
    cfg = get_oidc_settings()
    try:
        discovery = oidc_discovery_cache.get_discovery(cfg["issuer_url"])
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if not userinfo_endpoint:
            return {}

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        resp = requests.get(userinfo_endpoint, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"Userinfo endpoint returned status {resp.status_code}")
    except Exception as e:
        logger.warning(f"Error fetching userinfo from OIDC provider: {e}")
    return {}


def verify_admin_group(claims: Dict[str, Any], required_group: str) -> bool:
    """
    Verifies that the authenticated user claims contain the required admin group.
    Returns True if no group is required or if user belongs to the required group.
    """
    if not required_group:
        return True

    # Search through common group/role claim keys
    for claim_key in ("groups", "group", "roles", "role", "memberOf"):
        claim_val = claims.get(claim_key)
        if claim_val is None:
            continue
        if isinstance(claim_val, (list, tuple, set)):
            if any(str(g).strip().lower() == required_group.lower() for g in claim_val):
                return True
        elif isinstance(claim_val, str):
            # Check direct match or comma/space separated values
            if claim_val.strip().lower() == required_group.lower():
                return True
            parts = [p.strip().lower() for p in claim_val.replace(";", ",").split(",")]
            if required_group.lower() in parts:
                return True

    return False


def handle_callback(code: str, state: str, request=None) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Validates state & code, exchanges for tokens, retrieves & merges user claims,
    and checks admin group membership.
    Returns: (success: bool, error_code: Optional[str], claims: Optional[dict])
    """
    entry = oidc_state_store.validate_and_pop(state)
    if not entry:
        logger.warning("OIDC state validation failed: state not found or expired")
        return False, "invalid_state", None

    code_verifier = entry["code_verifier"]
    redirect_uri = entry.get("redirect_uri") or resolve_redirect_uri(request=request)

    try:
        tokens = exchange_code_for_tokens(code=code, code_verifier=code_verifier, redirect_uri=redirect_uri)
    except Exception as e:
        logger.error(f"OIDC token exchange failed: {e}")
        return False, "token_exchange_failed", None

    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")

    merged_claims: Dict[str, Any] = {}
    if id_token:
        merged_claims.update(decode_id_token_claims(id_token))

    if access_token:
        userinfo_claims = fetch_userinfo(access_token)
        merged_claims.update(userinfo_claims)

    cfg = get_oidc_settings()
    required_group = cfg["admin_group"]
    if required_group and not verify_admin_group(merged_claims, required_group):
        user_id = merged_claims.get("preferred_username") or merged_claims.get("email") or merged_claims.get("sub")
        logger.warning(f"OIDC user {user_id} denied access: missing required group '{required_group}'")
        return False, "unauthorized_group", None

    return True, None, merged_claims


def initialize_oidc():
    """
    Checks if OIDC is configured and ensures authentication enforcement is active.
    If settings.auth.type is None when OIDC is configured, sets settings.auth.type = 'form'
    and ensures a fallback local admin credential exists.
    """
    if not is_oidc_enabled():
        return

    from app.config import settings, write_config

    changed = False
    if settings.auth.type is None:
        logger.info("OIDC is enabled via environment variables: enforcing 'form' authentication")
        settings.auth.type = "form"
        changed = True

    if not getattr(settings.auth, "username", ""):
        settings.auth.username = "admin"
        changed = True

    if not getattr(settings.auth, "password", ""):
        # Generate fallback local admin password
        fallback_pw = secrets.token_urlsafe(16)
        settings.auth.password = fallback_pw
        logger.info(f"OIDC bootstrap: generated fallback local admin credentials (username: admin)")
        changed = True

    if changed:
        try:
            write_config()
        except Exception as e:
            logger.debug(f"Could not persist config during OIDC initialization: {e}")

    try:
        def oidc_cleanup_task():
            while True:
                time.sleep(300)
                try:
                    oidc_state_store.cleanup_expired()
                except Exception:
                    pass

        cleanup_thread = threading.Thread(target=oidc_cleanup_task, daemon=True)
        cleanup_thread.start()
        logger.info("OIDC state cache cleanup started")
    except Exception as e:
        logger.warning(f"Could not start OIDC cache cleanup task: {e}")

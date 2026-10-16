# coding=utf-8

import base64
import json
import os
import time
from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask, session

from app.oidc import (
    OIDCStateStore,
    OIDCDiscoveryCache,
    generate_pkce_pair,
    get_oidc_settings,
    is_oidc_enabled,
    get_oidc_config,
    resolve_redirect_uri,
    build_authorization_url,
    decode_id_token_claims,
    exchange_code_for_tokens,
    fetch_userinfo,
    verify_admin_group,
    handle_callback,
    initialize_oidc,
    oidc_state_store,
    oidc_discovery_cache,
)
from app.config import settings


@pytest.fixture(autouse=True)
def reset_oidc_state(monkeypatch):
    """Ensure clean OIDC discovery cache, state store, and environment for each test."""
    oidc_discovery_cache.clear()
    with oidc_state_store._lock:
        oidc_state_store._cache.clear()
    for env_var in (
        "OIDC_ENABLED",
        "OIDC_ISSUER_URL",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "OIDC_REDIRECT_URI",
        "OIDC_SCOPES",
        "OIDC_ADMIN_GROUP",
        "OIDC_DISPLAY_NAME",
    ):
        monkeypatch.delenv(env_var, raising=False)
    yield
    oidc_discovery_cache.clear()
    with oidc_state_store._lock:
        oidc_state_store._cache.clear()


class TestOIDCStateStore:
    def test_create_and_validate_state(self):
        store = OIDCStateStore(default_ttl=60)
        state = store.create_state("verifier_123", "https://app.com/callback")
        assert state is not None

        entry = store.validate_and_pop(state)
        assert entry is not None
        assert entry["code_verifier"] == "verifier_123"
        assert entry["redirect_uri"] == "https://app.com/callback"

        # Second pop returns None (single use)
        assert store.validate_and_pop(state) is None

    def test_validate_unknown_state(self):
        store = OIDCStateStore()
        assert store.validate_and_pop("") is None
        assert store.validate_and_pop("nonexistent") is None

    def test_state_expiry(self):
        store = OIDCStateStore(default_ttl=-1)  # already expired
        state = store.create_state("verifier_exp", "https://app.com/callback")
        assert store.validate_and_pop(state) is None

    def test_cleanup_expired(self):
        store = OIDCStateStore()
        s_expired = store.create_state("v1", "https://app.com/callback", ttl=-10)
        s_valid = store.create_state("v2", "https://app.com/callback", ttl=300)

        store.cleanup_expired()
        assert store.validate_and_pop(s_expired) is None
        assert store.validate_and_pop(s_valid) is not None


class TestPKCE:
    def test_generate_pkce_pair(self):
        verifier, challenge = generate_pkce_pair()
        assert isinstance(verifier, str)
        assert len(verifier) >= 43
        assert isinstance(challenge, str)
        assert "=" not in challenge


class TestOIDCDiscoveryCache:
    def test_get_discovery_success(self, requests_mock):
        cache = OIDCDiscoveryCache(ttl=60)
        requests_mock.get(
            "https://idp.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/token",
                "userinfo_endpoint": "https://idp.example.com/userinfo",
            },
        )
        doc = cache.get_discovery("https://idp.example.com")
        assert doc["authorization_endpoint"] == "https://idp.example.com/auth"

        # Cached call
        doc2 = cache.get_discovery("https://idp.example.com/")
        assert doc2["token_endpoint"] == "https://idp.example.com/token"

    def test_get_discovery_invalid_doc(self, requests_mock):
        cache = OIDCDiscoveryCache(ttl=60)
        requests_mock.get(
            "https://idp.bad.com/.well-known/openid-configuration",
            json={"foo": "bar"},
        )
        with pytest.raises(ValueError, match="missing required"):
            cache.get_discovery("https://idp.bad.com")

    def test_clear_cache(self, requests_mock):
        cache = OIDCDiscoveryCache(ttl=60)
        requests_mock.get(
            "https://idp.test.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://idp.test.com/auth",
                "token_endpoint": "https://idp.test.com/token",
            },
        )
        cache.get_discovery("https://idp.test.com")
        cache.clear()
        assert "https://idp.test.com" not in cache._cache


class TestOIDCSettings:
    def test_get_oidc_settings_default(self):
        cfg = get_oidc_settings()
        assert cfg["enabled"] is False
        assert cfg["display_name"] == "Login with OIDC"
        assert is_oidc_enabled() is False
        assert get_oidc_config()["enabled"] is False

    def test_get_oidc_settings_auto_enable(self, monkeypatch):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr_client")

        cfg = get_oidc_settings()
        assert cfg["enabled"] is True
        assert cfg["issuer_url"] == "https://auth.example.com"
        assert is_oidc_enabled() is True

    def test_get_oidc_settings_explicit_disable(self, monkeypatch):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr_client")
        monkeypatch.setenv("OIDC_ENABLED", "false")

        assert is_oidc_enabled() is False


class TestResolveRedirectURI:
    def test_explicit_env(self, monkeypatch):
        monkeypatch.setenv("OIDC_REDIRECT_URI", "https://custom.app/callback")
        assert resolve_redirect_uri() == "https://custom.app/callback"

    def test_dynamic_request_headers(self):
        mock_req = Mock()
        mock_req.headers = {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "bazarr.media.internal",
        }
        uri = resolve_redirect_uri(request=mock_req, default_path="/api/auth/oidc/callback")
        assert uri.startswith("https://bazarr.media.internal")
        assert uri.endswith("/api/auth/oidc/callback")

    def test_fallback_localhost(self):
        uri = resolve_redirect_uri(request=None)
        assert uri.startswith("http://localhost:6767")


class TestBuildAuthorizationURL:
    def test_build_url_disabled_raises(self):
        with pytest.raises(ValueError):
            build_authorization_url()

    def test_build_url_success(self, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        monkeypatch.setenv("OIDC_REDIRECT_URI", "https://bazarr.example.com/api/auth/oidc/callback")
        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        url = build_authorization_url()
        assert url.startswith("https://auth.example.com/oauth2/auth?")
        assert "response_type=code" in url
        assert "client_id=bazarr" in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url


class TestClaimsAndGroupVerification:
    def test_decode_id_token_claims(self):
        payload = {"sub": "user123", "email": "admin@example.com", "groups": ["admins"]}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
        fake_jwt = f"header.{payload_b64}.signature"
        claims = decode_id_token_claims(fake_jwt)
        assert claims["sub"] == "user123"
        assert claims["email"] == "admin@example.com"

    def test_decode_invalid_id_token(self):
        assert decode_id_token_claims("") == {}
        assert decode_id_token_claims("invalid_jwt") == {}
        assert decode_id_token_claims("a.invalid_base64!!!.c") == {}

    def test_verify_admin_group_none_required(self):
        assert verify_admin_group({}, "") is True

    def test_verify_admin_group_list(self):
        claims = {"groups": ["media_users", "Admins"]}
        assert verify_admin_group(claims, "admins") is True
        assert verify_admin_group(claims, "superadmin") is False

    def test_verify_admin_group_string(self):
        assert verify_admin_group({"group": "admins"}, "admins") is True
        assert verify_admin_group({"roles": "user, admins, viewer"}, "admins") is True
        assert verify_admin_group({"role": "user"}, "admins") is False


class TestTokenExchangeAndUserInfo:
    def test_exchange_code_for_tokens(self, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        monkeypatch.setenv("OIDC_CLIENT_SECRET", "supersecret")
        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.post(
            "https://auth.example.com/oauth2/token",
            json={"access_token": "acc_123", "id_token": "id_123"},
        )
        tokens = exchange_code_for_tokens("test_code", "test_verifier", "https://bazarr/callback")
        assert tokens["access_token"] == "acc_123"

    def test_fetch_userinfo(self, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.get(
            "https://auth.example.com/oauth2/userinfo",
            json={"preferred_username": "john_doe", "groups": ["admins"]},
        )
        info = fetch_userinfo("test_token")
        assert info["preferred_username"] == "john_doe"

    def test_fetch_userinfo_no_token(self):
        assert fetch_userinfo("") == {}


class TestHandleCallback:
    def test_handle_callback_state_invalid(self):
        success, err, claims = handle_callback("code1", "bad_state")
        assert success is False
        assert err == "invalid_state"

    def test_handle_callback_success(self, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        monkeypatch.setenv("OIDC_ADMIN_GROUP", "admins")

        state = oidc_state_store.create_state("code_verifier_123", "https://bazarr/callback")

        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.post(
            "https://auth.example.com/oauth2/token",
            json={"access_token": "acc_tok", "id_token": "id_tok"},
        )
        requests_mock.get(
            "https://auth.example.com/oauth2/userinfo",
            json={"preferred_username": "alice", "groups": ["admins"]},
        )

        success, err, claims = handle_callback("valid_code", state)
        assert success is True
        assert err is None
        assert claims["preferred_username"] == "alice"

    def test_handle_callback_unauthorized_group(self, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        monkeypatch.setenv("OIDC_ADMIN_GROUP", "superadmins")

        state = oidc_state_store.create_state("code_verifier_123", "https://bazarr/callback")

        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.post(
            "https://auth.example.com/oauth2/token",
            json={"access_token": "acc_tok"},
        )
        requests_mock.get(
            "https://auth.example.com/oauth2/userinfo",
            json={"preferred_username": "bob", "groups": ["regular_users"]},
        )

        success, err, claims = handle_callback("valid_code", state)
        assert success is False
        assert err == "unauthorized_group"


class TestInitializeOIDC:
    def test_initialize_oidc_when_enabled(self, monkeypatch):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        settings.auth.type = None
        settings.auth.username = ""
        settings.auth.password = ""

        initialize_oidc()
        assert settings.auth.type == "form"
        assert settings.auth.username == "admin"
        assert len(settings.auth.password) > 0


class TestAPIEndpoints:
    @pytest.fixture
    def client(self):
        test_app = Flask(__name__)
        test_app.secret_key = "test_oidc_secret"
        from flask_restx import Api
        from api.auth.oidc import api_ns_auth_oidc
        api = Api(test_app)
        api.add_namespace(api_ns_auth_oidc, "/api/")
        test_app.config["TESTING"] = True
        return test_app.test_client()

    def test_get_oidc_config_endpoint(self, client, monkeypatch):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        monkeypatch.setenv("OIDC_DISPLAY_NAME", "Sign in with SSO")

        resp = client.get("/api/auth/oidc/config")
        assert resp.status_code == 200
        data = resp.json
        assert data["enabled"] is True
        assert data["displayName"] == "Sign in with SSO"

    def test_get_oidc_login_disabled(self, client):
        resp = client.get("/api/auth/oidc/login")
        assert resp.status_code == 302
        assert "error=oidc_disabled" in resp.headers["Location"]

    def test_get_oidc_login_redirects_to_idp(self, client, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        resp = client.get("/api/auth/oidc/login")
        assert resp.status_code == 302
        assert resp.headers["Location"].startswith("https://auth.example.com/oauth2/auth?")

    def test_get_oidc_callback_error_param(self, client):
        resp = client.get("/api/auth/oidc/callback?error=access_denied")
        assert resp.status_code == 302
        assert "error=access_denied" in resp.headers["Location"]

    def test_get_oidc_callback_missing_params(self, client):
        resp = client.get("/api/auth/oidc/callback")
        assert resp.status_code == 302
        assert "error=invalid_request" in resp.headers["Location"]

    def test_get_oidc_callback_success(self, client, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        state = oidc_state_store.create_state("code_verifier_999", "https://bazarr/callback")

        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.post(
            "https://auth.example.com/oauth2/token",
            json={"access_token": "acc_tok"},
        )
        requests_mock.get(
            "https://auth.example.com/oauth2/userinfo",
            json={"preferred_username": "charlie"},
        )

        resp = client.get(f"/api/auth/oidc/callback?code=good_code&state={state}")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")

        # Check session
        with client.session_transaction() as sess:
            assert sess.get("logged_in") is True
            assert sess.get("oidc_user") == "charlie"

    def test_get_oidc_callback_alternative_route(self, client, monkeypatch, requests_mock):
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_CLIENT_ID", "bazarr")
        state = oidc_state_store.create_state("code_verifier_888", "https://bazarr/callback")

        requests_mock.get(
            "https://auth.example.com/.well-known/openid-configuration",
            json={
                "authorization_endpoint": "https://auth.example.com/oauth2/auth",
                "token_endpoint": "https://auth.example.com/oauth2/token",
                "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
            },
        )
        requests_mock.post(
            "https://auth.example.com/oauth2/token",
            json={"access_token": "acc_tok"},
        )
        requests_mock.get(
            "https://auth.example.com/oauth2/userinfo",
            json={"preferred_username": "david"},
        )

        resp = client.get(f"/api/auth/callback/oidc?code=good_code&state={state}")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess.get("logged_in") is True
            assert sess.get("oidc_user") == "david"

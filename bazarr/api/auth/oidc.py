# coding=utf-8

import logging
from flask import request, redirect, session
from flask_restx import Resource, Namespace, reqparse

from app.config import base_url
from app.oidc import is_oidc_enabled, get_oidc_config, build_authorization_url, handle_callback

logger = logging.getLogger(__name__)

api_ns_auth_oidc = Namespace('Auth OIDC', description='OpenID Connect Authentication endpoints')

callback_parser = reqparse.RequestParser()
callback_parser.add_argument('code', type=str, required=False, location='args', help='Authorization Code')
callback_parser.add_argument('state', type=str, required=False, location='args', help='State Token')
callback_parser.add_argument('error', type=str, required=False, location='args', help='Error code from IdP')
callback_parser.add_argument('error_description', type=str, required=False, location='args', help='Error description')


@api_ns_auth_oidc.hide
@api_ns_auth_oidc.route('auth/oidc/config')
class OIDCConfigEndpoint(Resource):
    @api_ns_auth_oidc.doc(security=[])
    def get(self):
        """Returns OIDC configuration status for UI"""
        return get_oidc_config(), 200


@api_ns_auth_oidc.hide
@api_ns_auth_oidc.route('auth/oidc/login')
class OIDCLoginEndpoint(Resource):
    @api_ns_auth_oidc.doc(security=[])
    def get(self):
        """Initiates OIDC authorization flow via 302 redirect"""
        if not is_oidc_enabled():
            target_login = f"{base_url.rstrip('/')}/login?error=oidc_disabled"
            return redirect(target_login, code=302)
        try:
            auth_url = build_authorization_url(request=request)
            return redirect(auth_url, code=302)
        except Exception as e:
            logger.error(f"Failed to initiate OIDC login: {e}")
            target_login = f"{base_url.rstrip('/')}/login?error=oidc_init_failed"
            return redirect(target_login, code=302)


@api_ns_auth_oidc.hide
@api_ns_auth_oidc.route('auth/oidc/callback')
@api_ns_auth_oidc.route('auth/callback/oidc')
class OIDCCallbackEndpoint(Resource):
    @api_ns_auth_oidc.doc(security=[], parser=callback_parser)
    def get(self):
        """Handles OIDC authorization callback from Identity Provider"""
        target_login = f"{base_url.rstrip('/')}/login"
        args = callback_parser.parse_args()
        error = args.get('error')
        if error:
            error_desc = args.get('error_description') or error
            logger.warning(f"OIDC IdP returned error: {error} - {error_desc}")
            return redirect(f"{target_login}?error={error}", code=302)

        code = args.get('code')
        state = args.get('state')
        if not code or not state:
            logger.warning("OIDC callback missing required code or state parameter")
            return redirect(f"{target_login}?error=invalid_request", code=302)

        success, err_code, claims = handle_callback(code=code, state=state, request=request)
        if not success:
            logger.warning(f"OIDC callback processing failed: {err_code}")
            return redirect(f"{target_login}?error={err_code or 'oidc_failed'}", code=302)

        # Activate user session
        session['logged_in'] = True
        user_identifier = (
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("name")
            or claims.get("sub")
            or "oidc_user"
        )
        session['oidc_user'] = user_identifier
        session.permanent = True

        logger.info(f"OIDC authentication successful for user: {user_identifier}")
        destination = (base_url.rstrip('/') + '/') if base_url else '/'
        return redirect(destination, code=302)

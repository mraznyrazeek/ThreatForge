
"""
ThreatForge M7.5
Keycloak Authorization Code + PKCE S256 Smoke Test

Validates:
1. Browser-based Keycloak authentication.
2. Authorization Code + PKCE S256 exchange.
3. JWT issuer, audience, and application roles.
4. Successful access to a protected API endpoint.
5. Rejection of the same token after expiration.

Development-only security testing.

Passwords, authorization codes, and access tokens
are never printed or persisted.
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


# --------------------------------------------------
# Configuration
# --------------------------------------------------

ISSUER = (
    "http://localhost:8080"
    "/realms/threatforge"
)

CLIENT_ID = "threatforge-frontend"

API_AUDIENCE = "threatforge-api"

REDIRECT_URI = "http://localhost:5173/"

API_URL = (
    "http://127.0.0.1:5050"
    "/api/v1/intelligence/summary"
)

CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 5173

CALLBACK_TIMEOUT_SECONDS = 180

# Matches the ASP.NET Core ClockSkew setting.
CLOCK_SKEW_SECONDS = 30

# Additional margin to ensure the token is expired
# even if the server clock differs slightly.
EXPIRATION_MARGIN_SECONDS = 5


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def base64url(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(data)
        .decode("ascii")
        .rstrip("=")
    )


def decode_jwt_payload(token: str) -> dict:
    """
    Decode JWT claims for diagnostic purposes.

    This does not cryptographically validate the JWT.
    The ASP.NET Core API performs actual validation.
    """

    segments = token.split(".")

    if len(segments) != 3:
        raise RuntimeError(
            "Access token is not a three-part JWT."
        )

    payload = segments[1]

    payload += "=" * (-len(payload) % 4)

    return json.loads(
        base64.urlsafe_b64decode(payload)
    )


def format_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).isoformat()


def create_http_opener():
    """
    Access local services directly without proxying.
    """

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )


def call_protected_api(
    opener,
    access_token: str
) -> tuple[int, str]:
    """
    Call the protected API and return its HTTP status
    and WWW-Authenticate response header.

    The access token is never printed or saved.
    """

    request = urllib.request.Request(
        API_URL,
        headers={
            "Authorization":
                f"Bearer {access_token}"
        },
        method="GET"
    )

    try:
        with opener.open(
            request,
            timeout=15
        ) as response:
            return (
                response.status,
                response.headers.get(
                    "WWW-Authenticate", ""
                )
            )

    except urllib.error.HTTPError as error:
        return (
            error.code,
            error.headers.get(
                "WWW-Authenticate", ""
            )
        )


# --------------------------------------------------
# Main PKCE flow
# --------------------------------------------------

def main() -> None:

    print("=" * 55)
    print("ThreatForge M7.5 - Keycloak JWT Smoke Test")
    print("=" * 55)

    verifier = secrets.token_urlsafe(64)

    challenge = base64url(
        hashlib.sha256(
            verifier.encode("ascii")
        ).digest()
    )

    state = secrets.token_urlsafe(32)

    authorization_endpoint = (
        ISSUER
        + "/protocol/openid-connect/auth"
    )

    token_endpoint = (
        ISSUER
        + "/protocol/openid-connect/token"
    )

    authorization_url = (
        authorization_endpoint
        + "?"
        + urllib.parse.urlencode(
            {
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
    )

    callback_result = {}

    # ----------------------------------------------
    # Temporary local OAuth callback server
    # ----------------------------------------------

    class CallbackHandler(BaseHTTPRequestHandler):

        def do_GET(self):

            parsed = urllib.parse.urlparse(
                self.path
            )

            if parsed.path != "/":
                self.send_error(404)
                return

            params = urllib.parse.parse_qs(
                parsed.query
            )

            # Ignore unrelated requests, including
            # callbacks with an unexpected OAuth state.
            returned_state = params.get(
                "state", [None]
            )[0]

            if (
                returned_state is None
                or not secrets.compare_digest(
                    state,
                    returned_state
                )
            ):
                self.send_error(400)
                return

            callback_result["params"] = params

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8"
            )

            self.end_headers()

            self.wfile.write(
                b"ThreatForge login callback received. "
                b"You may return to your terminal."
            )

        def log_message(self, format, *args):
            # Prevent OAuth codes from being logged.
            pass

    with HTTPServer(
        (CALLBACK_HOST, CALLBACK_PORT),
        CallbackHandler
    ) as server:

        server.timeout = 1

        print("\n[1] PKCE callback server ready.")
        print("[2] Opening Keycloak login...")

        if not webbrowser.open(authorization_url):
            print(
                "Browser did not open automatically. "
                "Check your default browser settings."
            )
            raise RuntimeError(
                "Could not open Keycloak login."
            )

        deadline = (
            time.monotonic()
            + CALLBACK_TIMEOUT_SECONDS
        )

        while (
            "params" not in callback_result
            and time.monotonic() < deadline
        ):
            server.handle_request()

    # ----------------------------------------------
    # Validate OAuth callback
    # ----------------------------------------------

    params = callback_result.get("params")

    if not params:
        raise RuntimeError(
            "Login callback was not received."
        )

    if "error" in params:
        raise RuntimeError(
            "Keycloak returned an authorization error."
        )

    code = params.get("code", [None])[0]

    if not code:
        raise RuntimeError(
            "Authorization code missing."
        )

    print("[3] Authorization callback received.")

    # ----------------------------------------------
    # Exchange authorization code for access token
    # ----------------------------------------------

    token_request_body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": verifier,
        }
    ).encode("utf-8")

    opener = create_http_opener()

    token_request = urllib.request.Request(
        token_endpoint,
        data=token_request_body,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    with opener.open(
        token_request,
        timeout=15
    ) as response:
        token_data = json.load(response)

    access_token = token_data.get("access_token")

    if not access_token:
        raise RuntimeError(
            "Keycloak did not return an access token."
        )

    print("[4] Keycloak access token received.")

    # ----------------------------------------------
    # Inspect JWT claims
    # ----------------------------------------------

    claims = decode_jwt_payload(
        access_token
    )

    issuer = claims.get("iss")
    audience = claims.get("aud", [])

    if isinstance(audience, str):
        audience = [audience]

    roles = (
        claims.get("resource_access", {})
        .get(API_AUDIENCE, {})
        .get("roles", [])
    )

    expires_at = claims.get("exp")

    print("\nJWT CLAIMS")
    print("-" * 55)

    print("Issuer:", issuer)
    print("Audience:", audience)
    print("API roles:", roles)

    if issuer != ISSUER:
        raise RuntimeError(
            "JWT issuer does not match the expected realm."
        )

    if API_AUDIENCE not in audience:
        raise RuntimeError(
            "JWT does not include the required API audience."
        )

    if "analyst" not in roles:
        raise RuntimeError(
            "JWT does not contain the Analyst role."
        )

    if not isinstance(expires_at, int):
        raise RuntimeError(
            "JWT expiration timestamp is missing or invalid."
        )

    print("Expires at:", format_utc(expires_at))

    # ----------------------------------------------
    # Test 1: Valid JWT
    # ----------------------------------------------

    print("\nTEST 1 - VALID JWT")
    print("-" * 55)

    valid_status, _ = call_protected_api(
        opener,
        access_token
    )

    print("Protected API status:", valid_status)

    if valid_status != 200:
        raise RuntimeError(
            "Valid Keycloak JWT was not accepted."
        )

    print("PASS: Valid JWT accepted.")

    # ----------------------------------------------
    # Test 2: Expired JWT
    # ----------------------------------------------

    print("\nTEST 2 - EXPIRED JWT")
    print("-" * 55)

    # ASP.NET Core may accept a token briefly after
    # its exp timestamp because of ClockSkew.
    #
    # Wait until the expiration time plus that skew
    # and a small safety margin.
    #
    # Retain the original token in memory and do not
    # request a fresh token.

    rejection_time = (
        expires_at
        + CLOCK_SKEW_SECONDS
        + EXPIRATION_MARGIN_SECONDS
    )

    seconds_remaining = max(
        0,
        rejection_time - time.time()
    )

    print(
        "Token expiration:",
        format_utc(expires_at)
    )

    print(
        "Waiting until expiration and clock "
        "tolerance have elapsed."
    )

    if seconds_remaining > 0:
        time.sleep(seconds_remaining)

    print("Reusing the original access token.")

    expired_status, challenge_header = (
        call_protected_api(
            opener,
            access_token
        )
    )

    print(
        "Protected API status:",
        expired_status
    )

    if expired_status != 401:
        raise RuntimeError(
            "Expired JWT was not rejected with HTTP 401."
        )

    if 'invalid_token' not in challenge_header:
        raise RuntimeError(
            "Expired token response did not contain "
            "the expected invalid_token challenge."
        )

    print("PASS: Expired JWT rejected.")

    # ----------------------------------------------
    # Final report
    # ----------------------------------------------

    print("\n" + "=" * 55)
    print("THREATFORGE JWT SECURITY RESULTS")
    print("=" * 55)

    print("PKCE authentication: PASS")
    print("Issuer claim: PASS")
    print("Audience claim: PASS")
    print("Analyst role claim: PASS")
    print("Valid JWT authorization: PASS")
    print("Expired JWT rejection: PASS")

    print("\nAll selected JWT checks passed.")


if __name__ == "__main__":
    main()

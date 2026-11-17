import asyncio
import re
import html
import urllib.parse
import getpass
import sys
import json
import time
import base64
import os
import random
from pathlib import Path
from curl_cffi.requests import AsyncSession

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

async def human_delay(min_ms: int = 800, max_ms: int = 2500):
    delay = random.uniform(min_ms / 1000, max_ms / 1000)
    await asyncio.sleep(delay)


async def get_token(email: str, password: str, debug: bool = False) -> tuple[str, str | None]:
    """Perform the mobile app login using authorization code flow with PKCE.

    This mimics the Android app's OAuth flow:
    1. Start authorization request
    2. Submit credentials via SelfAsserted endpoint
    3. Follow through to get authorization code
    4. Exchange code for access_token
    """
    # The Post login endpoint rejects aiohttp's TLS fingerprint with HTTP 400.
    # Impersonate Chromium so the login and its cookies follow the browser flow.
    async with AsyncSession(impersonate="chrome") as session:

        # Mobile app parameters
        tenant = "f098c632-5a55-45ba-9bf4-c13870157cf1"
        policy = "B2C_1A_signup_signin_mobileapp"
        client_id = "228c4360-3391-4b1c-93a2-e5d7d946b647"
        redirect_uri = "msal228c4360-3391-4b1c-93a2-e5d7d946b647://at.post.app/auth"
        scope = "https://login.post.at/postag/PostApp2.AllAccess openid offline_access profile"

        # Generate PKCE challenge (simplified - using fixed values like the app)
        code_verifier = "FJQiaSFJ7U9gsRn-iZIXgh_maRMPr8-_NBkGyrLSJK0"
        code_challenge = "mcjbXmWvXOmZb_ipZAf37aP4d3QO6mJVjyk7HKnGL00"

        # Step 1: Start authorization
        import uuid
        state = str(uuid.uuid4()) + "-" + str(uuid.uuid4())
        client_request_id = str(uuid.uuid4())

        auth_params = {
            'prompt': 'login',
            'client-request-id': client_request_id,
            'x-client-CPU': 'x86_64',
            'x-client-DM': 'G011A',
            'x-client-MN': 'google',
            'x-client-OS': '28',
            'x-client-SKU': 'MSAL.Android',
            'x-client-Ver': '6.2.0',
            'instance_aware': 'false',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'x-client-WPAvailable': 'false',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': scope,
            'state': state,
        }

        auth_url = f"https://login.post.at/{tenant}/{policy}/oauth2/v2.0/authorize"
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de-AT,de;q=0.9,en-US;q=0.8,en;q=0.7',
            'DNT': '1',
        }

        r = await session.get(auth_url, params=auth_params, headers=headers, allow_redirects=False)
        body = r.text
        if debug:
            print(f"[AUTH DEBUG] Step 1 - Authorization page status: {r.status_code}")

        tx_match = re.search(r'StateProperties=([^&"\']+)', body)
        csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', body)
        if not tx_match or not csrf_match:
            raise RuntimeError("Could not extract tx or csrf_token from authorization page")

        tx = tx_match.group(1)
        csrf_token = csrf_match.group(1)
        if debug:
            # Never print cookie or CSRF values: both can authorize this session.
            print("[AUTH DEBUG] Extracted transaction and CSRF token")
            print(f"[AUTH DEBUG] Cookies after Step 1: {len(session.cookies)}")

        await human_delay(1500, 3500)

        # Step 2: Submit credentials
        selfasserted_url = f"https://login.post.at/{tenant}/{policy}/SelfAsserted"
        selfasserted_params = {
            'tx': f'StateProperties={tx}',
            'p': policy,
        }

        selfasserted_data = {
            'request_type': 'RESPONSE',
            'signInName': email,
            'password': password,
        }

        selfasserted_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'de-AT,de;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-CSRF-TOKEN': csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': auth_url + '?' + urllib.parse.urlencode(auth_params),
        }

        if debug:
            print(f"[AUTH DEBUG] Step 2 - Submitting credentials")

        r = await session.post(selfasserted_url, params=selfasserted_params, data=selfasserted_data, headers=selfasserted_headers)
        text = r.text
        status_code = r.status_code

        if status_code == 400 and debug:
            print(f"[AUTH DEBUG] SelfAsserted response status: {status_code}")
            print(f"[AUTH DEBUG] Response: {text[:200]}")

        try:
            result = json.loads(text)
        except Exception as e:
            if debug:
                print(f"[AUTH DEBUG] Failed to parse JSON: {e}")
            raise RuntimeError(f"SelfAsserted response not JSON (status={status_code}): {text[:500]}")
        if result.get('status') != '200':
            raise RuntimeError(f"Login failed: {result}")

        await human_delay(600, 1200)

        # Step 3: Get authorization code from confirmed endpoint
        if debug:
            print(f"[AUTH DEBUG] Step 3 - Getting authorization code")
        confirmed_url = f"https://login.post.at/{tenant}/{policy}/api/CombinedSigninAndSignup/confirmed"
        confirmed_params = {
            'rememberMe': 'true',
            'csrf_token': csrf_token,
            'tx': f'StateProperties={tx}',
            'p': policy,
        }

        confirmed_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'de-AT,de;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': auth_url + '?' + urllib.parse.urlencode(auth_params),
        }

        r = await session.get(confirmed_url, params=confirmed_params, headers=confirmed_headers, allow_redirects=False)
        if debug:
            print(f"[AUTH DEBUG] Confirmed endpoint status: {r.status_code}")
        if r.status_code != 302:
            if debug:
                print(f"[AUTH DEBUG] Expected redirect, got {r.status_code}")
                print(f"[AUTH DEBUG] Response: {r.text[:500]}")
            raise RuntimeError(f"Expected redirect, got {r.status_code}")

        location = r.headers.get('Location', '')

        # Extract code from redirect: msal...://at.post.app/auth?state=...&code=...
        code_match = re.search(r'[?&]code=([^&]+)', location)
        if not code_match:
            raise RuntimeError("No authorization code in redirect")

        code = urllib.parse.unquote(code_match.group(1))

        # Step 4: Exchange code for tokens
        if debug:
            print(f"[AUTH DEBUG] Step 4 - Exchanging code for tokens")
        token_url = f"https://login.post.at/{tenant}/{policy}/oauth2/v2.0/token"
        token_data = {
            'client-request-id': client_request_id,
            'client_id': client_id,
            'client_info': '1',
            'code': code,
            'code_verifier': code_verifier,
            'grant_type': 'authorization_code',
            'mPKeyAuthHeaderAllowed': 'false',
            'redirect_uri': redirect_uri,
            'scope': scope,
            'x-app-name': 'at.post.app',
            'x-app-ver': '2.8.0',
        }

        token_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'x-client-SKU': 'MSAL.Android',
            'x-client-Ver': '6.2.0',
            'x-client-CPU': 'x86_64',
            'x-client-OS': '28',
            'x-client-DM': 'G011A',
            'x-client-MN': 'google',
            'x-app-name': 'at.post.app',
            'x-app-ver': '2.8.0',
        }

        r = await session.post(token_url, data=token_data, headers=token_headers)
        result = r.json()

        if 'error' in result:
            if debug:
                print(f"[AUTH DEBUG] Token exchange error: {result.get('error')}")
            raise RuntimeError(f"Token exchange error: {result.get('error_description', result.get('error'))}")

        access_token = result.get('access_token')
        if not access_token:
            if debug:
                print(f"[AUTH DEBUG] No access_token in response. Keys: {result.keys()}")
            raise RuntimeError(f"No access_token in response: {result.keys()}")

        refresh_token = result.get('refresh_token')
        if debug:
            print("[AUTH DEBUG] Tokens obtained successfully")
            print(f"[AUTH DEBUG] Has refresh_token: {bool(refresh_token)}")
        return access_token, refresh_token


def get_token_sync(email: str, password: str) -> tuple[str, str | None]:
    return asyncio.run(get_token(email, password))


def load_config(path: str | None = None) -> dict | None:
    if path is None:
        path = DEFAULT_CONFIG_PATH
    p = Path(path)
    if not p.exists():
        return None
    try:
        with p.open('r', encoding='utf-8') as f:
            cfg = json.load(f)
            if cfg.get('password'):
                try:
                    cfg['password'] = base64.b64decode(cfg['password']).decode('utf-8')
                except Exception:
                    pass
            return cfg
    except Exception:
        return None


def build_missing_credentials_message(config_path: str) -> str:
    return (
        "No valid credentials in config and prompting disabled. "
        f"Create/update config at {config_path} with email/password or a valid token/refresh_token."
    )


def save_config(email: str, password: str, path: str | None = None) -> None:
    if path is None:
        path = DEFAULT_CONFIG_PATH
    p = Path(path)
    data = {}
    if p.exists():
        try:
            with p.open('r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            data = {}
    encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    data.update({"email": email, "password": encoded_password})
    with p.open('w', encoding='utf-8') as f:
        json.dump(data, f)


def save_token_data(token: str, refresh_token: str | None = None, path: str | None = None) -> None:
    if path is None:
        path = DEFAULT_CONFIG_PATH
    p = Path(path)
    data = {}
    if p.exists():
        try:
            with p.open('r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            data = {}
    exp = get_token_expiry(token)
    if exp:
        data.update({"token": token, "token_exp": exp})
    else:
        data.update({"token": token})
    if refresh_token:
        data["refresh_token"] = refresh_token
    with p.open('w', encoding='utf-8') as f:
        json.dump(data, f)


def save_token(token: str, refresh_token: str | None = None, path: str | None = None) -> None:
    save_token_data(token, refresh_token, path)


def get_token_expiry(token: str) -> int | None:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        b = parts[1]
        rem = len(b) % 4
        if rem:
            b += '=' * (4 - rem)
        payload = base64.urlsafe_b64decode(b)
        obj = json.loads(payload)
        exp = obj.get('exp')
        if isinstance(exp, int):
            return exp
    except Exception:
        return None
    return None


def is_token_valid(token: str, leeway: int = 60) -> bool:
    exp = get_token_expiry(token)
    if not exp:
        return False
    now = int(time.time())
    return exp > (now + leeway)


async def refresh_access_token(refresh_token: str, config_path: str | None = None, debug: bool = False) -> str:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    tenant = "f098c632-5a55-45ba-9bf4-c13870157cf1"
    policy = "B2C_1A_signup_signin_mobileapp"
    client_id = "228c4360-3391-4b1c-93a2-e5d7d946b647"
    redirect_uri = "msal228c4360-3391-4b1c-93a2-e5d7d946b647://at.post.app/auth"
    scope = "https://login.post.at/postag/PostApp2.AllAccess openid offline_access profile"

    token_url = f"https://login.post.at/{tenant}/{policy}/oauth2/v2.0/token"

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-client-SKU": "MSAL.Android",
        "x-client-Ver": "6.2.0"
    }

    async with AsyncSession(impersonate="chrome") as session:
        r = await session.post(token_url, data=data, headers=headers)
        result = r.json()

        if "error" in result:
            raise RuntimeError(f"Refresh failed: {result.get('error_description', result.get('error'))}")

        if "access_token" not in result:
            raise RuntimeError(f"No access_token in refresh response: {result.keys()}")

        new_access = result["access_token"]
        new_refresh = result.get("refresh_token", refresh_token)

        # Save both tokens
        cfg = load_config(config_path) or {}
        cfg["token"] = new_access
        cfg["token_exp"] = get_token_expiry(new_access)
        cfg["refresh_token"] = new_refresh

        p = Path(config_path)
        with p.open('w', encoding='utf-8') as f:
            json.dump(cfg, f)

        return new_access


def get_token_auto(config_path: str | None = None, prompt: bool = True, save: bool = True) -> str:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    cfg = load_config(config_path)
    # If a valid token is present, return it
    if cfg and cfg.get('token') and is_token_valid(cfg.get('token')):
        return cfg.get('token')

    if cfg and cfg.get('email') and cfg.get('password'):
        try:
            token, refresh_token = get_token_sync(cfg['email'], cfg['password'])
            if save:
                try:
                    save_token_data(token, refresh_token, config_path)
                except Exception:
                    pass
            return token
        except Exception:
            pass

    if not prompt:
        raise RuntimeError(build_missing_credentials_message(config_path))

    try:
        email = input("Email: ").strip()
        password = getpass.getpass("Password: ")
    except (KeyboardInterrupt, EOFError):
        print_error_and_exit("Input cancelled by user", 2)

    if not email or not password:
        print_error_and_exit("Email and password are required")

    token, refresh_token = get_token_sync(email, password)
    if save:
        try:
            save_config(email, password, config_path)
        except Exception:
            pass
        try:
            save_token_data(token, refresh_token, config_path)
        except Exception:
            pass
    return token


async def get_token_auto_async(config_path: str | None = None, prompt: bool = True, save: bool = True, use_config_first: bool = True, debug: bool = False) -> str:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    cfg = load_config(config_path) if use_config_first else None

    # Debug logging only if enabled
    if debug and cfg:
        print(f"[AUTH DEBUG] Config loaded from: {config_path}")
        print(f"[AUTH DEBUG] Config has email: {bool(cfg.get('email'))}")
        print(f"[AUTH DEBUG] Config has password: {bool(cfg.get('password'))}")
        print(f"[AUTH DEBUG] Config has token: {bool(cfg.get('token'))}")
        print(f"[AUTH DEBUG] Config has refresh_token: {bool(cfg.get('refresh_token'))}")
        if cfg.get('token'):
            token_valid = is_token_valid(cfg.get('token'))
            print(f"[AUTH DEBUG] Token is valid: {token_valid}")
            if not token_valid:
                exp = get_token_expiry(cfg.get('token'))
                if exp:
                    remaining = exp - int(time.time())
                    print(f"[AUTH DEBUG] Token expired {-remaining} seconds ago" if remaining < 0 else f"[AUTH DEBUG] Token expires in {remaining} seconds")
    elif debug and not cfg:
        print(f"[AUTH DEBUG] No config found at: {config_path}")

    # 1. If config contains a valid token, return it
    if cfg and cfg.get('token') and is_token_valid(cfg.get('token')):
        if debug:
            print("[AUTH DEBUG] Using valid token from config")
        return cfg.get('token')

    # 2. If we have a refresh_token, try to refresh
    if cfg and cfg.get('refresh_token'):
        if debug:
            print("[AUTH DEBUG] Attempting token refresh with refresh_token")
        try:
            new_token = await refresh_access_token(cfg['refresh_token'], config_path, debug=debug)
            if debug:
                print("[AUTH DEBUG] ✅ Token refreshed successfully")
            return new_token
        except Exception as e:
            if debug:
                print(f"[AUTH DEBUG] ❌ Refresh failed: {e}")

    # 3. If we have email + password, try full login
    if cfg and cfg.get('email') and cfg.get('password'):
        if debug:
            print("[AUTH DEBUG] Attempting full login with email/password")
        try:
            token, refresh_token = await get_token(cfg['email'], cfg['password'], debug=debug)
            if debug:
                print("[AUTH DEBUG] ✅ Full login successful")
            if save:
                try:
                    save_token_data(token, refresh_token, config_path)
                    if debug:
                        print("[AUTH DEBUG] Token and refresh_token saved")
                except Exception as e:
                    if debug:
                        print(f"[AUTH DEBUG] Failed to save token: {e}")
            return token
        except Exception as e:
            if debug:
                print(f"[AUTH DEBUG] ❌ Full login failed: {e}")
            # In unattended mode, keep the real, non-secret OAuth error. The old
            # fallback below incorrectly reported that configured credentials
            # were missing even when the server had rejected the login request.
            if not prompt:
                raise RuntimeError(f"OAuth login failed: {e}") from e

    if not prompt:
        raise RuntimeError(build_missing_credentials_message(config_path))

    try:
        # input() and getpass are blocking; run them in thread to avoid blocking event loop
        loop = asyncio.get_running_loop()
        email = await loop.run_in_executor(None, lambda: input("Email: ").strip())
        password = await loop.run_in_executor(None, getpass.getpass)
    except (KeyboardInterrupt, EOFError):
        print_error_and_exit("Input cancelled by user", 2)

    if not email or not password:
        print_error_and_exit("Email and password are required")

    token, refresh_token = await get_token(email, password)
    if save:
        try:
            save_config(email, password, config_path)
        except Exception:
            pass
        try:
            save_token_data(token, refresh_token, config_path)
        except Exception:
            pass
    return token


def print_error_and_exit(msg: str, code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


if __name__ == '__main__':
    try:
        token = get_token_auto()
        print(token)
    except Exception as exc:
        print_error_and_exit(str(exc))

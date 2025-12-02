# Minecraft Authentication Script - Python Version
# Standardized with English comments and messages

import http.server
import socketserver
import webbrowser
import json
import base64
import hashlib
import secrets
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode
from threading import Thread, Event, Lock
import requests

# Configuration
CLIENT_ID = '4a07b708-b86d-4365-a55f-f4f23ecb85ab'
REDIRECT_URI = 'http://localhost:3000/proxy/'
SCOPE = 'XboxLive.signin offline_access'

# OAuth endpoints
AUTHORIZE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize'
TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token'
XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate'
XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize'
MC_LOGIN_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox'
MC_ENTITLEMENTS_URL = 'https://api.minecraftservices.com/entitlements/mcstore'
PROFILE_URL = 'https://api.minecraftservices.com/minecraft/profile'


# Generate random string
def generate_random_string(length):
    return secrets.token_hex(length // 2 + 1)[:length]


# Generate Code Challenge for PKCE
def generate_code_challenge(code_verifier):
    sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    challenge = base64.urlsafe_b64encode(sha256).decode('utf-8')
    return challenge.replace('=', '')


# PKCE
CODE_VERIFIER = generate_random_string(32)
CODE_CHALLENGE = generate_code_challenge(CODE_VERIFIER)


# Global state with thread safety
class AuthState:
    def __init__(self):
        self.auth_data = None
        self.data_endpoint = None
        self.lock = Lock()

    def set_auth_data(self, auth_data, data_endpoint):
        with self.lock:
            self.auth_data = auth_data
            self.data_endpoint = data_endpoint

    def get_auth_data(self):
        with self.lock:
            return self.auth_data

    def get_data_endpoint(self):
        with self.lock:
            return self.data_endpoint


# Global state instance
auth_state = AuthState()
shutdown_event = Event()


# Generate authorization URL
def generate_authorize_url():
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'code_challenge': CODE_CHALLENGE,
        'code_challenge_method': 'S256',
        'prompt': 'select_account',
    }

    return f"{AUTHORIZE_URL}?{urlencode(params)}"


# Exchange authorization code for tokens
def exchange_code_for_token(auth_code):
    params = {
        'client_id': CLIENT_ID,
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'code_verifier': CODE_VERIFIER,
    }

    try:
        response = requests.post(TOKEN_URL, data=params, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle error response
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                raise Exception(f"Token exchange failed: {error_data}")
            except:
                raise Exception(f"Token exchange failed: {e.response.text}")
        raise e


# Xbox Live authentication
def authenticate_xbox_live(access_token):
    def try_authenticate(rps_ticket):
        data = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": rps_ticket
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }

        try:
            response = requests.post(XBL_AUTH_URL, json=data, headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # Return error message instead of exception object
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = str(error_data)
                except:
                    error_msg = e.response.text
            return {"error": error_msg}

    result = try_authenticate(f"d={access_token}")
    if "error" not in result:
        return result

    result = try_authenticate(access_token)
    if "error" not in result:
        return result

    raise Exception(f"Xbox Live authentication failed: {result.get('error', 'Unknown error')}")


# XSTS authentication
def authenticate_xsts(xbl_token):
    data = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }

    try:
        response = requests.post(XSTS_AUTH_URL, json=data, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                raise Exception(f"XSTS authentication failed: {error_data}")
            except:
                raise Exception(f"XSTS authentication failed: {e.response.text}")
        raise e


# Login to Minecraft with Xbox
def login_with_xbox(user_hash, xsts_token):
    data = {
        "identityToken": f"XBL3.0 x={user_hash};{xsts_token}"
    }

    try:
        response = requests.post(MC_LOGIN_URL, json=data, headers={
            'Content-Type': 'application/json'
        })
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                raise Exception(f"Minecraft login failed: {error_data}")
            except:
                raise Exception(f"Minecraft login failed: {e.response.text}")
        raise e


# Check Minecraft game ownership
def check_game_ownership(mc_access_token):
    try:
        response = requests.get(MC_ENTITLEMENTS_URL, headers={
            'Authorization': f'Bearer {mc_access_token}'
        })
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                raise Exception(f"Ownership check failed: {error_data}")
            except:
                raise Exception(f"Ownership check failed: {e.response.text}")
        raise e


# Get Minecraft player profile
def get_minecraft_profile(mc_access_token):
    try:
        response = requests.get(PROFILE_URL, headers={
            'Authorization': f'Bearer {mc_access_token}',
        })
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                raise Exception(f"Profile fetch failed: {error_data}")
            except:
                raise Exception(f"Profile fetch failed: {e.response.text}")
        raise e


# Custom HTTP request handler
# noinspection PyTypeChecker
class AuthRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Handle callback
        if self.path.startswith('/proxy/'):
            query_components = parse_qs(urlparse(self.path).query)
            auth_code = query_components.get('code')

            if auth_code and len(auth_code) > 0:
                auth_code = auth_code[0]
                try:
                    print('[1/6] Exchanging authorization code for Microsoft token...')
                    token_data = exchange_code_for_token(auth_code)
                    access_token = token_data['access_token']

                    print('[2/6] Xbox Live authentication...')
                    xbl_data = authenticate_xbox_live(access_token)
                    xbl_token = xbl_data['Token']
                    user_hash = xbl_data['DisplayClaims']['xui'][0]['uhs']

                    print('[3/6] XSTS authentication...')
                    xsts_data = authenticate_xsts(xbl_token)
                    xsts_token = xsts_data['Token']

                    print('[4/6] Getting Minecraft access token...')
                    mc_token_data = login_with_xbox(user_hash, xsts_token)
                    mc_access_token = mc_token_data['access_token']

                    print('[5/6] Checking game ownership...')
                    entitlements = check_game_ownership(mc_access_token)
                    if len(entitlements['items']) == 0:
                        raise Exception('This account does not own Minecraft')

                    print('[6/6] Getting Minecraft profile...')
                    profile = get_minecraft_profile(mc_access_token)

                    # Use player UUID as path name
                    player_uuid = profile['id']
                    data_endpoint = f'/data/{player_uuid}.json'

                    # Store data in shared state
                    auth_data = {
                        "tokens": {
                            "microsoft_access_token": access_token,
                            "microsoft_refresh_token": token_data.get('refresh_token', ''),
                            "xbl_token": xbl_token,
                            "xsts_token": xsts_token,
                            "minecraft_access_token": mc_access_token,
                            "expires_in": mc_token_data.get('expires_in', 0),
                        },
                        "profile": profile,
                        "pkce": {
                            "code_verifier": CODE_VERIFIER,
                            "code_challenge": CODE_CHALLENGE,
                        },
                    }

                    auth_state.set_auth_data(auth_data, data_endpoint)

                    print('\nDone.')
                    print('\nData access URL:')
                    print(f'http://localhost:{PORT}{data_endpoint}')
                    print('Press Enter to exit, or keep server running to access data')

                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'Authentication successful! Please check console for results.')

                    # Setup key press exit in a separate thread
                    Thread(target=setup_key_press_exit, daemon=True).start()

                except Exception as e:
                    error_msg = str(e)
                    print(f'Authentication failed: {error_msg}')
                    self.send_response(500)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f'Authentication failed: {error_msg}'.encode())
            else:
                self.send_response(400)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Authorization code not received')

        # Handle data endpoint
        else:
            # Get current data endpoint from shared state
            current_data_endpoint = auth_state.get_data_endpoint()

            if current_data_endpoint and self.path == current_data_endpoint:
                current_auth_data = auth_state.get_auth_data()
                if current_auth_data:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(current_auth_data).encode())
                else:
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'Data not found or expired')
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass


# Setup key press exit
def setup_key_press_exit():
    print('\nPress Enter to exit...')
    input()
    print('Exiting program')
    shutdown_event.set()


# Start server
# noinspection PyTypeChecker
def start_server():
    with socketserver.TCPServer(("", PORT), AuthRequestHandler) as httpd:
        httpd.timeout = 0.5  # Set timeout to handle shutdown quickly
        print(f'Server started on port: {PORT}')
        print('Please visit the following URL for authorization:')
        print(auth_url)
        print('Waiting for authorization...')

        # Open browser automatically
        try:
            webbrowser.open(auth_url)
        except:
            print("Could not open browser automatically. Please open the URL manually.")

        # Serve until shutdown event is set
        while not shutdown_event.is_set():
            try:
                httpd.handle_request()
            except Exception as e:
                # Ignore socket errors during shutdown
                if not shutdown_event.is_set():
                    print(f"Server error: {e}")

        print("Server shutting down...")
        httpd.server_close()


if __name__ == '__main__':
    PORT = 3000
    auth_url = generate_authorize_url()

    # Start server in a separate thread
    server_thread = Thread(target=start_server, daemon=True)
    server_thread.start()

    # Keep main thread alive until shutdown
    try:
        while not shutdown_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print('\nExiting program (Ctrl+C)')
        shutdown_event.set()

    # Wait for server thread to finish
    server_thread.join(timeout=2.0)
    sys.exit(0)
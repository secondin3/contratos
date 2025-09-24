import msal
import jwt
from flask import Flask, redirect, url_for, session, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user
from dotenv import load_dotenv
import os
from flask_talisman import Talisman
from datetime import datetime, timedelta
from functools import wraps

load_dotenv()

app = Flask(__name__)
Talisman(app)
app.secret_key = os.getenv("FLASK_SECRET", "your_secret_key")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Configurações Azure AD
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTHORITY = os.getenv('AUTHORITY')  # Ex: "https://login.microsoftonline.com/<tenant_id>"
REDIRECT_PATH = '/getAToken'
SCOPE = ['User.Read']
SESSION_TYPE = 'filesystem'

# Segredo para assinar JWT interno
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-super-secret")


# ---------------------------
# Decorator para proteger rotas com JWT
# ---------------------------
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token ausente"}), 401
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------
# Rotas de login/logout
# ---------------------------

@app.route('/login')
def login():
    # Força HTTPS em ambientes com proxy/reverse proxy
    if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

    session["flow"] = _build_auth_code_flow(scopes=SCOPE)
    return redirect(session["flow"]["auth_uri"])


@app.route(REDIRECT_PATH)
def authorized():
    try:
        result = _build_msal_app().acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args
        )
        if "error" in result:
            return "Login falhou: " + result.get("error_description")

        # ID do usuário no Azure AD
        user_id = result.get("id_token_claims").get("oid")
        session["user_id"] = user_id
        login_user(User(user_id))

        # Cria um JWT interno para o React
        internal_token = jwt.encode(
            {
                "sub": user_id,
                "exp": datetime.utcnow() + timedelta(hours=1)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        # Redireciona o usuário pro React com o token na URL
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return redirect(f"{frontend_url}/#/callback?token={internal_token}")

    except ValueError:
        return "Erro na autorização", 400


@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect("https://www.elopar.com.br")


# ---------------------------
# Helpers internos MSAL
# ---------------------------

def _build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
        token_cache=cache
    )

def _build_auth_code_flow(scopes=None):
    return _build_msal_app().initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for('authorized', _external=True, _scheme='https')
    )

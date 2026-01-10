import os
import sqlite3
import jwt
import logging
from functools import wraps
from flask import Flask, request, render_template, jsonify, send_file, abort
from flask_cors import CORS
from dotenv import load_dotenv
from waitress import serve

# Налаштування логування (замість print)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# Конфігурація з .env
BANS_DB = os.getenv("BANS_DB_NAME", "bans.db")
SECRET = os.getenv("FLASK_SECRET", "PRODUCTION_SECRET_KEY_HERE")
PNUM = os.getenv("PNUM", "0")

app = Flask(__name__)

# Налаштування CORS
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "Authorization"], origins=["127.0.0.1:51011"])

def init_db():
    """Ініціалізація бази даних при старті"""
    try:
        with sqlite3.connect(BANS_DB) as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT
                )
            """)
    except Exception as e:
        logger.error(f"Database init error: {e}")

init_db()

@app.before_request
def check_ban():
    """Перевірка IP на бан перед кожним запитом"""
    if request.path.startswith('/static'):
        return

    ip = request.remote_addr
    try:
        with sqlite3.connect(BANS_DB) as con:
            cur = con.cursor()
            cur.execute("SELECT 1 FROM banned_ips WHERE ip=?", (ip,))
            if cur.fetchone():
                return render_template("pages/forbidden.html"), 403
    except sqlite3.Error as e:
        logger.error(f"DB Error in check_ban: {e}")

def get_user_from_cookie():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return {"id": payload.get("user_id"), "username": payload.get("username")}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_user_from_cookie()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.user = user
        return f(*args, **kwargs)
    return wrapper

# --- РУТИ ---

@app.route("/")
def home():
    return render_template("pages/crossroad.html")

@app.route("/login")
def login_page(): return render_template("pages/login.html")

@app.route("/register")
def register_page(): return render_template("pages/register.html")

@app.route("/main")
@require_auth
def main_page():
    return render_template("pages/main.html")

@app.route("/account")
@require_auth
def account():
    return render_template("pages/management.html")

@app.route("/api/get-prime-p")
def returnpnum():
    return jsonify({'number': PNUM})

@app.route("/getbackground")
def getbackground():
    # Безпечне відправлення файлу
    bg_path = os.path.join('static', 'images.jpg')
    if os.path.exists(bg_path):
        return send_file(bg_path, mimetype='image/jpeg')
    abort(404)

@app.route("/scriptget/<path:scriptname>")
@require_auth
def scriptget(scriptname):
    """Безпечне отримання JS скриптів"""
    # Захист від '../' (Directory Traversal)
    safe_name = os.path.basename(scriptname).replace('.js', '') + '.js'
    script_path = os.path.join('scripts', safe_name)

    if os.path.exists(script_path):
        return send_file(script_path, mimetype='application/javascript')
    
    return "Script not found", 404

# Сторінки помилок (опціонально)
@app.route("/recovery")
def recovery(): return render_template('pages/recovery.html')

@app.route("/encountered-error")
def encountered_error_page(): return render_template('pages/encountered_error.html')

# ВАЖЛИВО: Для Waitress ми не використовуємо app.run() всередині скрипта для запуску, 
# але залишаємо цей блок для зручності розробки.
if __name__ == "__main__":
    #app.run(host="0.0.0.0", port=51011)
    serve(app, host="0.0.0.0", port=51011)
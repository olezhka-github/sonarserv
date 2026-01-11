import os
import re
import json
import logging
import bcrypt
import jwt
import psycopg2
import threading  # Для фонової відправки пошти
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from dotenv import load_dotenv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# -------------------------
# CONFIG & LOGGING
# -------------------------
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("INTERNAL_DATABASE_URL") or os.getenv("DATABASE_URL")
SECRET = os.getenv("FLASK_SECRET")
BASE_URL = os.getenv("BASE_URL")
PNUM = int(os.getenv("PNUM", 0))
GMAIL_USER = os.getenv("GMAIL_EMAIL")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

if not all([DATABASE_URL, SECRET, GMAIL_USER, GMAIL_APP_PASSWORD]):
    logger.critical("Missing essential environment variables! Check .env")
    exit(1)

app = Flask(__name__)

ALLOWED_ORIGINS = [
    "http://127.0.0.1:51011", 
    "http://localhost:51011", 
    "http://localhost:3000", 
    "http://localhost:5001",
    "https://sonarserv.onrender.com"
]

CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}}, 
     supports_credentials=True, 
     allow_headers=["Content-Type", "Authorization"], 
     methods=["GET", "POST", "OPTIONS"])

app.config["SECRET_KEY"] = SECRET

# -------------------------
# DATABASE HELPER
# -------------------------
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    conn.set_client_encoding('UTF8')
    return conn

def init_dbs():
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    password BYTEA NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    last_online BIGINT DEFAULT 0,
                    created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
                    profile_data TEXT DEFAULT '{}',
                    is_banned INTEGER DEFAULT 0
                );
                """)
                cur.execute("CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, participants TEXT);")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id SERIAL PRIMARY KEY,
                        chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
                        sender VARCHAR(255),
                        content TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS banned_ips (
                        id SERIAL PRIMARY KEY,
                        ip VARCHAR(50) UNIQUE,
                        reason TEXT
                    );
                """)
            con.commit()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"DB Init Error: {e}")

init_dbs()

# -------------------------
# MAIL HELPER (REWORKED)
# -------------------------
def send_verification_email_sync(email: str, token: str):
    """Синхронна функція відправки (викликається в потоці)"""
    try:
        verification_link = f"{BASE_URL}/api/verify-email?token={token}"
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Verify your email - Sonar"
        msg['From'] = GMAIL_USER
        msg['To'] = email

        html = f"<h3>Welcome!</h3><br/>Click here to verify: <a href='{verification_link}'>VERIFY EMAIL</a>"
        text = f"Verification Link: {verification_link}"

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Використовуємо порт 587 і STARTTLS (надійніше для Render)
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as server:
            server.starttls() 
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, email, msg.as_string())

        logger.info(f"Email successfully sent to {email}")
    except Exception as e:
        logger.error(f"Email sending failed for {email}: {e}")

def send_verification_email(email: str, token: str):
    """Запускає відправку листа в окремому потоці"""
    thread = threading.Thread(target=send_verification_email_sync, args=(email, token))
    thread.start()

# -------------------------
# UTILS & MIDDLEWARE
# -------------------------
def validate_username(username: str) -> bool:
    if not username or not (3 <= len(username) <= 16): return False
    return re.match(r"^[A-Za-z0-9._]+$", username) is not None

def validate_email(email: str) -> bool:
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email) is not None

@app.before_request
def check_ban():
    if request.method == "OPTIONS": return
    ip = request.remote_addr
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("SELECT 1 FROM banned_ips WHERE ip=%s", (ip,))
                if cur.fetchone():
                    return jsonify({"success": False, "message": "IP banned"}), 403
    except Exception as e:
        logger.error(f"Ban check error: {e}")

def get_user_from_cookie():
    token = request.cookies.get('token')
    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith("Bearer "):
             token = auth_header.split(" ")[1]
    if not token: return None
    
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("type") == "verification": return None
        return {"id": payload.get("user_id"), "username": payload.get("username")}
    except:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS": return make_response()
        user = get_user_from_cookie()
        if not user:
            return jsonify({"success": False, "message": "Not authenticated"}), 401
        request.user = user
        return f(*args, **kwargs)
    return wrapper

# -------------------------
# ROUTES
# -------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not validate_username(username) or not validate_email(email) or not password:
        return jsonify({"success": False, "message": "Invalid input data"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO users(username, email, password, is_verified) VALUES (%s, %s, %s, 0) RETURNING id", 
                    (username, email, hashed)
                )
                con.commit()
                
        # Створення токена
        verification_token = jwt.encode({
            "sub": email,
            "type": "verification",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        }, SECRET, algorithm="HS256")

        # Відправка пошти у ФОНІ (не блокує відповідь сервера)
        send_verification_email(email, verification_token)
        
        return jsonify({"success": True, "message": "Registration successful. Please check your email."}), 201

    except psycopg2.errors.UniqueViolation:
        return jsonify({"success": False, "message": "Username or Email already taken"}), 409
    except Exception as e:
        logger.error(f"Register Error: {e}")
        return jsonify({"success": False, "message": "Database error"}), 500

@app.route("/api/verify-email", methods=["GET"])
def verify_email_endpoint():
    token = request.args.get('token')
    if not token: return jsonify({"success": False, "message": "Missing token"}), 400

    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("type") != "verification": raise jwt.InvalidTokenError
        email = payload.get("sub")
        
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE users SET is_verified=1 WHERE email=%s", (email,))
                con.commit()
        
        return "<h1>Email successfully verified! You can login now.</h1>"
    except Exception as e:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("SELECT id, password, is_verified FROM users WHERE username=%s", (username,))
                row = cur.fetchone()

        if not row or not bcrypt.checkpw(password.encode(), bytes(row['password'])):
            return jsonify({"success": False, "err": "wrong_credentials"}), 401

        if row['is_verified'] == 0:
            return jsonify({"sonarcode": "IAR002", "message": "Email not verified"}), 403

        new_token = jwt.encode({
            "user_id": row['id'],
            "username": username,
            "type": "login",
            "exp": datetime.now(timezone.utc) + timedelta(days=30)
        }, SECRET, algorithm="HS256")

        resp = make_response(jsonify({
            "success": True, 
            "token": new_token, 
            "user": {"id": row['id'], "username": username}
        }))
        resp.set_cookie('token', new_token, max_age=60*60*24*30, httponly=True, samesite='Lax')
        return resp
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/chats", methods=["GET"])
@require_auth
def get_chats():
    current_user = request.user['username']
    user_chats = []
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("SELECT * FROM chats")
                all_chats = cur.fetchall()
                for chat in all_chats:
                    participants = json.loads(chat['participants'])
                    if current_user in participants:
                        cur.execute("SELECT content FROM messages WHERE chat_id=%s ORDER BY id DESC LIMIT 1", (chat['id'],))
                        last_msg = cur.fetchone()
                        user_chats.append({
                            "id": chat['id'],
                            "name": next((p for p in participants if p != current_user), "Self"),
                            "last_message": last_msg['content'] if last_msg else "No messages",
                            "participants": participants
                        })
        return jsonify({"success": True, "chats": user_chats})
    except Exception as e:
        return jsonify({"success": False}), 500

if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting API Server on port 5001...")
    serve(app, host="0.0.0.0", port=5001, threads=8)

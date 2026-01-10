import os
import re
import json
import logging
import bcrypt
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from dotenv import load_dotenv
from mailjet_rest import Client

# -------------------------
# CONFIG & LOGGING
# -------------------------
load_dotenv()

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Змінні середовища
INTERNAL_URL = os.getenv("INTERNAL_DATABASE_URL")
DATABASE_URL = os.getenv("DATABASE_URL", INTERNAL_URL)
SECRET = os.getenv("FLASK_SECRET")
BASE_URL = os.getenv("BASE_URL")
PNUM = int(os.getenv("PNUM"))

# Mailjet Config
MAILJET_API_KEY = os.getenv("MAILJET_API_KEY")
MAILJET_API_SECRET = os.getenv("MAILJET_API_SECRET")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

# Перевірка критичних змінних
if not all([DATABASE_URL, SECRET, MAILJET_API_KEY, MAILJET_API_SECRET, SENDER_EMAIL]):
    logger.critical("Missing essential environment variables! Check .env")
    exit(1)

app = Flask(__name__)

# Налаштування CORS (Додайте свої продакшн домени сюди)
ALLOWED_ORIGINS = [
    "http://127.0.0.1:51011", 
    "http://localhost:51011", 
    "http://localhost:3000", 
    "http://localhost:5001"
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
    """Створює з'єднання з PostgreSQL"""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    conn.set_client_encoding('UTF8')
    return conn

def init_dbs():
    """Ініціалізація таблиць"""
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                # Users
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
                    is_banned INTEGER DEFAULT 0,
                );
                """)
                # Chats
                cur.execute("CREATE TABLE IF NOT EXISTS chats (id SERIAL PRIMARY KEY, participants TEXT);")
                # Messages
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id SERIAL PRIMARY KEY,
                        chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
                        sender VARCHAR(255),
                        content TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                # Bans
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

# Викликаємо ініціалізацію при запуску
init_dbs()

# -------------------------
# MAIL HELPER
# -------------------------
def send_verification_email(email: str, token: str):
    try:
        mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_API_SECRET), version='v3.1')
        verification_link = f"{BASE_URL}/api/verify-email?token={token}"
        
        data = {
          'Messages': [
            {
              "From": {"Email": SENDER_EMAIL, "Name": "Service Auth"},
              "To": [{"Email": email, "Name": "User"}],
              "Subject": "Verify your email",
              "HTMLPart": f"<h3>Welcome!</h3><br/>Click here to verify: <a href='{verification_link}'>VERIFY EMAIL</a>",
              "TextPart": f"Verification Link: {verification_link}"
            }
          ]
        }
        result = mailjet.send.create(data=data)
        if result.status_code != 200:
            logger.error(f"Mailjet Error: {result.json()}")
        else:
            logger.info(f"Email sent to {email}")
    except Exception as e:
        logger.error(f"Email sending failed: {e}")

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
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    except Exception as e:
        logger.error(f"Auth decode error: {e}")
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
# ROUTES: AUTH
# -------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not validate_username(username):
        return jsonify({"success": False, "message":"Username format invalid."}), 400
    if not email or not validate_email(email):
        return jsonify({"success": False, "message":"Invalid email format."}), 400
    if not password:
        return jsonify({"success": False, "message": "Missing password"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO users(username, email, password, is_verified) VALUES (%s, %s, %s, 0) RETURNING id", 
                    (username, email, hashed)
                )
                con.commit()
    except psycopg2.errors.UniqueViolation:
        return jsonify({"success": False, "message": "Username or Email already taken"}), 409
    except Exception as e:
        logger.error(f"Register DB Error: {e}")
        return jsonify({"success": False, "message": "Database error"}), 500
    
    # Send Email
    verification_token = jwt.encode({
        "sub": email,
        "type": "verification",
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }, SECRET, algorithm="HS256")
    
    send_verification_email(email, verification_token)
    
    return jsonify({"success": True, "message": "User created. Check email."}), 201

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
        
        return "<h1>Email successfully verified! You can close this page and login.</h1>"

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
         return jsonify({"success": False, "message": "Missing fields"}), 400

    with get_db_connection() as con:
        with con.cursor() as cur:
            cur.execute("SELECT id, password, is_verified FROM users WHERE username=%s", (username,))
            row = cur.fetchone()

    if not row:
        return jsonify({"success": False, "err": "user_not_found"}), 404

    if not bcrypt.checkpw(password.encode(), bytes(row['password'])):
        return jsonify({"success": False, "err": "wrong_pass"}), 401

    if row['is_verified'] == 0:
        return jsonify({"sonarcode": "IAR002", "message": "Must verify email."}), 102

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
    resp.set_cookie('token', new_token, max_age=60*60*24*7, httponly=True, secure=False) # secure=True for HTTPS
    return resp

@app.route("/api/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie('token', '', max_age=0, httponly=True) 
    return resp

# -------------------------
# ROUTES: USER & CHAT
# -------------------------
@app.route("/api/ping", methods=["POST"])
@require_auth
def ping():
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE users SET last_online=%s WHERE id=%s", 
                           (int(datetime.now(timezone.utc).timestamp()), request.user['id']))
                con.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Ping error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/get_p_num")
def return_p_number():
    return jsonify({"success":True,"number": PNUM})

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
                    try:
                        participants = json.loads(chat['participants'])
                        if current_user in participants:
                            # Оптимізований запит останнього повідомлення
                            cur.execute("SELECT content FROM messages WHERE chat_id=%s ORDER BY id DESC LIMIT 1", (chat['id'],))
                            last_msg = cur.fetchone()
                            last_text = last_msg['content'] if last_msg else "No messages"
                            
                            other_user = next((p for p in participants if p != current_user), "Unknown")
                            user_chats.append({
                                "id": chat['id'],
                                "name": other_user,
                                "last_message": last_text,
                                "participants": participants
                            })
                    except ValueError: continue
    except Exception as e:
        logger.error(f"Get chats error: {e}")
        return jsonify({"success": False}), 500

    return jsonify({"success": True, "chats": user_chats})

@app.route("/api/chat/create", methods=["POST"])
@require_auth
def create_chat():
    target_user = request.json.get("target_user")
    me = request.user['username']
    if not target_user: return jsonify({"success": False}), 400

    participants_json = json.dumps(sorted([me, target_user]))

    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("SELECT id FROM chats WHERE participants = %s", (participants_json,))
                existing = cur.fetchone()
                
                if existing:
                    return jsonify({"success": True, "chat_id": existing['id']}), 200
                
                cur.execute("INSERT INTO chats (participants) VALUES (%s) RETURNING id", (participants_json,))
                new_id = cur.fetchone()['id']
                con.commit()
                return jsonify({"success": True, "chat_id": new_id}), 201
    except Exception as e:
        logger.error(f"Create chat error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/chat/<int:chat_id>", methods=["GET"])
@require_auth
def get_messages(chat_id):
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("SELECT participants FROM chats WHERE id=%s", (chat_id,))
                chat = cur.fetchone()
                
                if not chat: return jsonify({"success": False}), 404
                
                if request.user['username'] not in json.loads(chat['participants']):
                    return jsonify({"success": False, "message": "Access denied"}), 403

                cur.execute("SELECT sender, content, timestamp FROM messages WHERE chat_id=%s ORDER BY id ASC", (chat_id,))
                msgs = [{"from": row['sender'], "text": row['content'], "time": str(row['timestamp'])} for row in cur.fetchall()]
                
                return jsonify({"success": True, "messages": msgs})
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/chat/send", methods=["POST"])
@require_auth
def send_message():
    data = request.json
    chat_id = data.get("chat_id")
    text = data.get("text")
    if not chat_id or not text: return jsonify({"success": False}), 400
    
    try:
        with get_db_connection() as con:
            with con.cursor() as cur:
                cur.execute("INSERT INTO messages (chat_id, sender, content) VALUES (%s, %s, %s)", 
                           (chat_id, request.user['username'], text))
                con.commit()
        return jsonify({"success": True}), 201
    except Exception as e:
        logger.error(f"Send message error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"success": True, "user": request.user})

# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting API Server with Waitress on port 5001...")
    # Обов'язково вкажіть threads, оскільки Postgres блокує з'єднання
    serve(app, host="0.0.0.0", port=5001, threads=4)
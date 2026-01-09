from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime, timedelta

# -------------------- App setup --------------------

app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "dev-secret-change-this"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

jwt = JWTManager(app)

DB_PATH = "lilygram.db"

# -------------------- Database --------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            visibility TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

# -------------------- Auth --------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

    return jsonify({"success": True}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=user["id"])
    return jsonify({"token": token})


# -------------------- Posts --------------------

@app.route("/api/posts", methods=["GET"])
def get_posts():
    conn = get_db()
    rows = conn.execute(
        "SELECT content, visibility, created_at FROM posts ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    posts = [dict(r) for r in rows if r["visibility"] == "Everyone"]
    return jsonify(posts)


@app.route("/api/posts", methods=["POST"])
@jwt_required()
def create_post():
    data = request.get_json()
    content = data.get("content", "").strip()
    visibility = data.get("visibility", "Everyone")

    if not content:
        return jsonify({"error": "Empty post"}), 400

    user_id = get_jwt_identity()

    conn = get_db()
    conn.execute(
        "INSERT INTO posts (user_id, content, visibility, created_at) VALUES (?, ?, ?, ?)",
        (user_id, content, visibility, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True}), 201


# -------------------- Run --------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


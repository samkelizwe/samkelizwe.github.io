from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.environ.get('LILY_DB_PATH', 'lilygram.db')

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
jwt = JWTManager(app)

# DB helpers
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript('''
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
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        invite_only INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    conn.commit()
    conn.close()

# initialize if DB missing
if not os.path.exists(DB_PATH):
    init_db()

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                    (username, generate_password_hash(password), datetime.utcnow().isoformat()))
        user_id = cur.lastrowid
        cur.execute('INSERT INTO settings (user_id, invite_only) VALUES (?, 0)', (user_id,))
        conn.commit()
        return jsonify({'success': True}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    conn = get_db()
    user = conn.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password_hash'], password):
        token = create_access_token(identity=user['id'])
        return jsonify({'success': True, 'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = get_db()
    rows = conn.execute('''
        SELECT p.id, p.content, p.visibility, p.created_at, u.username
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ''').fetchall()
    conn.close()
    posts = [dict(r) for r in rows if r['visibility'] == 'Everyone']
    return jsonify(posts)

@app.route('/api/posts', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    visibility = data.get('visibility') or 'Everyone'
    if not content:
        return jsonify({'error': 'Post content cannot be empty'}), 400
    user_id = get_jwt_identity()
    conn = get_db()
    conn.execute('INSERT INTO posts (user_id, content, visibility, created_at) VALUES (?, ?, ?, ?)',
                 (user_id, content, visibility, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 201

@app.route('/api/settings/invite', methods=['GET'])
@jwt_required()
def get_invite():
    user_id = get_jwt_identity()
    conn = get_db()
    row = conn.execute('SELECT invite_only FROM settings WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    return jsonify({'invite_only': bool(row['invite_only'])})

@app.route('/api/settings/invite', methods=['POST'])
@jwt_required()
def toggle_invite():
    data = request.get_json() or {}
    invite_only = 1 if data.get('invite_only') else 0
    user_id = get_jwt_identity()
    conn = get_db()
    conn.execute('UPDATE settings SET invite_only = ? WHERE user_id = ?', (invite_only, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'invite_only': bool(invite_only)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
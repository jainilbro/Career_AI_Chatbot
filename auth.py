import streamlit as st
import libsql_client
import re
import pickle
import bcrypt
import uuid
from datetime import datetime, timedelta
from libsql_client import errors

def get_db_connection():
    url = st.secrets["TURSO_DATABASE_URL"]
    auth_token = st.secrets["TURSO_AUTH_TOKEN"]
    conn = libsql_client.create_client_sync(url=url, auth_token=auth_token)
    return conn

def fetch_user_by_username_or_email(identifier):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password, email FROM users "
        "WHERE LOWER(username) = ? OR email = ?",
        (identifier.lower(), identifier)
    )
    user = cursor.fetchone()
    conn.close()
    return user  # Returns (username, hashed_password, email) or None

def add_user(username, hashed_password, email):
    username = username.lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, hashed_password, email),
        )
        conn.commit()
        return True
    except errors.IntegrityError:
        return False
    finally:
        conn.close()

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain a number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character."
    return True, "Password is strong."

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def save_chat_history(username, history):
    conn = get_db_connection()
    cursor = conn.cursor()
    serialized_history = pickle.dumps(history)
    cursor.execute(
        "INSERT OR REPLACE INTO chat_history (username, history_data) VALUES (?, ?)",
        (username, serialized_history),
    )
    conn.commit()
    conn.close()

def load_chat_history(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT history_data FROM chat_history WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return pickle.loads(result[0])
    return {}

def username_exists(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM users WHERE LOWER(username) = ?",  # case-insensitive
        (username.lower(),)
    )
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def generate_session_token(username):
    token = str(uuid.uuid4())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))  # Clear old tokens
    cursor.execute("INSERT INTO sessions (username, token) VALUES (?, ?)", (username, token))
    conn.commit()
    conn.close()
    return token

def validate_session_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, created_at FROM sessions WHERE token = ?", (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        username, created_at = result
        # Token valid for 30 days (adjust as needed)
        if datetime.now() - datetime.fromisoformat(created_at) < timedelta(days=30):
            return username
    return None

def clear_session_token(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
    conn.commit()

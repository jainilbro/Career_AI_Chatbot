
import streamlit as st
import libsql_client
import re
import pickle
import bcrypt
import uuid
from datetime import datetime, timedelta

def get_db_connection():
    """Establishes a connection to the Turso database using Streamlit secrets."""
    url = st.secrets["TURSO_DATABASE_URL"]
    auth_token = st.secrets["TURSO_AUTH_TOKEN"]
    conn = libsql_client.create_client_sync(url=url, auth_token=auth_token)
    return conn

def fetch_user_by_username_or_email(identifier):
    """Fetches a user by username or email using the Turso client API."""
    conn = get_db_connection()
    try:
        # The Turso/libsql client uses conn.execute() which returns a ResultSet
        rs = conn.execute(
            "SELECT username, password, email FROM users WHERE LOWER(username) = ? OR email = ?",
            [identifier.lower(), identifier]
        )
        # rs[0] will be the first row if it exists
        return rs[0] if len(rs) > 0 else None
    finally:
        conn.close()

def username_exists(username):
    """Checks if a username already exists in the database."""
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT 1 FROM users WHERE LOWER(username) = ?", [username.lower()])
        return len(rs) > 0
    finally:
        conn.close()

def add_user(username, hashed_password, email):
    """Adds a new user after checking if they already exist."""
    # Pre-check to avoid relying on IntegrityError, as suggested
    if username_exists(username):
        return False

    conn = get_db_connection()
    try:
        # Use conn.execute() for INSERT statements
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            [username.lower(), hashed_password, email]
        )
        return True
    except Exception as e:
        # Generic exception for any other DB write issues
        st.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def save_chat_history(username, history):
    """Saves chat history using the Turso client API."""
    conn = get_db_connection()
    serialized_history = pickle.dumps(history)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO chat_history (username, history_data) VALUES (?, ?)",
            [username, serialized_history]
        )
    finally:
        conn.close()

def load_chat_history(username):
    """Loads chat history using the Turso client API."""
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT history_data FROM chat_history WHERE username = ?", [username])
        if len(rs) > 0:
            return pickle.loads(rs[0][0])
        return {}
    finally:
        conn.close()

# --- The functions below are unchanged but included for completeness ---

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

def generate_session_token(username):
    token = str(uuid.uuid4())
    conn = get_db_connection()
    try:
        # Use a batch to perform multiple operations reliably
        conn.batch([
            "DELETE FROM sessions WHERE username = ?",
            "INSERT INTO sessions (username, token) VALUES (?, ?)"
        ], [[username], [username, token]])
    finally:
        conn.close()
    return token

def validate_session_token(token):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT username, created_at FROM sessions WHERE token = ?", [token])
        if len(rs) > 0:
            username, created_at = rs[0]
            if datetime.now() - datetime.fromisoformat(created_at.replace('Z', '+00:00')) < timedelta(days=30):
                return username
        return None
    finally:
        conn.close()

def clear_session_token(username):
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE username = ?", [username])
    finally:
        conn.close()
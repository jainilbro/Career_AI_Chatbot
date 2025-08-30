import streamlit as st
import requests
import markdown
import base64
import re
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
from datetime import datetime, timedelta
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from auth import fetch_user_by_username_or_email, add_user, is_password_strong, hash_password, check_password, save_chat_history, load_chat_history, username_exists, generate_session_token, validate_session_token, clear_session_token
from auth import ensure_db_ready
try:
    ensure_db_ready()
except Exception as e:
    st.error(str(e))
    st.stop()

def mask_email(email):
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    if len(username) <= 4:
        masked_username = username[0] + '***' + username[-1]
    else:
        masked_username = username[:3] + '***' + username[-2:]
    return masked_username + '@' + domain

# JavaScript for cookie management (used for persistent login)
def set_cookie(key, value, expires_days=30):
    expires = datetime.now() + timedelta(days=expires_days)
    st.markdown(
        f"""
        <script>
            document.cookie = "{key}={value}; expires={expires.strftime('%a, %d %b %Y %H:%M:%S GMT')}; path=/";
        </script>
        """,
        unsafe_allow_html=True
    )

def get_cookie(key):
    return st.query_params.get(key, [None])[0]

def delete_cookie(key):
    st.markdown(
        f"""
        <script>
            document.cookie = "{key}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
        </script>
        """,
        unsafe_allow_html=True
    )

# ---------------------------------------------------
# App Configuration
# ---------------------------------------------------
st.set_page_config(page_title="Career AI", layout="wide", initial_sidebar_state="collapsed")

chat_css = """
<style>
[data-testid="stChatMessage"] {
    overflow-anchor: none;
}
</style>
"""
st.markdown(chat_css, unsafe_allow_html=True)

hide_logo_fs = """
<style>
    /* Hide fullscreen expand icon for all images */
    div[data-testid="stImage"] button[title="View fullscreen"] {
        display: none !important;
        visibility: hidden !important;
    }
</style>
"""
st.markdown(hide_logo_fs, unsafe_allow_html=True)

# System Prompt (Moved here to be defined before use)
SYSTEM_PROMPT = {"role": "system", "content": "You are a helpful career guidance assistant..."}

# ---------------------------------------------------
# Core Functions
# ---------------------------------------------------
def transform_query_for_search(user_query: str) -> str:
    prompt = f"""
    You are an expert at rewriting user questions into optimized search engine queries.
    Based on the user's request below, generate a single, concise, keyword-focused search query.
    Remove any conversational fluff. Today's date is August 30, 2025.
    User's request: "{user_query}"
    Optimized Search Query:
    """
    api_key = st.secrets.get("GROQ_API_KEY") # Change to GROQ_API_KEY
    if not api_key:
            return user_query
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
            "model": "llama-3.1-8b-instant", # Change to Llama 3.1 model
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 50,
            "temperature": 0.1,
        }
    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        optimized_query = response.json()["choices"][0]["message"]["content"]
        return optimized_query.strip().replace('"', "")
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):

        return user_query
    except Exception:
        return user_query

def web_search(query: str) -> str:
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, region="us-en", max_results=4))
            return "\n".join([f"[{i+1}] {r['body']}" for i, r in enumerate(results)]) if results else "No web results found."
    except Exception as e:
        return f"⚠️ Web search failed: {e}"

def get_bot_response(messages: list) -> str:
    api_key = st.secrets.get("GROQ_API_KEY") # Change to GROQ_API_KEY
    if not api_key:
            st.error("Groq API key not found.", icon="🚨")
            return ""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
            "model": "llama-3.1-8b-instant", # Change to Llama 3.1 model
            "messages": messages,
            "max_tokens": 4096,
            "temperature": 0.7,
        }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError as e:
        st.error("Could not connect to the AI server. It might be busy or down. Please try again in a few moments.")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            st.error("Too many requests. Please try again after some time.")
        else:
            st.error(f"An HTTP error occurred: {e.response.status_code}")
    except Exception as e:
        st.error(f"An unexpected error occurred.")
    return ""

def format_chat_for_export(messages, title):
    """Creates a well-formatted PDF using standard, compatible fonts."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(name='MainHeading', parent=styles['h2'], fontName='Helvetica-Bold', fontSize=14, spaceAfter=10))
    styles.add(ParagraphStyle(name='SubHeading', parent=styles['BodyText'], fontName='Helvetica-Bold', spaceBefore=8, spaceAfter=4, leftIndent=10))
    styles.add(ParagraphStyle(name='BulletStyle', parent=styles['BodyText'], leftIndent=36, bulletIndent=18, fontName='Helvetica'))
    styles['BodyText'].fontName = 'Helvetica'
    styles['h1'].fontName = 'Helvetica-Bold'
    styles['h3'].fontName = 'Helvetica-Bold'

    story = []

    story.append(Paragraph(title, styles['h1']))
    story.append(Spacer(1, 24))

    for msg in messages:
        if msg["role"] != "system":
            # Ensure the role text is safe
            role_text = msg.get('role', 'unknown').capitalize()
            story.append(Paragraph(f"{role_text}:", styles['h3']))

            content = msg.get('content', '')
            if not isinstance(content, str):
                content = str(content)

            content_lines = content.split('\n')
            for line in content_lines:
                clean_line = line.strip()

                if clean_line:

                    from xml.sax.saxutils import escape
                    safe_line = escape(clean_line)

                    if (safe_line[0].isdigit() and safe_line[1] == '.' and safe_line.endswith(':')) or safe_line.endswith(':'):
                        story.append(Paragraph(safe_line.replace('*',''), styles['SubHeading']))
                    elif safe_line.startswith('###'):
                        story.append(Paragraph(safe_line.replace('#', '').replace('*','').strip(), styles['MainHeading']))
                    elif safe_line.startswith('-'):
                        story.append(Paragraph(safe_line[1:].replace('*','').strip(), styles['BulletStyle'], bulletText='•'))
                    else:
                        story.append(Paragraph(safe_line.replace('*',''), styles['BodyText']))

            story.append(Spacer(1, 12))

    doc.build(story)

    pdf_value = buffer.getvalue()
    buffer.close()
    return pdf_value

# ---------------------------------------------------
# Session State Initialization
# ---------------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "show_login" not in st.session_state:
    st.session_state.show_login = False
if "show_register" not in st.session_state:
    st.session_state.show_register = False
if "history" not in st.session_state:
    st.session_state.history = {} # In-memory for guests
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None

# Check for persistent login cookie on app load/refresh
token = get_cookie("session_token")
if token and not st.session_state.authenticated:
    username = validate_session_token(token)
    if username:
        st.session_state.authenticated = True
        st.session_state.username = username
        st.session_state.history = load_chat_history(username)
        # Set to most recent chat or new if none

        pending = st.session_state.pop("pending_chat_id", None)
        if pending:
            st.session_state.history.setdefault(
                pending, {"title": "New Chat", "messages": [SYSTEM_PROMPT]}
            )
            st.session_state.current_chat_id = pending
        elif not st.session_state.history:
            seed_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            st.session_state.history[seed_id] = {"title": "New Chat", "messages": [SYSTEM_PROMPT]}
            st.session_state.current_chat_id = seed_id
        st.rerun()  # Refresh to apply login state

if st.session_state.authenticated and not st.session_state.history:
    st.session_state.history = load_chat_history(st.session_state.username)

if not st.session_state.authenticated and not st.session_state.history:
    welcome_chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    welcome_message ="Welcome to Career Guidance AI. I am here to provide data-driven insights on career paths, skill requirements, and industry trends. How can I assist you today?"
    st.session_state.history[welcome_chat_id] = {
        "title": "Welcome Chat",
        "messages": [
            SYSTEM_PROMPT,
            {"role": "assistant", "content": welcome_message}
        ],
    }
    st.session_state.current_chat_id = welcome_chat_id
# ---------------------------------------------------
# Sidebar: Authentication and Chat History
# --------------------------------------------------

with st.sidebar:
    st.title("Welcome")
    # --- Authentication Logic ---
    if st.session_state.authenticated:
        st.write(f"Logged in as **{st.session_state.username}**")
        if st.button("Logout"):
            if st.session_state.username:
                clear_session_token(st.session_state.username)
                delete_cookie("session_token")
            # Reset all session state keys
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    else:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login", use_container_width=True):
                if not st.session_state.get('show_login', False):
                    st.session_state.history = {}
                st.session_state.current_chat_id = None
                st.session_state.show_login = True
                st.session_state.show_register = False
                st.rerun()

        with col2:
            if st.button("Register", use_container_width=True):
                if not st.session_state.get('show_register', False):
                    st.session_state.history = {}
                st.session_state.current_chat_id = None
                st.session_state.show_register = True
                st.session_state.show_login = False
                st.rerun()

    st.header("📝 Chat History")

    # --- "New Chat" Button with corrected logic ---
    if st.button("➕ New Chat", use_container_width=True):
        st.session_state.show_login = False
        st.session_state.show_register = False
        sorted_chat_ids = sorted(st.session_state.history.keys(), reverse=True)
        if not sorted_chat_ids or st.session_state.history[sorted_chat_ids[0]]["title"] != "New Chat":
            new_chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            st.session_state.history[new_chat_id] = {"title": "New Chat", "messages": [SYSTEM_PROMPT]}
            st.session_state.current_chat_id = new_chat_id
        else:
            st.session_state.current_chat_id = sorted_chat_ids[0]
        st.rerun()

    use_web_search = st.toggle("Web Search", key="web_search_toggle", help="Allow the AI to search the web.")

    # --- PDF Export Button ---
    if st.session_state.current_chat_id and len(st.session_state.history[st.session_state.current_chat_id]["messages"]) > 1:
        current_chat = st.session_state.history[st.session_state.current_chat_id]
        full_chat_title = current_chat.get("title", "Chat Export")
        short_title = " ".join(full_chat_title.split()[:8])
        chat_export_data = format_chat_for_export(current_chat["messages"], full_chat_title)
        st.download_button(
            label="📄 Export as PDF",
            data=chat_export_data,
            file_name=f"{short_title}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    # --- Chat History List with corrected delete logic ---
    sorted_chat_ids = sorted(st.session_state.history.keys(), reverse=True)
    for chat_id in sorted_chat_ids:
        col1, col2 = st.columns([0.85, 0.15])
        with col1:
            if st.button(st.session_state.history[chat_id]["title"], key=f"select_{chat_id}", use_container_width=True):
                st.session_state.current_chat_id = chat_id
                st.rerun()
        with col2:
            if st.button("🗑️", key=f"delete_{chat_id}", help="Delete this chat", use_container_width=True):
                is_active_chat = chat_id == st.session_state.current_chat_id

                del st.session_state.history[chat_id]
                if st.session_state.authenticated:
                    save_chat_history(st.session_state.username, st.session_state.history)

                if is_active_chat:
                    new_chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    st.session_state.history[new_chat_id] = {"title": "New Chat", "messages": [SYSTEM_PROMPT]}
                    st.session_state.current_chat_id = new_chat_id

                st.success("Chat deleted!")
                st.rerun()

    # Logic to select the most recent chat if none is selected
    if st.session_state.current_chat_id is None and len(st.session_state.history) > 0:
        st.session_state.current_chat_id = sorted(st.session_state.history.keys(), reverse=True)[0]

# ---------------------------------------------------
# Main App: Authentication Forms and Chat Interface
# ---------------------------------------------------
def get_base64_image(image_path):
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode()

logo_base64 = get_base64_image("logo.png")

# Use HTML with Flexbox for perfect vertical alignment
st.markdown(f"""
    <div style="display: flex; align-items: center; margin-bottom: 20px;">
        <img src="data:image/png;base64,{logo_base64}" width="77" style="margin-right: 20px;">
        <h1 style="margin: 0;">Career Guidance AI</h1>
    </div>
    """,
    unsafe_allow_html=True
)

st.caption("Navigate Your Career with AI-Powered Insights. Ask about Jobs, Skills, and More!")

# Get current messages
current_messages = st.session_state.history.get(st.session_state.current_chat_id, {}).get("messages", [SYSTEM_PROMPT])


if st.session_state.get("just_selected_chat", False):
    st.components.v1.html(
        """
        <script>
            const main = window.parent.document.querySelector('[data-testid="stAppViewContainer"]');
            if (main) {
                main.scrollTo(0, 0);
            }
        </script>
        """,
        height=0,
    )

    st.session_state.just_selected_chat = False

# --- ADD THIS CORRECTED BLOCK ---

if st.session_state.show_login:
    # --- LOGIN FORM ---
    st.subheader("Login")
    identifier = st.text_input("Username or Email", value="", key="login_user")
    password = st.text_input("Password", type="password", value="", key="login_password")
    if st.button("Submit Login"):
        user = fetch_user_by_username_or_email(identifier)
        if user:
            username, hashed_password, email = user
            if check_password(password, hashed_password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.history = load_chat_history(username)

                token = generate_session_token(username)
                set_cookie("session_token", token)

                if not st.session_state.history:
                    new_chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    st.session_state.history[new_chat_id] = {
                        "title": "New Chat",
                        "messages": [SYSTEM_PROMPT],
                    }
                    st.session_state.current_chat_id = new_chat_id
                else:
                    # If history exists, find the most recent chat
                    sorted_chat_ids = sorted(st.session_state.history.keys(), reverse=True)
                    most_recent_chat_id = sorted_chat_ids[0]

                    # Check if the most recent chat is empty (has no user/assistant messages)
                    if len(st.session_state.history[most_recent_chat_id]["messages"]) > 1:
                        # If it's not empty, create a new chat
                        new_chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                        st.session_state.history[new_chat_id] = {
                            "title": "New Chat",
                            "messages": [SYSTEM_PROMPT],
                        }
                        st.session_state.current_chat_id = new_chat_id
                    else:
                        # If it is empty, just open that one
                        st.session_state.current_chat_id = most_recent_chat_id

                st.session_state.show_login = False
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Incorrect password.")
        else:
            st.error("No account found with that username or email.")

elif st.session_state.show_register:
    # --- REGISTER FORM ---
    st.subheader("Register")
    reg_username = st.text_input("Username", value="", key="reg_username")
    if reg_username:
        if username_exists(reg_username):
            st.markdown('❌ Username already taken', unsafe_allow_html=True)
        else:
            st.markdown('✅ Username available', unsafe_allow_html=True)
    reg_email = st.text_input("Email", value="")
    reg_password = st.text_input("Password", type="password", value="")
    if st.button("Submit Registration"):
        if username_exists(reg_username):
            st.error("Username already taken. Please choose another.")
        else:
            is_strong, message = is_password_strong(reg_password)
            if not is_strong:
                st.error(message)
            else:
                hashed_password = hash_password(reg_password)
                if add_user(reg_username, hashed_password, reg_email):
                    st.success("Registered successfully!Please save your password securely, as there is no 'Forgot Password' feature.")
                    st.session_state.show_register = False
                else:
                    st.error("Username or email already exists.")
else:
    # --- CHAT INTERFACE (only shows if login/register are hidden) ---
    current_messages = st.session_state.history.get(st.session_state.current_chat_id, {}).get("messages", [SYSTEM_PROMPT])

    chat_container = st.container()
    with chat_container:
        for msg in current_messages:
            if msg["role"] != "system":
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

def generate_title_from_prompt(prompt: str) -> str:
    """Uses the AI to generate a short, concise title from the user's first message."""
    title_prompt = f"Generate a very short, concise title (4-5 words max) for a chat that starts with this user message: \"{prompt}\". Do not use quotes in the title."
    try:
        # Re-using the get_bot_response logic but with different parameters for a quick, non-streaming response
        api_key = st.secrets.get("GROQ_API_KEY")
        if not api_key: return prompt[:30] # Fallback to first 30 chars
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": title_prompt}],
            "max_tokens": 20, "temperature": 0.2,
        }
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        title = response.json()["choices"][0]["message"]["content"]
        return title.strip().replace('"', "")
    except Exception:
        return " ".join(prompt.split()[:5])

if user_input := st.chat_input("Send a message..."):
    if st.session_state.current_chat_id is None:
        chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        st.session_state.current_chat_id = chat_id
        st.session_state.history[chat_id] = {
            "title": "New Chat", 
            "messages": [SYSTEM_PROMPT]
        }
    else:
        chat_id = st.session_state.current_chat_id

    st.session_state.history[chat_id]["messages"].append(
        {"role": "user", "content": user_input}
    )

    # If it's the first real message in a "New Chat", generate a proper title
    if st.session_state.history[chat_id]["title"] == "New Chat":
        with st.spinner("Generating title..."):
            st.session_state.history[chat_id]["title"] = generate_title_from_prompt(user_input)

    st.rerun()

# Generate Assistant Reply
if current_messages and current_messages[-1]["role"] == "user":
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            final_prompt_messages = list(current_messages)
            if use_web_search:
                user_query = final_prompt_messages[-1]["content"]
                with st.spinner("Optimizing search query..."):
                    optimized_query = transform_query_for_search(user_query)
                st.info(f"Searching for: `{optimized_query}`", icon="🔍")
                with st.spinner(f"Searching for '{optimized_query}'..."):
                    search_results = web_search(optimized_query)
                web_prompt = {
                    "role": "user",
                    "content": f"Based on the following web search results, please answer my original query. "
                               f"Original Query: \"{user_query}\"\n\nWeb Search Results (for query: \"{optimized_query}\"):\n---\n"
                               f"{search_results}\n---",
                }
                final_prompt_messages.append(web_prompt)
            bot_reply = get_bot_response(final_prompt_messages)
            if bot_reply:
                st.markdown(bot_reply)
                st.session_state.history[st.session_state.current_chat_id]["messages"].append(
                    {"role": "assistant", "content": bot_reply}
                )
                # Save if authenticated
                if st.session_state.authenticated:
                    save_chat_history(st.session_state.username, st.session_state.history)

                st.rerun()
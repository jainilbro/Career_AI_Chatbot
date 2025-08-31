import streamlit as st
import requests
import extra_streamlit_components as stx
import markdown
import base64
import textwrap
import re
from duckduckgo_search import DDGS
from datetime import datetime, timedelta
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from auth import fetch_user_by_username_or_email, add_user, is_password_strong, hash_password, check_password, save_chat_history, load_chat_history, username_exists, generate_session_token, validate_session_token, clear_session_token
from auth import ensure_db_ready

st.set_page_config(page_title="Career AI", layout="wide", initial_sidebar_state="collapsed")

try:
    ensure_db_ready()
except Exception as e:
    st.error(str(e))
    st.stop()

GROQ_MODEL_NAME = "llama-3.1-8b-instant"

if 'cookie_manager' not in st.session_state:
    st.session_state.cookie_manager = stx.CookieManager()

cookie_manager = st.session_state.cookie_manager

EMAIL_RE = re.compile(
    r'^[a-zA-Z0-9]'                     # Must start with alphanumeric
    r'[a-zA-Z0-9._+\-]*'                # Can contain dots, underscores, plus, hyphen
    r'[a-zA-Z0-9]'                      # Must end with alphanumeric (before @)
    r'@'                                # @ symbol
    r'[a-zA-Z0-9]'                      # Domain must start with alphanumeric
    r'[a-zA-Z0-9.-]*'                   # Domain can contain dots and hyphens
    r'\.'                               # Must have at least one dot
    r'[a-zA-Z]{2,}$'                    # TLD must be at least 2 letters
)

def is_email_valid(email: str) -> bool:
    """
    Validates email format with improved regex.
    Also handles edge cases like consecutive dots and invalid characters.
    """
    if not email or not email.strip():
        return False
    
    email = email.strip().lower()
    
    # Basic length check
    if len(email) < 5 or len(email) > 254:
        return False
    
    # Check for consecutive dots
    if '..' in email:
        return False
    
    # Check for dots at start or end of local part
    local, _, domain = email.partition('@')
    if local.startswith('.') or local.endswith('.'):
        return False
    
    # Main regex validation
    return bool(EMAIL_RE.match(email))
    
def validate_username_on_change():
    """Checks username availability as the user types."""
    username = st.session_state.get("reg_username", "")
    if username:
        if username_exists(username):
            st.session_state.username_validity_msg = "❌ Username already taken"
        else:
            st.session_state.username_validity_msg = "✅ Username available"
    else:
        st.session_state.username_validity_msg = ""

def validate_email_on_change():
    email = st.session_state.get("reg_email", "")
    if email:
        if not is_email_valid(email):
            st.session_state.email_validity_msg = "❌ Invalid email format"
            return
        user = fetch_user_by_username_or_email(email)
        st.session_state.email_validity_msg = "❌ Email already registered" if user else "✅ Email available"
    else:
        st.session_state.email_validity_msg = ""

def trim_messages(messages, keep_last=24):
    """Prunes the message history to prevent token bloat."""
    sys = [m for m in messages if m["role"] == "system"]
    rest = [m for m in messages if m["role"] != "system"]
    return sys + rest[-keep_last:]

def create_new_chat():
    """Creates a new, empty chat in session_state and returns its ID."""
    chat_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    st.session_state.history[chat_id] = {
        "title": "New Chat",
        "messages": [SYSTEM_PROMPT],
    }
    return chat_id

def set_view(view):
    """Central function to control the app's view state."""
    st.session_state.show_login = (view == 'login')
    st.session_state.show_register = (view == 'register')
    # When switching to an auth view as a guest, clear guest history
    if view in ['login', 'register'] and not st.session_state.get("authenticated"):
        st.session_state.history = {}
        st.session_state.current_chat_id = None


# ---------------------------------------------------
# App Configuration
# ---------------------------------------------------
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

st.markdown("""
    <style>
        .block-container {
            padding-top: 1rem;
        }
        /* This rule makes the title smaller on mobile screens */
        @media (max-width: 600px) {
            h1 {
                font-size: 22px !important;
            }
        }
    </style>
    """, unsafe_allow_html=True)

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
            "model": GROQ_MODEL_NAME,
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
            if not results:
                return "No web results found."
            
            lines = []
            for i, r in enumerate(results, start=1):
                t = (r.get("title") or "").strip()
                u = (r.get("href") or "").strip()
                s = (r.get("body") or "").strip()
                lines.append(f"[{i}] {t}\n{u}\n{s}")
        
            return "\n\n".join(lines)
    except Exception as e:
        return f"⚠️ Web search failed: {e}"

def get_bot_response(messages: list) -> str:
    api_key = st.secrets.get("GROQ_API_KEY") # Change to GROQ_API_KEY
    if not api_key:
            st.error("Groq API key not found.", icon="🚨")
            return ""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
            "model": GROQ_MODEL_NAME, 
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
        st.exception(e)
    return ""

def format_chat_for_export(messages, title):
    """
    Creates a well-formatted PDF by intelligently parsing Markdown from the AI's response
    and converting it to ReportLab Platypus objects.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()

    # --- CORRECTED: Modify existing styles instead of adding them ---
    styles['BodyText'].fontName = 'Helvetica'
    styles['BodyText'].fontSize = 10
    styles['BodyText'].leading = 14
    styles['BodyText'].wordWrap = 'CJK'
    styles['h1'].fontName = 'Helvetica-Bold'
    styles['h1'].fontSize = 18
    styles['h1'].spaceAfter = 12
    styles['h2'].fontName = 'Helvetica-Bold'
    styles['h2'].fontSize = 14
    styles['h2'].spaceAfter = 10
    styles['h3'].fontName = 'Helvetica-Bold'
    styles['h3'].fontSize = 12
    styles['h3'].spaceAfter = 8
    

    styles['Bullet'].leftIndent = 36
    styles['Bullet'].bulletIndent = 18

    # --- Only add new, custom styles that don't already exist ---
    styles.add(ParagraphStyle(name='NumberedList', parent=styles['BodyText'], leftIndent=36, bulletIndent=18))

    story = []
    story.append(Paragraph(title, styles['h1']))
    story.append(Spacer(1, 24))

    for msg in messages:
        if msg["role"] != "system":
            role_text = msg.get('role', 'unknown').capitalize()
            story.append(Paragraph(f"{role_text}:", styles['h3']))

            content = msg.get('content', '')
            if not isinstance(content, str):
                content = str(content)

            content_lines = content.split('\n')
            for line in content_lines:
                clean_line = line.strip()

                if not clean_line:
                    continue

                processed_line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', clean_line)
                processed_line = re.sub(r'\*(.*?)\*', r'<i>\1</i>', processed_line)

                if processed_line.startswith('### '):
                    story.append(Paragraph(processed_line.replace('### ', ''), styles['h3']))
                elif processed_line.startswith('## '):
                    story.append(Paragraph(processed_line.replace('## ', ''), styles['h2']))
                elif processed_line.startswith('# '):
                    story.append(Paragraph(processed_line.replace('# ', ''), styles['h1']))
                elif re.match(r"^\d+\.\s+", processed_line):
                    story.append(Paragraph(processed_line, styles['NumberedList']))
                elif processed_line.startswith(('* ', '- ')):
                    formatted_line = f"• {processed_line[2:]}"
                    story.append(Paragraph(formatted_line, styles['Bullet']))
                else:
                    story.append(Paragraph(processed_line, styles['BodyText']))

            story.append(Spacer(1, 12))

    doc.build(story)
    pdf_value = buffer.getvalue()
    buffer.close()
    return pdf_value
# ---------------------------------------------------
# Session State Initialization
# ---------------------------------------------------
defaults = {
    "authenticated": False, "username": None, "history": {},
    "current_chat_id": None, "show_login": False, "show_register": False
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

token = cookie_manager.get("session_token")
if token and not st.session_state.get("authenticated"):
    username = validate_session_token(token)
    if username:
        st.session_state.authenticated = True
        st.session_state.username = username
        st.session_state.history = load_chat_history(username)
        st.rerun()

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
    if st.session_state.get("authenticated"):
        st.write(f"Logged in as **{st.session_state.username}**")
        if st.button("Logout"):
            if st.session_state.get("username"):
                clear_session_token(st.session_state.username)
                cookie_manager.delete("session_token")
            
            # Controlled state reset
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.history = {}
            st.session_state.current_chat_id = None
            set_view('chat') # Use the new view manager
            st.rerun()

    else:
        # --- LOGIN/REGISTER BUTTONS ---
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login", use_container_width=True):
                set_view('login')
                st.rerun()

        with col2:
            if st.button("Register", use_container_width=True):
                set_view('register')
                st.rerun()

    st.header("📝 Chat History")

    # --- "New Chat" Button ---
    if st.button("➕ New Chat", use_container_width=True):
        set_view('chat')
        # This logic prevents creating multiple empty "New Chat" entries
        sorted_chat_ids = sorted(st.session_state.history.keys(), reverse=True)
        if not sorted_chat_ids or st.session_state.history[sorted_chat_ids[0]]["title"] != "New Chat":
            new_chat_id = create_new_chat()
            st.session_state.current_chat_id = new_chat_id
        else:
            st.session_state.current_chat_id = sorted_chat_ids[0]
        st.rerun()

    use_web_search = st.toggle("Web Search", key="web_search_toggle", help="Allow the AI to search the web.")

    # --- PDF Export Button ---
    if st.session_state.get("current_chat_id") and len(st.session_state.history.get(st.session_state.current_chat_id, {}).get("messages", [])) > 1:
        current_chat = st.session_state.history[st.session_state.current_chat_id]
        pdf_data = format_chat_for_export(current_chat["messages"], current_chat["title"])
        title = current_chat.get("title", "Chat") 
        safe_title = re.sub(r"\s+", "_", re.sub(r"[^A-Za-z0-9 _\.-]+", "", title)).strip("_.") or "Chat"

        st.download_button(
            label="📄 Export as PDF",
            data=pdf_data,
            file_name=f"{safe_title}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    # --- Chat History List ---
    sorted_chat_ids = sorted(st.session_state.history.keys(), reverse=True)
    for chat_id in sorted_chat_ids:
        col1, col2 = st.columns([0.85, 0.15])
        with col1:
            if st.button(st.session_state.history[chat_id]["title"], key=f"select_{chat_id}", use_container_width=True):
                st.session_state.show_login = False
                st.session_state.show_register = False
                st.session_state.current_chat_id = chat_id
                st.rerun()
        with col2:
            if st.button("🗑️", key=f"delete_{chat_id}", help="Delete this chat"):
                is_active_chat = chat_id == st.session_state.current_chat_id
                del st.session_state.history[chat_id]
                if st.session_state.get("authenticated"):
                    save_chat_history(st.session_state.username, st.session_state.history)
                if is_active_chat:
                    st.session_state.current_chat_id = create_new_chat()
                st.rerun()

    # Logic to select the most recent chat if none is selected
    if st.session_state.current_chat_id is None and len(st.session_state.history) > 0:
        st.session_state.current_chat_id = sorted(st.session_state.history.keys(), reverse=True)[0]

# ---------------------------------------------------
# Main App: Authentication Forms and Chat Interface
# ---------------------------------------------------
def get_base64_image(image_path):
    try:
        with open(image_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        return None

logo_base_64 = get_base64_image("logo.png")

if logo_base_64:
    # This final version is responsive but also has a maximum size cap
    st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 10px;">
            <img src="data:image/png;base64,{logo_base_64}" 
                 style="width: 15%; max-width: 65px; height: auto;">
            <h1 style="margin: 0; font-size: 28px; line-height: 1;">Career Guidance AI</h1>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    st.title("Career Guidance AI")

st.caption("Navigate Your Career with AI-Powered Insights. Ask about Jobs, Skills, and More!")

# --- ADD THIS CORRECTED BLOCK ---

if st.session_state.get("show_login"):
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


                token = generate_session_token(st.session_state.username)
                cookie_manager.set(
                    "session_token",
                    token,
                    max_age=30*24*60*60  
                )


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

elif st.session_state.get("show_register"):
    # --- REGISTER FORM (with real-time validation, without st.form) ---
    st.subheader("Register")

    # Initialize session state for validation messages if they don't exist
    if "username_validity_msg" not in st.session_state:
        st.session_state.username_validity_msg = ""
    if "email_validity_msg" not in st.session_state:
        st.session_state.email_validity_msg = ""

    # Username input with on_change callback
    reg_username = st.text_input(
        "Username",
        key="reg_username",
        on_change=validate_username_on_change
    )
    # Display the validation message right below the input
    if st.session_state.username_validity_msg:
        st.markdown(st.session_state.username_validity_msg)

    # Email input with on_change callback
    reg_email = st.text_input(
        "Email",
        key="reg_email",
        on_change=validate_email_on_change
    )
    # Display the validation message right below the input
    if st.session_state.email_validity_msg:
        st.markdown(st.session_state.email_validity_msg)

    reg_password = st.text_input("Password", type="password")

    # Use a regular st.button instead of a form submit button
    if st.button("Submit Registration"):
        # Final validation on submit
        if "already taken" in st.session_state.username_validity_msg or not reg_username:
            st.error("Please enter an available username.")
        elif "Invalid" in st.session_state.email_validity_msg or "already registered" in st.session_state.email_validity_msg or not reg_email:
            st.error("Please enter an available and valid email.")
        else:
            is_strong, message = is_password_strong(reg_password)
            if not is_strong:
                st.error(message)
            else:
                hashed_password = hash_password(reg_password)
                if add_user(reg_username, hashed_password, reg_email):
                    st.success("Registered successfully!Please save your password securely, as there is no 'Forgot Password' feature.")
                    st.session_state.show_register = False
                    # Clear validation messages for next time
                    st.session_state.username_validity_msg = ""
                    st.session_state.email_validity_msg = ""
                else:
                    st.error("An error occurred during registration.")
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
            if not api_key: return textwrap.shorten(prompt, width=40, placeholder="...") 
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": GROQ_MODEL_NAME,
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

        if st.session_state.get("authenticated"):
            save_chat_history(st.session_state.username, st.session_state.history)

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
                final_prompt_messages = trim_messages(final_prompt_messages)

                bot_reply = get_bot_response(final_prompt_messages)
                if bot_reply:
                    st.session_state.history[st.session_state.current_chat_id]["messages"].append(
                        {"role": "assistant", "content": bot_reply}
                    )
                    # Save if authenticated
                    if st.session_state.get("authenticated"):
                        save_chat_history(st.session_state.username, st.session_state.history)

                    st.rerun()
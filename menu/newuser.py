import streamlit as st
import sqlite3
import random
import string
import asyncio
from httpx_oauth.clients.google import GoogleOAuth2
from firebase_admin import auth, exceptions, initialize_app

# Initialize Firebase Admin
initialize_app()

# Streamlit title
st.title("College.ai")

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    conn.commit()
    return conn, c

conn, c = init_db()

# Initialize Google OAuth2 client
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
redirect_url = "YOUR_REDIRECT_URL"
client = GoogleOAuth2(client_id=client_id, client_secret=client_secret)

async def get_access_token(client: GoogleOAuth2, redirect_url: str, code: str):
    return await client.get_access_token(code, redirect_url)

async def get_email(client: GoogleOAuth2, token: str):
    user_id, user_email = await client.get_id_email(token)
    return user_id, user_email

def get_logged_in_user_email():
    try:
        query_params = st.experimental_get_query_params()
        code = query_params.get('code')
        if code:
            token = asyncio.run(get_access_token(client, redirect_url, code[0]))
            st.experimental_set_query_params()

            if token:
                user_id, user_email = asyncio.run(get_email(client, token['access_token']))
                if user_email:
                    try:
                        user = auth.get_user_by_email(user_email)
                    except exceptions.FirebaseError:
                        user = auth.create_user(email=user_email)
                    st.session_state.email = user.email
                    return user.email
        return None
    except Exception as e:
        st.error(f"Error during Google login: {e}")
        return None

def show_login_button():
    authorization_url = asyncio.run(client.get_authorization_url(
        redirect_url,
        scope=["email", "profile"],
        extras_params={"access_type": "offline"},
    ))
    button_html = f'<a href="{authorization_url}" target="_self" style="text-decoration: none;"><button style="background-color: #2F80ED; color: white; border: none; padding: 10px 20px; border-radius: 5px; font-size: 16px; cursor: pointer;">Login via Google</button></a>'
    st.markdown(button_html, unsafe_allow_html=True)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp(email, otp):
    st.write(f"An OTP has been sent to {email}. Your OTP is: {otp}")

def handle_login(c, form):
    user = form.text_input("Username")
    password = form.text_input("Password", type="password")

    if form.form_submit_button("Login"):
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (user, password))
        result = c.fetchone()
        if result:
            st.session_state["user"] = user
            st.session_state["logged_in"] = True
            st.success("Logged in successfully!")
        else:
            st.error("Invalid username or password")
    show_login_button()

def handle_signup(c, conn, form):
    new_user = form.text_input("New Username")
    new_password = form.text_input("New Password", type="password")
    email = form.text_input("Email")

    if form.form_submit_button("Sign Up"):
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (new_user, new_password, email))
        conn.commit()
        st.success("Account created successfully! Please login.")
    show_login_button()

def handle_forgot_password(c, form):
    email = form.text_input("Enter Email")

    if form.form_submit_button("Send OTP"):
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        result = c.fetchone()
        if result:
            otp = generate_otp()
            send_otp(email, otp)
            st.success("OTP sent successfully! Check your email.")
        else:
            st.error("Email not found")

def main():
    st.write("<h1><center> AUTHENTICATION PORTAL</center></h1>", unsafe_allow_html=True)
    
    if "logged_in" not in st.session_state:
        form_type = st.selectbox('LOGIN/SIGNUP/FORGOT PASSWORD', ['Login', 'Sign Up', 'Forgot Password'])
        
        if form_type == "Login":
            form = st.form(key="login_form")
            form.subheader("LOGIN")
            handle_login(c, form)
            get_logged_in_user_email()

        elif form_type == "SIGN UP":
            form = st.form(key="signup_form")
            form.subheader("SIGN UP")
            handle_signup(c, conn, form)
            get_logged_in_user_email()

        elif form_type == "Forgot Password":
            form = st.form(key="forgot_password_form")
            form.subheader("FORGOT PASSWORD")
            handle_forgot_password(c, form)

    else:
        st.subheader("Logged in")
        st.write("Ready to conquer today:", st.session_state["user"])

        if st.button("LOGOUT"):
            st.session_state.pop("logged_in", None)
            st.session_state.pop("user", None)
            st.success("Catch you later, trailblazer!")

if __name__ == "__main__":
    main()

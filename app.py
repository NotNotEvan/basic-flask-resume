"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

# Standard library imports
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import os
from os import environ
import tempfile
from typing import Tuple

# Third-party imports
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_session import Session
from passlib.hash import sha256_crypt

# Initialize Flask app
load_dotenv()
app = Flask(__name__)
app.secret_key = environ.get("SECRET_KEY", "fallback_secret_key")
DATABASE_FILE = environ.get("DATABASE_FILE", "database.txt")
COMMON_PASSWORDS_FILE = environ.get(
    "COMMON_PASSWORDS_FILE", "static/data/CommonPassword.txt"
)

# Create a temporary directory for sessions
TEMP_SESSION_DIR = tempfile.mkdtemp()

# Session configuration
app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=TEMP_SESSION_DIR,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Initialize the Session extension
Session(app)


class SecurityLogger:
    """
    A class for logging security events.
    """

    def __init__(self, log_file="security.log"):
        """
        Initializes the SecurityLogger object.
        """
        self.logger = logging.getLogger("security_logger")
        self.logger.setLevel(logging.INFO)

        # Create logs directory if it doesn't exist
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Configure rotating file handler (10MB max size, keep 5 backup files)
        handler = RotatingFileHandler(
            os.path.join(log_dir, log_file), maxBytes=10 * 1024 * 1024, backupCount=5
        )

        # Set log format
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def log_failed_login(self, username: str, ip_address: str, reason: str):
        """
        Logs failed login attempts with timestamp and IP address.
        """
        self.logger.warning(
            "Failed login attempt - Username: %s - IP: %s - Reason: %s",
            username,
            ip_address,
            reason,
        )

    def log_successful_login(self, username: str, ip_address: str):
        """
        Logs successful login attempts with timestamp and IP address.
        """
        self.logger.info(
            "Successful login - Username: %s - IP: %s",
            username,
            ip_address,
        )


class UserDatabase:
    """
    A class for managing user authentication data in a text file.
    """

    def __init__(self, filename):
        """
        Initializes the UserDatabase object.
        """
        self.filename = filename
        self.users = {}
        self.load_database()

    def load_database(self):
        """
        Loads the database from a text file. Creates file if it doesn't exist.
        """
        try:
            with open(
                self.filename, "a+", encoding="utf-8"
            ):  # Create file if it doesn't exist
                pass

            with open(self.filename, "r", encoding="utf-8") as file:
                for line in file:
                    if line.strip():  # Skip empty lines
                        username, hashed_password = line.strip().split(":")
                        self.users[username.strip().lower()] = hashed_password
        except (IOError, OSError) as e:
            print(f"File system error loading database: {e}")

    def save_database(self):
        """
        Saves the database to a text file.
        """
        try:
            with open(self.filename, "w", encoding="utf-8") as file:
                for username, hashed_password in self.users.items():
                    file.write(f"{username.strip().lower()}:{hashed_password}\n")
            return True
        except (IOError, OSError) as e:
            print(f"Error saving database: {e}")
            return False


def load_common_passwords() -> list[str]:
    """
    Loads common passwords from a file into a list for efficient lookup.
    """

    try:
        if os.path.exists(COMMON_PASSWORDS_FILE):
            print(f"Found passwords file at: {COMMON_PASSWORDS_FILE}")
            with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as file:
                passwords = [line.strip().lower() for line in file if line.strip()]
                print(f"Successfully loaded {len(passwords)} passwords")
                return passwords

        print(f"No password file found at: {COMMON_PASSWORDS_FILE}")
        raise IOError(f"No password file found at: {COMMON_PASSWORDS_FILE}")
    except IOError as e:
        print(e)
        return []


# Initialize security logger
security_logger = SecurityLogger()

# Initialize database
db = UserDatabase(DATABASE_FILE)

# Route constants
URL_ROUTES = {
    "LOGIN": "/",
    "REGISTER": "/register",
    "UPDATE_PASSWORD": "/update_password",
    "HOME": "/home",
    "ABOUT": "/about",
    "CONTACT": "/contact",
}


# HELPER FUNCTIONS
def validate_password_strength(
    password: str, confirm_password: str
) -> Tuple[bool, str]:
    """
    Validates password against NIST SP 800-63B criteria:
    - Length and complexity requirements
    - Not a commonly used password
    - Passwords match
    """
    common_passwords = load_common_passwords()

    # Check if passwords match
    if password != confirm_password:
        return False, "Passwords do not match"

    # Check minimum length (12 characters)
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    # Check if any part of the password matches a common password
    password_lower = password.lower()
    for i in range(len(password_lower)):
        for j in range(i + 1, len(password_lower) + 1):
            substring = password_lower[i:j]
            if len(substring) > 3 and substring in common_passwords:
                return (
                    False,
                    f"Password contains a common secret: '{substring}'. "
                    "Please choose a different password",
                )

    # Check complexity requirements
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(not char.isalnum() for char in password)

    if not all([has_uppercase, has_lowercase, has_digit, has_special]):
        return (
            False,
            "Password must contain at least one uppercase letter, "
            "lowercase letter, number, and special character",
        )

    return True, ""


# HANDLERS
@app.route(URL_ROUTES["REGISTER"], methods=["POST"])
def handle_register():
    """
    Handles the register route's form submission.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # Get form data
    form_data = {
        "username": username,
        "password": password,
        "confirm_password": confirm_password,
    }

    # Validate password
    is_valid, error_message = validate_password_strength(password, confirm_password)
    if not is_valid:
        flash(error_message, "error")
        return render_template("register.html", **form_data)

    # Check if username already exists
    if username in db.users:
        flash("Username already exists", "error")
        return render_template("register.html", **form_data)

    # Hash password and save to database
    try:
        hashed_password = sha256_crypt.hash(password)
        db.users[username] = hashed_password
        if not db.save_database():
            raise IOError("Failed to save to database")

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    except IOError as e:
        flash(f"Registration error: {str(e)}", "error")
        return render_template("register.html", **form_data)


@app.route(URL_ROUTES["LOGIN"], methods=["POST"])
def handle_login():
    """
    Handles the login route's form submission.
    """
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "").strip()
    ip_address = request.remote_addr

    try:
        # Check if database is loaded
        if not os.path.exists(DATABASE_FILE):
            raise IOError("Failed to load database")

        # Check if username exists
        if username not in db.users:
            security_logger.log_failed_login(
                username=username, ip_address=ip_address, reason="Username not found"
            )
            flash("Username not found", "error")
            return render_template("login.html", username=username, password=password)

        # Verify password
        if not sha256_crypt.verify(password, db.users[username]):
            security_logger.log_failed_login(
                username=username, ip_address=ip_address, reason="Incorrect password"
            )
            flash("Incorrect password", "error")
            return render_template("login.html", username=username, password=password)

        # Set session data
        session["username"] = username
        session["authenticated"] = True
        flash("Login successful!", "success")
        security_logger.log_successful_login(username=username, ip_address=ip_address)
        return redirect(url_for("home"))
    except IOError as e:
        security_logger.log_failed_login(
            username=username, ip_address=ip_address, reason=f"Database error: {str(e)}"
        )
        flash(f"Login error: {str(e)}", "error")
        return render_template("login.html", username=username, password=password)


@app.route(URL_ROUTES["UPDATE_PASSWORD"], methods=["POST"])
def handle_update_password():
    """
    Handles the update password route's form submission.
    """
    current_password = request.form.get("current_password", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # Check if current password is correct
    if not sha256_crypt.verify(current_password, db.users[session["username"]]):
        flash("Current password is incorrect", "error")
        return render_template(
            "update_password.html",
            current_password=current_password,
            password=password,
            confirm_password=confirm_password,
        )

    # Validate new password
    is_valid, error_message = validate_password_strength(password, confirm_password)
    if not is_valid:
        flash(error_message, "error")
        return render_template(
            "update_password.html",
            current_password=current_password,
            password=password,
            confirm_password=confirm_password,
        )

    # Hash new password and save to database
    try:
        hashed_password = sha256_crypt.hash(password)
        db.users[session["username"]] = hashed_password
        if not db.save_database():
            raise IOError("Failed to save to database")

        flash("Password updated successfully!", "success")
        return redirect(url_for("home"))
    except IOError as e:
        flash(f"Password update error: {str(e)}", "error")
        return render_template(
            "update_password.html",
            current_password=current_password,
            password=password,
            confirm_password=confirm_password,
        )


@app.route(URL_ROUTES["CONTACT"], methods=["POST"])
def handle_contact():
    """
    Handles the contact route's form submission.
    """

    # Get form data
    form_data = {
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "message": request.form.get("message"),
    }

    # Check if user is authenticated
    if not session.get("authenticated"):
        flash("Please login to send a message", "error")
        return redirect(url_for("login"))

    # Validate form data
    if not all(form_data.values()):
        flash("All fields are required", "error")
        return render_template("contact.html", form_data=form_data)

    # Process form data
    flash("Message sent successfully!", "success")
    return render_template("contact.html")


# ROUTES
@app.route(URL_ROUTES["LOGIN"], methods=["GET", "POST"])
def login():
    """
    Renders the login page template.
    """
    if session.get("authenticated"):
        return redirect(url_for("home"))
    if request.method == "POST":
        return handle_login()
    return render_template("login.html", username="", password="")


@app.route(URL_ROUTES["REGISTER"], methods=["GET", "POST"])
def register():
    """
    Renders the register page template.
    """
    if request.method == "POST":
        return handle_register()
    return render_template(
        "register.html", username="", password="", confirm_password=""
    )


@app.route(URL_ROUTES["UPDATE_PASSWORD"], methods=["GET", "POST"])
def update_password():
    """
    Renders the update password page template.
    """
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    if request.method == "POST":
        return handle_update_password()
    return render_template(
        "update_password.html",
        current_password="",
        password="",
        confirm_password="",
    )


@app.route("/home")
def home():
    """
    Renders the home page template.
    """
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("home.html")


@app.route(URL_ROUTES["ABOUT"])
def about():
    """
    Renders the about page template.
    """
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    current_time = datetime.now().strftime("%B %d, %Y %I:%M %p")
    return render_template("about.html", current_time=current_time)


@app.route(URL_ROUTES["CONTACT"], methods=["GET", "POST"])
def contact():
    """
    Renders the contact page template.
    """
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    if request.method == "POST":
        return handle_contact()
    return render_template("contact.html")


@app.route("/logout")
def logout():
    """
    Handles user logout by clearing the session.
    """
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))


# RUN APP
if __name__ == "__main__":
    app.run()

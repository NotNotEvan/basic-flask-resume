"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

from datetime import datetime, timedelta
from os import environ
import os
from string import ascii_lowercase, ascii_uppercase, digits, punctuation
import tempfile

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

# Create a temporary directory for sessions
temp_session_dir = tempfile.mkdtemp()

# Session configuration
app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=temp_session_dir,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Initialize the Session extension
Session(app)


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


# HANDLERS
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


def validate_password(password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Validates password against security requirements.
    """
    validations = [
        # Check if passwords match
        (password == confirm_password, "Passwords do not match"),
        # Check if password contains uppercase letter
        (
            any(char in ascii_uppercase for char in password),
            "Password must contain at least one uppercase letter",
        ),
        # Check if password contains lowercase letter
        (
            any(char in ascii_lowercase for char in password),
            "Password must contain at least one lowercase letter",
        ),
        # Check if password contains number
        (
            any(char in digits for char in password),
            "Password must contain at least one number",
        ),
        # Check if password contains special character
        (
            any(char in punctuation for char in password),
            "Password must contain at least one special character",
        ),
        # Check if password is at least 12 characters long
        (len(password) >= 12, "Password must be at least 12 characters long"),
    ]

    # Validate password
    for is_valid, error_message in validations:
        if not is_valid:
            return False, error_message

    return True, ""


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
    is_valid, error_message = validate_password(password, confirm_password)
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

    try:
        # Check if database is loaded
        if not os.path.exists(DATABASE_FILE):
            raise IOError("Failed to load database")

        # Check if username exists
        if username not in db.users:
            flash("Username not found", "error")
            return render_template("login.html", username=username, password=password)

        # Verify password
        if not sha256_crypt.verify(password, db.users[username]):
            flash("Incorrect password", "error")
            return render_template("login.html", username=username, password=password)

        # Set session data
        session["username"] = username
        session["authenticated"] = True
        flash("Login successful!", "success")
        return redirect(url_for("home"))
    except IOError as e:
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
    is_valid, error_message = validate_password(password, confirm_password)
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

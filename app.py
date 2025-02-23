"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

from datetime import datetime, timedelta
from http import HTTPStatus
from werkzeug.exceptions import BadRequest
import tempfile

from passlib.hash import sha256_crypt
from flask_session import Session
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    jsonify,
    flash,
    url_for,
    session,
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "super_secret_key"

# Create a temporary directory for sessions
temp_session_dir = tempfile.mkdtemp()

# Session configuration
app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=temp_session_dir,
    SESSION_FILE_THRESHOLD=500,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Initialize the Session extension
Session(app)

# Route constants
URL_ROUTES = {
    "LOGIN": "/",
    "REGISTER": "/register",
    "HOME": "/home",
    "ABOUT": "/about",
    "CONTACT": "/contact",
}

# Initialize the database in the form of a text file
DATABASE = "database.txt"
db = {}


# Hash password
def hash_password(password):
    """
    Hashes a password using the sha256_crypt algorithm.
    """
    return sha256_crypt.hash(password)


# Verify password
def verify_password(password, hashed_password):
    """
    Verifies a password against a hashed password using the sha256_crypt algorithm.
    """
    return sha256_crypt.verify(password, hashed_password)


# Load database
def load_database():
    """
    Loads the database from a text file. Creates file if it doesn't exist.
    """
    try:
        with open(DATABASE, "a+"):  # Create file if it doesn't exist
            pass

        with open(DATABASE, "r") as file:
            for line in file:
                if line.strip():  # Skip empty lines
                    username, hashed_password = line.strip().split(":")
                    db[username] = hashed_password
    except Exception as e:
        print(f"Error loading database: {e}")
    return db


# Save database
def save_database():
    """
    Saves the database to a text file.
    """
    try:
        with open(DATABASE, "w") as file:
            for username, hashed_password in db.items():
                file.write(f"{username}:{hashed_password}\n")
        return True
    except Exception as e:
        print(f"Error saving database: {e}")
        return False


# Initialize database
load_database()


# HANDLERS
@app.route(URL_ROUTES["CONTACT"], methods=["POST"])
def handle_contact():
    """
    Handles the contact route's form submission.
    """
    try:
        # Get form data
        form_data = {
            "name": request.form.get("name"),
            "email": request.form.get("email"),
            "message": request.form.get("message"),
        }

        # Validate form data
        if not all(form_data.values()):
            raise BadRequest("All fields are required")

        # Process form data
        return jsonify(form_data), HTTPStatus.OK

    except BadRequest as e:
        # Log BadRequest error
        return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST


@app.route(URL_ROUTES["REGISTER"], methods=["POST"])
def handle_register():
    """
    Handles the register route's form submission.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # # Validate form data
    # if not username or not password:
    #     flash("Username and password are required")
    #     return redirect(url_for("register"))

    # if password != confirm_password:
    #     flash("Passwords do not match")
    #     return redirect(url_for("register"))

    # if len(password) < 8:
    #     flash("Password must be at least 8 characters long")
    #     return redirect(url_for("register"))

    # # Check if username already exists
    # if username in db:
    #     flash("Username already exists")
    #     return redirect(url_for("register"))

    # Hash password and save to database
    try:
        hashed_password = hash_password(password)
        db[username] = hashed_password
        if save_database():
            flash("Registration successful! Please login.")
            return redirect(url_for("login"))
        else:
            flash("Error saving registration. Please try again.")
    except Exception as e:
        flash(f"Registration error: {str(e)}")

    return redirect(url_for("register"))


@app.route(URL_ROUTES["LOGIN"], methods=["POST"])
def handle_login():
    """
    Handles the login route's form submission.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    # Validate form data
    if not username or not password:
        flash("Username and password are required")
        return redirect(url_for("login"))

    try:
        # Check credentials
        if username in db and verify_password(password, db[username]):
            # Set session data
            session["username"] = username
            session["authenticated"] = True
            flash("Login successful!")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password")
    except Exception as e:
        flash(f"Login error: {str(e)}")

    return redirect(url_for("login"))


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
    return render_template("login.html")


@app.route(URL_ROUTES["REGISTER"], methods=["GET", "POST"])
def register():
    """
    Renders the register page template.
    """
    if request.method == "POST":
        return handle_register()
    return render_template("register.html")


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
    return redirect(url_for("login"))


# RUN APP
if __name__ == "__main__":
    app.run()

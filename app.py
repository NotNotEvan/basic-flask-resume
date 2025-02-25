"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

from datetime import datetime, timedelta
from werkzeug.exceptions import BadRequest
import tempfile
from string import digits, ascii_uppercase, ascii_lowercase, punctuation

from passlib.hash import sha256_crypt
from flask_session import Session
from flask import (
    Flask,
    redirect,
    render_template,
    request,
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

        # Check if user is authenticated
        if not session.get("authenticated"):
            flash("Please login to send a message", "error")
            return redirect(url_for("login"))

        # Validate form data
        if not all(form_data.values()):
            flash("All fields are required", "error")
            return render_template("contact.html", form_data=form_data)

        # Process form data
        print(form_data)
        flash("Message sent successfully!", "success")
        return render_template("contact.html")

    except BadRequest:
        # Log BadRequest error
        flash(f"Error sending message. Please try again.", "error")
        return render_template("contact.html")


def validate_password(password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Validates password against security requirements.
    """
    if password != confirm_password:
        return False, "Passwords do not match"

    if not any(char in ascii_uppercase for char in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(char in ascii_lowercase for char in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(char in digits for char in password):
        return False, "Password must contain at least one number"

    if not any(char in punctuation for char in password):
        return False, "Password must contain at least one special character"

    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    return True, ""


@app.route(URL_ROUTES["REGISTER"], methods=["POST"])
def handle_register():
    """
    Handles the register route's form submission.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # Validate password
    is_valid, error_message = validate_password(password, confirm_password)
    if not is_valid:
        flash(error_message, "error")
        return render_template(
            "register.html",
            username=username,
            password=password,
            confirm_password=confirm_password,
        )

    # Check if username already exists
    if username in db:
        flash("Username already exists", "error")
        return render_template(
            "register.html",
            username=username,
            password=password,
            confirm_password=confirm_password,
        )

    # Hash password and save to database
    try:
        hashed_password = sha256_crypt.hash(password)
        db[username] = hashed_password
        if save_database():
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Error saving registration. Please try again.", "error")
            return render_template(
                "register.html",
                username=username,
                password=password,
                confirm_password=confirm_password,
            )
    except Exception as e:
        flash(f"Registration error: {str(e)}", "error")
        return render_template(
            "register.html",
            username=username,
            password=password,
            confirm_password=confirm_password,
        )


@app.route(URL_ROUTES["LOGIN"], methods=["POST"])
def handle_login():
    """
    Handles the login route's form submission.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    try:
        # Check credentials
        if username in db and sha256_crypt.verify(password, db[username]):
            # Set session data
            session["username"] = username
            session["authenticated"] = True
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html", username=username, password=password)
    except Exception as e:
        flash(f"Login error: {str(e)}", "error")
        return render_template("login.html", username=username, password=password)


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

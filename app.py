"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

from datetime import datetime
from http import HTTPStatus
from werkzeug.exceptions import BadRequest
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    jsonify,
    flash,
    url_for,
)

# Initialize Flask app
app = Flask(__name__)

# Route constants
URL_ROUTES = {
    "LOGIN": "/",
    "REGISTER": "/register",
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
    username = request.form["username"]
    password = request.form["password"]
    error = None

    # Validate form data
    if not username:
        error = "Username is required"
    elif not password:
        error = "Password is required"
    flash(error)

    # TODO: Encrypt and store credentials

    if not error:
        return redirect(url_for("login"))


# ROUTES
@app.route(URL_ROUTES["LOGIN"], methods=["GET", "POST"])
def login():
    """
    Renders the login page template.
    """
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
    return render_template("home.html")


@app.route(URL_ROUTES["ABOUT"])
def about():
    """
    Renders the about page template.
    """
    # Get current time
    current_time = datetime.now().strftime("%B %d, %Y %I:%M %p")
    return render_template("about.html", current_time=current_time)


@app.route(URL_ROUTES["CONTACT"], methods=["GET", "POST"])
def contact():
    """
    Renders the contact page template.
    """
    # Handle form submission
    if request.method == "POST":
        return handle_contact()
    return render_template("contact.html")


# RUN APP
if __name__ == "__main__":
    app.run()

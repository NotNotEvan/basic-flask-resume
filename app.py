"""
A Flask-based resume website application.

This module implements a simple resume website with home, about, and contact pages,
providing basic routing and form handling functionality.
"""

from datetime import datetime
from http import HTTPStatus
from werkzeug.exceptions import BadRequest

from flask import Flask, render_template, request, jsonify

# Initialize Flask app
app = Flask(__name__)

# Route constants
URL_ROUTES = {"HOME": "/", "ABOUT": "/about", "CONTACT": "/contact"}


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


@app.route(URL_ROUTES["HOME"])
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

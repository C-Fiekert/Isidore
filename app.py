# Project Imports
from flask import Flask, request, render_template
from system import Settings
import os, webbrowser, hashlib



# Defining Flask App
app = Flask(__name__)

# Home page
@app.route("/Home", methods=["POST", "GET"])
def home():
    # Returns the Home page
    return render_template("home.html")

# Search History page
@app.route("/History", methods=["POST", "GET"])
def history():
    # Returns the Search History page
    return render_template("history.html")

# Settings page
@app.route("/Settings", methods=["POST", "GET"])
def settings():
    # Returns the Settings page
    return render_template("settings.html")

# URL page
@app.route("/Url", methods=["POST", "GET"])
def url():
    # Returns the URL Query page
    return render_template("url.html")

# IP Address page
@app.route("/IP", methods=["POST", "GET"])
def ip():
    # Returns the IP Address Query page
    return render_template("ip.html")

# Domain page
@app.route("/Domain", methods=["POST", "GET"])
def domain():
    # Returns the Domain Query page
    return render_template("domain.html")

# File Hash page
@app.route("/FileHash", methods=["POST", "GET"])
def filehash():
    # Returns the File Hash Query page
    return render_template("filehash.html")
    

# Instanciates the Flask server and opens the dashboard automatically on localhost
if __name__ == "__main__":
    webbrowser.open_new("http://127.0.0.1:5000/home")
    app.run(debug=False)
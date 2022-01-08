# Project Imports
from flask import Flask, request, render_template
from system import Settings, initialise
import os, webbrowser, hashlib

# Defining Flask App
app = Flask(__name__)

userSettings = Settings("", "", "", "", "", "")
initialise(userSettings)


# Home page
@app.route("/home", methods=["POST", "GET"])
def home():
    global userSettings
    keyAdded = 0

    if request.method == "POST":
        try:
            # Grabs the submitted service and API key
            service = request.form.get("service")
            key = request.form["key"]
            if key == "":
                keyAdded = 3
            else:
                userSettings.updateApiKey(service, key)
                f = open("keys.txt", "w")
                f.write("VT:" + userSettings.virustotalKey + "\n")
                f.write("US:" + userSettings.urlscanKey + "\n")
                f.write("HA:" + userSettings.hybridAnalysisKey + "\n")
                f.write("AIP:" + userSettings.abuseIPKey + "\n")
                f.write("SH:" + userSettings.shodanKey + "\n")
                f.write("IP:" + userSettings.ipInfoKey + "\n")
                f.close()
                keyAdded = 1
        except:
            keyAdded = 2

    # Returns the Home page
    return render_template("home.html", keyAdded=keyAdded)

    

# Search History page
@app.route("/history", methods=["POST", "GET"])
def history():
    # Returns the Search History page
    return render_template("history.html")

# Settings page
@app.route("/settings", methods=["POST", "GET"])
def settings():
    # Returns the Settings page
    return render_template("settings.html")

# URL page
@app.route("/url", methods=["POST", "GET"])
def url():
    # Returns the URL Query page
    return render_template("url.html")

# IP Address page
@app.route("/ip", methods=["POST", "GET"])
def ip():
    # Returns the IP Address Query page
    return render_template("ip.html")

# Domain page
@app.route("/domain", methods=["POST", "GET"])
def domain():
    # Returns the Domain Query page
    return render_template("domain.html")

# File Hash page
@app.route("/filehash", methods=["POST", "GET"])
def filehash():
    # Returns the File Hash Query page
    return render_template("filehash.html")
    

# Instanciates the Flask server and opens the dashboard automatically on localhost
if __name__ == "__main__":
    webbrowser.open_new("http://127.0.0.1:5000/home")
    app.run(debug=False)
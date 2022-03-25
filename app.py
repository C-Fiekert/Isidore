# Project Imports
from cgitb import html
from flask import Flask, request, render_template
from api import HybridAnalysis, Urlscan, VtUrl, VtIP, AbuseIP, Greynoise, Shodan, IPinfo
from system import Settings, UrlQuery, IPQuery, initialise
import os, webbrowser, hashlib, datetime

# Defining Flask App
app = Flask(__name__)

userSettings = Settings("", "", "", "", "", "")
initialise(userSettings)


# Home page
@app.route("/home", methods=["POST", "GET"])
def home():
    global userSettings
    keyAdded = 0
    # Runs if POST request received
    if request.method == "POST":
        try:
            # Grabs the submitted service and API key
            service = request.form.get("service")
            key = request.form["key"]
            # If the key is empty, return a warning
            if key == "":
                keyAdded = 3
            else:
                # Update the user settings
                userSettings.updateApiKey(service, key)
                f = open("keys.txt", "w")
                f.write("VT:" + userSettings.virustotalKey + "\n")
                f.write("US:" + userSettings.urlscanKey + "\n")
                f.write("HA:" + userSettings.hybridAnalysisKey + "\n")
                f.write("AIP:" + userSettings.abuseIPKey + "\n")
                f.write("SH:" + userSettings.shodanKey + "\n")
                f.write("IP:" + userSettings.ipInfoKey + "\n")
                f.close()
                # Return a success notification
                
                keyAdded = 1
        except:
            # Return an error notification
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
    global userSettings
    keyAdded = 0
    # Runs if POST request received
    if request.method == "POST":
        try:
            # Grabs the submitted service and API key
            service = request.form.get("service")
            key = request.form["key"]
            # If the key is empty, return a warning
            if key == "":
                keyAdded = 3
            else:
                # Update the user settings
                userSettings.updateApiKey(service, key)
                f = open("keys.txt", "w")
                f.write("VT:" + userSettings.virustotalKey + "\n")
                f.write("US:" + userSettings.urlscanKey + "\n")
                f.write("HA:" + userSettings.hybridAnalysisKey + "\n")
                f.write("AIP:" + userSettings.abuseIPKey + "\n")
                f.write("SH:" + userSettings.shodanKey + "\n")
                f.write("IP:" + userSettings.ipInfoKey + "\n")
                f.close()
                # Return a success notification
                keyAdded = 1
        except:
            # Return an error notification
            keyAdded = 2

    # Returns the Settings page
    return render_template("settings.html", keyAdded=keyAdded)

# URL page
@app.route("/url", methods=["POST", "GET"])
def url():
    global userSettings
    disabled = "disabled"

    # Runs if POST request received
    if request.method == "POST":
        # try:
        userQueries = request.form["query"]
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        disabled = ""
        for input in userQueries:
        
            query = UrlQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "URL", "", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)

            if query.validate():
                virustotal = VtUrl("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                urlscan = Urlscan("", "", "", "", "", "", "", "", "", "", "", "", "", "")
                urlscan.retrieve(query.query, userSettings.urlscanKey)
                urlscanCard = urlscan.generate(count)

                hybridAnalysis = HybridAnalysis("", "", "")
                hybridAnalysis.retrieve(query.query, userSettings.hybridAnalysisKey)
                hybridAnalysisCard = hybridAnalysis.generate()

                query.setVirustotal(virustotal)
                query.setUrlscan(urlscan)
                query.setHybridAnalysis(hybridAnalysis)

                html += query.generateHTML(virustotalCard, urlscanCard, hybridAnalysisCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1
        
        return render_template("url.html", html=html, chart=chart, style=style, disabled=disabled)

        # except:
        #     return render_template("url.html")
    # Returns the URL Query page
    return render_template("url.html", disabled=disabled)

# IP Address page
@app.route("/ip", methods=["POST", "GET"])
def ip():
    global userSettings
    
    # Runs if POST request received
    if request.method == "POST":
        # try:
        userQueries = request.form["query"]
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        for input in userQueries:
        
            query = IPQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "IP Address", "", "", "", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)

            if query.validate():
                virustotal = VtIP("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                abuseIp = AbuseIP("", "", "", "", "", "", "", "", "", "", "", "")
                abuseIp.retrieve(query.query, userSettings.abuseIPKey)
                abuseIpCard = abuseIp.generate(count)

                greynoise = Greynoise("", "", "", "", "", "", "")
                greynoise.retrieve(query.query)
                greynoiseCard = greynoise.generate()

                shodan = Shodan("", "", "", "", "", "", "", "", "", "", "", "")
                shodan.retrieve(query.query, userSettings.shodanKey)
                shodanCard = shodan.generate(count)

                ipInfo = IPinfo("", "", "", "", "", "", "", "", "", "")
                ipInfo.retrieve(query.query, userSettings.ipInfoKey)
                ipInfoCard = ipInfo.generate()

                query.setVirustotal(virustotal)
                query.setAbuseIP(abuseIp)
                query.setGreynoise(greynoise)
                query.setShodan(shodan)
                query.setIPInfo(ipInfo)

                html += query.generateHTML(virustotalCard, abuseIpCard, greynoiseCard, shodanCard, ipInfoCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1
        
        return render_template("ip.html", html=html, chart=chart, style=style)

        # except:
        #     return render_template("url.html")
    # Returns the URL Query page
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
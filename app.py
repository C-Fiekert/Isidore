# Project Imports
from attr import asdict
from flask import Flask, request, render_template, redirect
from matplotlib.pyplot import hist
from api import HybridAnalysis, Urlscan, VtUrl, VtIP, VtDomain, VtFileHash, AbuseIP, Greynoise, Shodan, IPinfo
from system import Settings, UrlQuery, IPQuery, DomainQuery, FileHashQuery, initialise
import os, webbrowser, hashlib, datetime, pyrebase
import json
from json import JSONEncoder

# Defining Flask App
app = Flask(__name__)

config = {
    "apiKey": "AIzaSyAzydxPiVakaZdrKMZ5e2aqXsOxXKeb6CM",
    "authDomain": "isidore-5c6c3.firebaseapp.com",
    "databaseURL": "https://isidore-5c6c3-default-rtdb.europe-west1.firebasedatabase.app/",
    "projectId": "isidore-5c6c3",
    "storageBucket": "isidore-5c6c3.appspot.com",
    "messagingSenderId": "616530519567",
    "appId": "1:616530519567:web:85d62ec1e197137b16257a"
}

firebase = pyrebase.initialize_app(config)
db = firebase.database()
auth = firebase.auth()
userSettings = Settings("", "", "", "", "", "")

class QueryEncoder(JSONEncoder):
        def default(self, o):
            return o.__dict__

@app.route("/", methods=["POST", "GET"])
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        # try:
        if request.form["loginemail"] != None and request.form["loginpw"] != None:
            email = request.form["loginemail"]
            password = request.form["loginpw"]
            auth.sign_in_with_email_and_password(email, password)
            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
            initialise(userSettings, user)
            return redirect("/home")
        # except:
        #     print("Error")
        #     return redirect("/")
    return redirect("/")

@app.route("/signup", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        try:
            if request.form["signemail"] != None and request.form["signpw"] != None:
                email = request.form["signemail"]
                password = request.form["signpw"]
                auth.create_user_with_email_and_password(email, password)
                return redirect("/home")
        except:
            print("Error")
            return redirect("/")
    return redirect("/")

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
                keyAdded = 1
        except:
            # Return an error notification
            keyAdded = 2

    table = ""
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    history = db.child("Settings").child(user).child("History").get()
    times= []
    if history.val() != None:
        for item in history.each():
            times.append(datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"))
        times.sort(reverse=True)
        times = times[:3]
        for time in times:
            for item in history.each():
                if time == datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"):
                    name = item.val()["Query"]
                    if len(name) > 40:
                        name = name[:40] + "\n" + name[40:]
                    table = "<tr class='odd'><td class='sorting_1 dtr-control' tabindex='0' style=>" + item.val()["Time"] + "</td> <td>" + name + "</td> <td>" + str(item.val()["VT Malicious Detections"]) + " malicious detections out of " + str(item.val()["VT Total Detections"]) + "</td> <td>" + item.val()["Type"] + "</td></tr>" + table

    # Returns the Home page
    return render_template("home.html", info=table, keyAdded=keyAdded)

# Search History page
@app.route("/history", methods=["POST", "GET"])
def history():
    table = ""
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    history = db.child("Settings").child(user).child("History").get()
    times= []
    if history.val() != None:
        for item in history.each():
            times.append(datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"))
        times.sort(reverse=True)
        for time in times:
            for item in history.each():
                if time == datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"):
                    name = item.val()["Query"]
                    if len(name) > 40:
                        name = name[:40] + "\n" + name[40:]
                    table = "<tr class='odd'><td class='sorting_1 dtr-control' tabindex='0' style=>" + item.val()["Time"] + "</td> <td>" + name + "</td> <td>" + str(item.val()["VT Malicious Detections"]) + " malicious detections out of " + str(item.val()["VT Total Detections"]) + "</td> <td>" + item.val()["Type"] + "</td></tr>" + table
    # Loads the page with the query search history
    return render_template("history.html", info=table)

@app.route('/clear')
def clear():
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    db.child("Settings").child(user).child("History").remove()
    # Returns the search history page
    return render_template("history.html", info="")

# Settings page
@app.route("/settings", methods=["POST", "GET"])
def settings():
    global userSettings
    keyAdded = 0
    # Runs if POST request received
    if request.method == "POST":
        # try:
            # Grabs the submitted service and API key
        service = request.form.get("service")
        key = request.form["key"]
        # If the key is empty, return a warning
        if key == "":
            keyAdded = 3
        else:
            # Update the user settings
            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
            userSettings.updateApiKey(service, key, user)
            f = open("keys.txt", "w")
            f.write("VT:" + userSettings.virustotalKey + "\n")
            f.write("US:" + userSettings.urlscanKey + "\n")
            f.write("HA:" + userSettings.hybridAnalysisKey + "\n")
            f.write("AIP:" + userSettings.abuseIPKey + "\n")
            f.write("SH:" + userSettings.shodanKey + "\n")
            f.write("IP:" + userSettings.ipInfoKey + "\n")
            f.close()

            

            keys = {"Virustotal": userSettings.virustotalKey, 
                    "UrlScan": userSettings.urlscanKey, 
                    "Hybrid Analysis": userSettings.hybridAnalysisKey,
                    "AbuseIP": userSettings.abuseIPKey,
                    "Shodan": userSettings.shodanKey,
                    "IPinfo": userSettings.ipInfoKey}
            keyAdded = 1

        # except:
        #     # Return an error notification
        #     keyAdded = 2

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
                hybridAnalysis.retrieve(query.query, "url", userSettings.hybridAnalysisKey)
                hybridAnalysisCard = hybridAnalysis.generate("url")

                query.setVirustotal(virustotal)
                query.setUrlscan(urlscan)
                query.setHybridAnalysis(hybridAnalysis)

                html += query.generateHTML(virustotalCard, urlscanCard, hybridAnalysisCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("URL").child(query.qId).set(query.todict())
                print(query.submissionTime)
                print(time)

                history = {"Time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                    "Query": query.query, 
                    "VT Malicious Detections": query.virustotal.malDetection,
                    "VT Total Detections": query.virustotal.cleanDetection + query.virustotal.malDetection + query.virustotal.susDetection + query.virustotal.undetected,
                    "Type": "URL"}

                db.child("Settings").child(user).child("History").child(time).set(history)
        
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
                chart += query.generateChart(virustotal, abuseIp, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                count += 1

                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("IP").child(query.qId).set(query.todict())

                history = {"Time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                    "Query": query.query, 
                    "VT Malicious Detections": query.virustotal.malDetection,
                    "VT Total Detections": query.virustotal.cleanDetection + query.virustotal.malDetection + query.virustotal.susDetection + query.virustotal.undetected,
                    "Type": "IP"}

                db.child("Settings").child(user).child("History").child(time).set(history)
        
        return render_template("ip.html", html=html, chart=chart, style=style)

        # except:
        #     return render_template("url.html")
    # Returns the URL Query page
    return render_template("ip.html")

# Domain page
@app.route("/domain", methods=["POST", "GET"])
def domain():
    # Returns the Domain Query page
    global userSettings

    # Runs if POST request received
    if request.method == "POST":
        # try:
        userQueries = request.form["query"]
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        disabled = ""
        for input in userQueries:
        
            query = DomainQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "Domain", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)

            if query.validate():
                virustotal = VtDomain("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                urlscan = Urlscan("", "", "", "", "", "", "", "", "", "", "", "", "", "")
                urlscan.retrieve(query.query, userSettings.urlscanKey)
                urlscanCard = urlscan.generate(count)

                query.setVirustotal(virustotal)
                query.setUrlscan(urlscan)

                html += query.generateHTML(virustotalCard, urlscanCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("Domain").child(query.qId).set(query.todict())

                history = {"Time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                    "Query": query.query, 
                    "VT Malicious Detections": query.virustotal.malDetection,
                    "VT Total Detections": query.virustotal.cleanDetection + query.virustotal.malDetection + query.virustotal.susDetection + query.virustotal.undetected,
                    "Type": "Domain"}

                db.child("Settings").child(user).child("History").child(time).set(history)
        
        return render_template("domain.html", html=html, chart=chart, style=style)

        # except:
        #     return render_template("domain.html")
    # Returns the Domain Query page
    return render_template("domain.html")

# File Hash page
@app.route("/filehash", methods=["POST", "GET"])
def filehash():
    # Returns the File Hash Query page
    global userSettings

    # Runs if POST request received
    if request.method == "POST":
        # try:
        userQueries = request.form["query"]
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        for input in userQueries:
        
            query = FileHashQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "File Hash", "", "")
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)

            if query.validate():
                virustotal = VtFileHash("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                hybridAnalysis = HybridAnalysis("", "", "")
                hybridAnalysis.retrieve(query.query, "filehash", userSettings.hybridAnalysisKey)
                hybridAnalysisCard = hybridAnalysis.generate("filehash")

                query.setVirustotal(virustotal)
                query.setHybridAnalysis(hybridAnalysis)

                html += query.generateHTML(virustotalCard, hybridAnalysisCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("Filehash").child(query.qId).set(query.todict())

                history = {"Time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
                    "Query": query.query, 
                    "VT Malicious Detections": query.virustotal.malDetection,
                    "VT Total Detections": query.virustotal.cleanDetection + query.virustotal.malDetection + query.virustotal.susDetection + query.virustotal.undetected,
                    "Type": "Filehash"}

                db.child("Settings").child(user).child("History").child(time).set(history)
        
        return render_template("filehash.html", html=html, chart=chart, style=style)

        # except:
        #     return render_template("url.html")
    # Returns the URL Query page
    return render_template("filehash.html")
    

# Instanciates the Flask server and opens the dashboard automatically on localhost
if __name__ == "__main__":
    webbrowser.open_new("http://127.0.0.1:5000/")
    app.run(debug=False)
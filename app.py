# Project Imports
from flask import Flask, request, render_template, redirect
from apis.virustotal import VtUrl, VtIP, VtDomain, VtFileHash
from apis.urlscan import Urlscan
from apis.hybridanalysis import HybridAnalysis
from apis.abuseip import AbuseIP
from apis.greynoise import Greynoise
from apis.shodan import Shodan
from apis.ipinfo import IPinfo
from system import Settings, UrlQuery, IPQuery, DomainQuery, FileHashQuery, initialise
import webbrowser, hashlib, datetime, pyrebase

# Defining Flask App
app = Flask(__name__)

# Firebase configuration
config = {
    "apiKey": "API-KEY",
    "authDomain": "isidore-5c6c3.firebaseapp.com",
    "databaseURL": "https://isidore-5c6c3-default-rtdb.europe-west1.firebasedatabase.app/",
    "projectId": "isidore-5c6c3",
    "storageBucket": "isidore-5c6c3.appspot.com",
    "messagingSenderId": "616530519567",
    "appId": "1:616530519567:web:85d62ec1e197137b16257a"
}

# Initialising Firebase objects
firebase = pyrebase.initialize_app(config)
db = firebase.database()
auth = firebase.auth()
# Defines user settings and global variables
userSettings = Settings("", "", "", "", "", "")
search = ""
cache = []

# Front page
@app.route("/", methods=["POST", "GET"])
def index():
    return render_template("index.html")

# Login route
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        try:
            # Checks if all credentials are provided
            if request.form["loginemail"] != None and request.form["loginpw"] != None:
                email = request.form["loginemail"]
                password = request.form["loginpw"]
                # Signs the user in and initialises their API keys
                auth.sign_in_with_email_and_password(email, password)
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                initialise(userSettings, user)
                # Redirect user to the homepage
                return redirect("/home")
        except:
            print("Error")
            return redirect("/")
    return redirect("/")

# Sign-Up route
@app.route("/signup", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        try:
            # Checks if all credentials are provided
            if request.form["signemail"] != None and request.form["signpw"] != None:
                email = request.form["signemail"]
                password = request.form["signpw"]
                # Creates a new user account and logs them in
                auth.create_user_with_email_and_password(email, password)
                auth.sign_in_with_email_and_password(email, password)
                # Redirect the user to the homepage
                return redirect("/home")
        except:
            print("Error")
            return redirect("/")
    return redirect("/")

# Sign-Out route
@app.route("/signout", methods=["POST", "GET"])
def signout():
    # Grab current user instance and remove their query history
    auth.current_user = None
    # Returns the search history page
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
    # Gets the current user instance and retrieves their query history
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    history = db.child("Settings").child(user).child("History").get()
    times= []
    # Grabs the users query history and sorts it by data from newest to oldest
    if history.val() != None:
        for item in history.each():
            times.append(datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"))
        times.sort(reverse=True)
        # Grabs the 3 newest historical queries and displays them on the homepage as a preview
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
    # Grab current user instance and get their query history
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    history = db.child("Settings").child(user).child("History").get()
    times= []
    # Checks if there is history
    if history.val() != None:
        # Gets the time of each historical query
        for item in history.each():
            times.append(datetime.datetime.strptime(item.val()["Time"], "%d/%m/%Y %H:%M:%S"))
        times.sort(reverse=False)
        # Grabs each historical query and orders them by date from newest to oldest
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
    # Grab current user instance and remove their query history
    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    db.child("Settings").child(user).child("History").remove()
    # Returns the search history page
    return redirect("/history")

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
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                userSettings.updateApiKey(service, key, user)
                keyAdded = 1

        except:
            # Return an error notification
            keyAdded = 2

    # Returns the Settings page
    return render_template("settings.html", keyAdded=keyAdded)

# URL page
@app.route("/url", methods=["POST", "GET"])
def url():
    global userSettings, search, cache
    disabled = "disabled"

    # Runs if POST request received
    if request.method == "POST":
        try:
            # Splits each query separated by space and initialises generation variables
            userQueries = request.form["query"]
            search = request.form["query"]
            userQueries = userQueries.split(' ')
            html, chart, style = "", "", ""
            count = 0
            disabled = ""
            # Runs for each query inpput
            for input in userQueries:
                cached = False
                query = UrlQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "URL", "", "", "")
                query.defang()
                qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
                query.setQID(qId)

                # Checks if query is in cache
                for item in cache:
                    if item.qId == query.qId:
                        query = item
                        cached = True
                        break
                
                # Grabs query from cache if cached
                if cached:
                    print("Cached")
                    virustotalCard = query.virustotal.generate(count)
                    urlscanCard = query.urlscan.generate(count)
                    hybridAnalysisCard = query.hybridAnalysis.generate("url")

                    html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, hybridAnalysisCard, count)
                    chart += query.generateChart(query.virustotal, count)
                    style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                    count += 1
                    storeHistory(query, "URL")
                # Grabs query from database if in database
                else:
                    stored = False
                    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                    history = db.child("Queries").child("URL").child(query.qId).get()
                    if history.val() != None:
                        stored = True
                        query = query.fromdict(history)

                    if stored:
                        print("Stored")
                        virustotalCard = query.virustotal.generate(count)
                        urlscanCard = query.urlscan.generate(count)
                        hybridAnalysisCard = query.hybridAnalysis.generate("url")

                        html += query.generateHTML(history.val()["Submission Time"], virustotalCard, urlscanCard, hybridAnalysisCard, count)
                        chart += query.generateChart(query.virustotal, count)
                        style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                        count += 1

                        if len(cache) < 5:
                            cache.append(query)
                        else:
                            cache.pop(0)
                            cache.append(query)
                        storeHistory(query, "URL")
                    # Queries each API for information if not cached or stored in database
                    else:
                        if query.validate():
                            print("Query")
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

                            # Generates HTML and charts
                            html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, hybridAnalysisCard, count)
                            chart += query.generateChart(virustotal, count)
                            style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                            count += 1

                            # Stores the query to Isidore database
                            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                            time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                            db.child("Queries").child("URL").child(query.qId).set(query.todict())

                            if len(cache) < 5:
                                cache.append(query)
                            else:
                                cache.pop(0)
                                cache.append(query)
                            storeHistory(query, "URL")
            
            return render_template("url.html", html=html, chart=chart, style=style, value=query.query, disabled=disabled)

        except:
            return render_template("url.html")
    # Returns the URL Query page
    return render_template("url.html", disabled=disabled)

# URL page
@app.route("/url-analyse", methods=["POST", "GET"])
def urlAnalyse():
    global userSettings, search
    disabled = "disabled"

    try:
        # Splits the user query by space
        userQueries = search
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        # Cycles for each query input
        for input in userQueries:
            query = UrlQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "URL", "", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)
            # Fethces information from APIs if query is valid
            if query.validate():
                print("Re-Analysing")
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

                # Generates HTML for page and charts
                html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, hybridAnalysisCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                # Adds query to the Isidore database
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("URL").child(query.qId).set(query.todict())

                if len(cache) < 5:
                    cache.append(query)
                else:
                    cache.pop(0)
                    cache.append(query)
                storeHistory(query, "URL")
        
        return render_template("url.html", html=html, chart=chart, style=style, disabled=disabled)
    except:
        return render_template("url.html")

# IP Address page
@app.route("/ip", methods=["POST", "GET"])
def ip():
    global userSettings, search, cache
    disabled = "disabled"
    
    # Runs if POST request received
    if request.method == "POST":
        try:
            # Splits the query by space
            userQueries = request.form["query"]
            search = request.form["query"]
            userQueries = userQueries.split(' ')
            html, chart, style = "", "", ""
            count = 0
            disabled = ""
            # Cycles for each query input
            for input in userQueries:
                cached = False
                query = IPQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "IP Address", "", "", "", "", "")
                query.defang()
                qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
                query.setQID(qId)

                for item in cache:
                    if item.qId == query.qId:
                        query = item
                        cached = True
                        break
                # Returns query if cached
                if cached:
                    print("Cached")
                    virustotalCard = query.virustotal.generate(count)
                    abuseIpCard = query.abuseIP.generate(count)
                    greynoiseCard = query.greynoise.generate()
                    shodanCard = query.shodan.generate(count)
                    ipInfoCard = query.ipInfo.generate()

                    html += query.generateHTML(query.submissionTime, virustotalCard, abuseIpCard, greynoiseCard, shodanCard, ipInfoCard, count)
                    chart += query.generateChart(query.virustotal, query.abuseIP, count)
                    style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                    count += 1

                    storeHistory(query, "IP")

                # Returns query if stored in Isidore database
                else:
                    stored = False
                    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                    history = db.child("Queries").child("IP").child(query.qId).get()
                    if history.val() != None:
                        stored = True
                        query = query.fromdict(history)

                    if stored:
                        print("Stored")
                        virustotalCard = query.virustotal.generate(count)
                        abuseIpCard = query.abuseIP.generate(count)
                        greynoiseCard = query.greynoise.generate()
                        shodanCard = query.shodan.generate(count)
                        ipInfoCard = query.ipInfo.generate()

                        html += query.generateHTML(history.val()["Submission Time"], virustotalCard, abuseIpCard, greynoiseCard, shodanCard, ipInfoCard, count)
                        chart += query.generateChart(query.virustotal, query.abuseIP, count)
                        style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                        count += 1

                        if len(cache) < 5:
                            cache.append(query)
                        else:
                            cache.pop(0)
                            cache.append(query)

                        storeHistory(query, "IP")
                    else:
                        # Retrieves information from APIs if query is not in cache or database
                        if query.validate():
                            print("Query")
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

                            # Generates HTML for page and charts
                            html += query.generateHTML(query.submissionTime, virustotalCard, abuseIpCard, greynoiseCard, shodanCard, ipInfoCard, count)
                            chart += query.generateChart(virustotal, abuseIp, count)
                            style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                            count += 1

                            # Adds query to Isidore database
                            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                            time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                            db.child("Queries").child("IP").child(query.qId).set(query.todict())

                            if len(cache) < 5:
                                cache.append(query)
                            else:
                                cache.pop(0)
                                cache.append(query)

                            storeHistory(query, "IP")
            
            return render_template("ip.html", html=html, chart=chart, style=style, disabled=disabled)

        except:
            return render_template("url.html")
    # Returns the URL Query page
    return render_template("ip.html", disabled=disabled)

@app.route("/ip-analyse", methods=["POST", "GET"])
def ipAnalyse():
    global userSettings, search
    disabled = "disabled"

    try:
        # Splits the query by spaces
        userQueries = search
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        # Cycles through each query input
        for input in userQueries:
            query = IPQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "IP Address", "", "", "", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)
            # Retrieves information from APIs if query is valid
            if query.validate():
                print("Re-Analysing")
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

                # Generates HTML for page and charts
                html += query.generateHTML(query.submissionTime, virustotalCard, abuseIpCard, greynoiseCard, shodanCard, ipInfoCard, count)
                chart += query.generateChart(virustotal, abuseIp, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                count += 1

                # Stores query in Isidore database
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("IP").child(query.qId).set(query.todict())

                if len(cache) < 5:
                    cache.append(query)
                else:
                    cache.pop(0)
                    cache.append(query)

                storeHistory(query, "IP")
        
        return render_template("ip.html", html=html, chart=chart, style=style, disabled=disabled)
    except:
        return render_template("ip.html")


# Domain page
@app.route("/domain", methods=["POST", "GET"])
def domain():
    # Returns the Domain Query page
    global userSettings, search, cache
    disabled = "disabled"

    # Runs if POST request received
    if request.method == "POST":
        try:
            # Splits query by spaces
            userQueries = request.form["query"]
            search = request.form["query"]
            userQueries = userQueries.split(' ')
            html, chart, style = "", "", ""
            count = 0
            disabled = ""
            # Cycles for each query input
            for input in userQueries:
                cached = False
                query = DomainQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "Domain", "", "")
                query.defang()
                qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
                query.setQID(qId)

                for item in cache:
                    if item.qId == query.qId:
                        query = item
                        cached = True
                        break
                # Returns query if cached
                if cached:
                    print("Cached")
                    virustotalCard = query.virustotal.generate(count)
                    urlscanCard = query.urlscan.generate(count)

                    html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, count)
                    chart += query.generateChart(query.virustotal, count)
                    style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                    count += 1

                    storeHistory(query, "Domain")

                # Returns query if stored in Isidore database
                else:
                    stored = False
                    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                    history = db.child("Queries").child("Domain").child(query.qId).get()
                    if history.val() != None:
                        stored = True
                        query = query.fromdict(history)

                    if stored:
                        print("Stored")
                        virustotalCard = query.virustotal.generate(count)
                        urlscanCard = query.urlscan.generate(count)

                        html += query.generateHTML(history.val()["Submission Time"], virustotalCard, urlscanCard, count)
                        chart += query.generateChart(query.virustotal, count)
                        style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                        count += 1

                        if len(cache) < 5:
                            cache.append(query)
                        else:
                            cache.pop(0)
                            cache.append(query)

                        storeHistory(query, "Domain")

                    # Retrieves information from APIs if not cached or stored in database
                    else:
                        if query.validate():
                            print("Query")
                            virustotal = VtDomain("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                            virustotal.retrieve(query.query, userSettings.virustotalKey)
                            virustotalCard = virustotal.generate(count)

                            urlscan = Urlscan("", "", "", "", "", "", "", "", "", "", "", "", "", "")
                            urlscan.retrieve(query.query, userSettings.urlscanKey)
                            urlscanCard = urlscan.generate(count)

                            query.setVirustotal(virustotal)
                            query.setUrlscan(urlscan)

                            html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, count)
                            chart += query.generateChart(virustotal, count)
                            style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                            count += 1

                            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                            time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                            db.child("Queries").child("Domain").child(query.qId).set(query.todict())

                            if len(cache) < 5:
                                cache.append(query)
                            else:
                                cache.pop(0)
                                cache.append(query)

                            storeHistory(query, "Domain")
            
            return render_template("domain.html", html=html, chart=chart, style=style, disabled=disabled)

        except:
            return render_template("domain.html")
    # Returns the Domain Query page
    return render_template("domain.html", disabled=disabled)

@app.route("/domain-analyse", methods=["POST", "GET"])
def domainAnalyse():
    global userSettings, search
    disabled = "disabled"

    try:
        # Splits the query by spaces
        userQueries = search
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        # Cycles through each query input
        for input in userQueries:
            query = DomainQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "Domain", "", "")
            query.defang()
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)
            # Retrieves information from each API if query is valid
            if query.validate():
                print("Query")
                virustotal = VtDomain("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                urlscan = Urlscan("", "", "", "", "", "", "", "", "", "", "", "", "", "")
                urlscan.retrieve(query.query, userSettings.urlscanKey)
                urlscanCard = urlscan.generate(count)

                query.setVirustotal(virustotal)
                query.setUrlscan(urlscan)

                # Generates HTML for page and charts
                html += query.generateHTML(query.submissionTime, virustotalCard, urlscanCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                # Adds the query to the Isidore database
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("Domain").child(query.qId).set(query.todict())

                if len(cache) < 5:
                    cache.append(query)
                else:
                    cache.pop(0)
                    cache.append(query)

                storeHistory(query, "Domain")
        
        return render_template("domain.html", html=html, chart=chart, style=style, disabled=disabled)
    except:
        return render_template("domain.html")


# File Hash page
@app.route("/filehash", methods=["POST", "GET"])
def filehash():
    # Returns the File Hash Query page
    global userSettings, search, cache
    disabled = "disabled"

    # Runs if POST request received
    if request.method == "POST":
        try:
            # Splits the query by spaces
            userQueries = request.form["query"]
            search = request.form["query"]
            userQueries = userQueries.split(' ')
            html, chart, style = "", "", ""
            count = 0
            disabled = ""
            # Cycles through each query input
            for input in userQueries:
                cached = False
                query = FileHashQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "File Hash", "", "")
                qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
                query.setQID(qId)

                for item in cache:
                    if item.qId == query.qId:
                        query = item
                        cached = True
                        break
                # Returns the query if cached
                if cached:
                    print("Cached")
                    virustotalCard = query.virustotal.generate(count)
                    hybridAnalysisCard = query.hybridAnalysis.generate(count)

                    html += query.generateHTML(query.submissionTime, virustotalCard, hybridAnalysisCard, count)
                    chart += query.generateChart(query.virustotal, count)
                    style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                    count += 1

                    storeHistory(query, "Filehash")
                # Returns the query if stored in the Isidore database
                else:
                    stored = False
                    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                    history = db.child("Queries").child("Filehash").child(query.qId).get()
                    if history.val() != None:
                        stored = True
                        query = query.fromdict(history)

                    if stored:
                        print("Stored")
                        virustotalCard = query.virustotal.generate(count)
                        hybridAnalysisCard = query.hybridAnalysis.generate(count)

                        html += query.generateHTML(history.val()["Submission Time"], virustotalCard, hybridAnalysisCard, count)
                        chart += query.generateChart(query.virustotal, count)
                        style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }#chart2div' + str(count) + ' {width: 100%; height: 400px; } '
                        count += 1

                        if len(cache) < 5:
                            cache.append(query)
                        else:
                            cache.pop(0)
                            cache.append(query)

                        storeHistory(query, "Filehash")
                    # Retrieves information from each API if query not in cache or database
                    else:
                        if query.validate():
                            print("Query")
                            virustotal = VtFileHash("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                            virustotal.retrieve(query.query, userSettings.virustotalKey)
                            virustotalCard = virustotal.generate(count)

                            hybridAnalysis = HybridAnalysis("", "", "")
                            hybridAnalysis.retrieve(query.query, "filehash", userSettings.hybridAnalysisKey)
                            hybridAnalysisCard = hybridAnalysis.generate("filehash")

                            query.setVirustotal(virustotal)
                            query.setHybridAnalysis(hybridAnalysis)

                            # Generates HTML for page and charts
                            html += query.generateHTML(query.submissionTime, virustotalCard, hybridAnalysisCard, count)
                            chart += query.generateChart(virustotal, count)
                            style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                            count += 1

                            # Adds the query to the Isidore database
                            user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                            time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                            db.child("Queries").child("Filehash").child(query.qId).set(query.todict())

                            if len(cache) < 5:
                                cache.append(query)
                            else:
                                cache.pop(0)
                                cache.append(query)

                            storeHistory(query, "Filehash")
            
            return render_template("filehash.html", html=html, chart=chart, style=style, disabled=disabled)

        except:
            return render_template("filehash.html")
    # Returns the URL Query page
    return render_template("filehash.html", disabled=disabled)

@app.route("/filehash-analyse", methods=["POST", "GET"])
def filehashAnalyse():
    global userSettings, search
    disabled = "disabled"

    try:
        # Splits the query by spaces
        userQueries = search
        userQueries = userQueries.split(' ')
        html, chart, style = "", "", ""
        count = 0
        # Cycles through each query input
        for input in userQueries:
            query = FileHashQuery("", input, datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), "File Hash", "", "")
            qId = hashlib.sha256(query.query.encode('utf-8')).hexdigest()
            query.setQID(qId)
            # Retrieves information from each API if query is valid
            if query.validate():
                print("Query")
                virustotal = VtFileHash("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
                virustotal.retrieve(query.query, userSettings.virustotalKey)
                virustotalCard = virustotal.generate(count)

                hybridAnalysis = HybridAnalysis("", "", "")
                hybridAnalysis.retrieve(query.query, "filehash", userSettings.hybridAnalysisKey)
                hybridAnalysisCard = hybridAnalysis.generate("filehash")

                query.setVirustotal(virustotal)
                query.setHybridAnalysis(hybridAnalysis)

                # Generates HTML for page and charts
                html += query.generateHTML(query.submissionTime, virustotalCard, hybridAnalysisCard, count)
                chart += query.generateChart(virustotal, count)
                style += '#chartdiv' + str(count) + ' {width: 100%; height: 400px; }'
                count += 1

                # Adds page to Isidore database
                user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
                time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
                db.child("Queries").child("Filehash").child(query.qId).set(query.todict())

                if len(cache) < 5:
                    cache.append(query)
                else:
                    cache.pop(0)
                    cache.append(query)

                storeHistory(query, "Filehash")
        
        return render_template("filehash.html", html=html, chart=chart, style=style, disabled=disabled)
    except:
        return render_template("filehash.html")

# Adds the user query to their search history along with some of the query information
def storeHistory(query, type):
    history = {
        "Time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 
        "Query": query.query, 
        "VT Malicious Detections": query.virustotal.malDetection,
        "VT Total Detections": query.virustotal.cleanDetection + query.virustotal.malDetection + query.virustotal.susDetection + query.virustotal.undetected,
        "Type": type
        }

    user = hashlib.sha256(auth.current_user["email"].encode('utf-8')).hexdigest()
    time = hashlib.sha256(query.submissionTime.encode('utf-8')).hexdigest()
    db.child("Settings").child(user).child("History").child(time).set(history)
    

# Instanciates the Flask server and opens the dashboard automatically on localhost
if __name__ == "__main__":
    webbrowser.open_new("http://127.0.0.1:5000/")
    app.run(debug=False)

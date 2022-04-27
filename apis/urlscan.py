import requests, pycountry, time, json, dataclasses

# Urlscan Class ##########################################################################################################
@dataclasses.dataclass
class Urlscan:
    
    # Class Initialiser
    def __init__(self, screenshot, lastAnalysed, contentType, documentType, finalUrl, ipAddress, securityStatus, server, country, city, registrar, registerDate, response, reportLink):
        self.screenshot = screenshot
        self.lastAnalysed = lastAnalysed
        self.contentType = contentType
        self.documentType = documentType
        self.finalUrl = finalUrl
        self.ipAddress = ipAddress
        self.securityStatus = securityStatus
        self.server = server
        self.country = country
        self.city = city
        self.registrar = registrar
        self.registerDate = registerDate
        self.response = response
        self.reportLink = reportLink

    # Screenshot setter
    def setScreenshot(self, screenshot):
        self.screenshot = screenshot
 
    # Last Analysed setter
    def setLastAnalysed(self, lastAnalysed):
        self.lastAnalysed = lastAnalysed

    # Content Type setter
    def setContentType(self, contentType):
        self.contentType = contentType

    # Document Type setter
    def setDocumentType(self, documentType):
        self.documentType = documentType

    # Final URL setter
    def setFinalUrl(self, finalURL):
        self.finalUrl = finalURL

    # IP Address setter
    def setIP(self, ipAddress):
        self.ipAddress = ipAddress

    # Security Status setter
    def setSecurityStatus(self, securityStatus):
        self.securityStatus = securityStatus

    # Server setter
    def setServer(self, server):
        self.server = server

    # Country setter
    def setCountry(self, country):
        self.country = country

    # City setter
    def setCity(self, city):
        self.city = city

    # Registrar setter
    def setRegistrar(self, registrar):
        self.registrar = registrar

    # Register Date setter
    def setRegisterDate(self, registerDate):
        self.registerDate = registerDate

    # Response setter
    def setResponse(self, response):
        self.response = response

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink

    # Converts object to dictionary
    def todict(self):
        return {"Screenshot": self.screenshot, "Last Analysed": self.lastAnalysed, "Content Type": self.contentType, "Document Type": self.documentType, 
                "Final URL": self.finalUrl, "IP Address": self.ipAddress, "Security Status": self.securityStatus, "Server": self.server, 
                "Country": self.country, "City": self.city, "Registrar": self.registrar, "Registrar Date": self.registerDate, "Response": self.response, 
                "Report Link": self.reportLink}

    # Converts dictionary to object
    def fromdict(self, item):
        self.screenshot = item.val()["UrlScan"]["Screenshot"]
        self.lastAnalysed = item.val()["UrlScan"]["Last Analysed"]
        self.contentType = item.val()["UrlScan"]["Content Type"]
        self.documentType = item.val()["UrlScan"]["Document Type"]
        self.finalUrl = item.val()["UrlScan"]["Final URL"]
        self.ipAddress = item.val()["UrlScan"]["IP Address"]
        self.securityStatus = item.val()["UrlScan"]["Security Status"]
        self.server = item.val()["UrlScan"]["Server"]
        self.country = item.val()["UrlScan"]["Country"]
        self.city = item.val()["UrlScan"]["City"]
        self.registrar = item.val()["UrlScan"]["Registrar"]
        self.registerDate = item.val()["UrlScan"]["Registrar Date"]
        self.response = item.val()["UrlScan"]["Response"]
        self.reportLink = item.val()["UrlScan"]["Report Link"]

        return Urlscan(self.screenshot, self.lastAnalysed, self.contentType, self.documentType, self.finalUrl, self.ipAddress, self.securityStatus, self.server, 
        self.country, self.city, self.registrar, self.registerDate, self.response, self.reportLink)

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        # API call header
        headers = {'API-Key': key,'Content-Type':'application/json'}
        # Ensures the user input has a valid format for the query
        if query.startswith("http://"):
            query = query[7:]
        elif query.startswith("https://"):
            query = query[8:]
        elif query.endswith("/"):
            query = query[:-1]

        # API request to retrieve information on the URL
        urlScan = requests.get('https://urlscan.io/api/v1/search/?q=task.url:' + query, headers=headers)
        response_json = urlScan.json()

        # Not a valid API key
        if "message" in response_json:
            if response_json["message"] == "API key supplied but not found in database!":
                return
            elif response_json["message"] == 'Expected "/", "\\\\", or any character but end of input found.':
                return
        # If there are no existing results, run code
        if len(response_json['results']) == 0:
            print("Submitted")
            # API request to scan the URL
            data = {"url": query, "visibility": "unlisted"}
            urlScan = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
            usResult = urlScan.json()
            usID = usResult["uuid"]
            tries = 20
            # Requests for the result until it is received or the max number of attempts is hit
            while tries >=0: 
                URLresponse = requests.request("GET", "https://urlscan.io/api/v1/result/" + usID + "/", headers=headers)

                response_json = URLresponse.json()
                if "data" in response_json:
                    break
                else:
                    tries -= 1
                    time.sleep(2)
                    continue
        # Use response which has been returned
        else:
            URLresponse = requests.request("GET", response_json['results'][0]['result'], headers=headers)
            response_json = URLresponse.json()

        self.parse(response_json)

    # Parses the information returned from the URLscan API
    def parse(self, json):
        if "data" in json:
            if "url" in json["data"]["requests"][0]["request"]["request"]:
                self.setFinalUrl(json["data"]["requests"][0]["request"]["request"]["url"])
            if "requests" in json["data"]["requests"][0]:
                if "type" in json["data"]["requests"][0]["requests"][0]:
                    self.setDocumentType(json["data"]["requests"][0]["requests"][0]["type"])
            if "response" in json["data"]["requests"][0]:
                if "response" in json["data"]["requests"][0]["response"]:
                    if "headers" in json["data"]["requests"][0]["response"]["response"]:
                        if "content-type" in json["data"]["requests"][0]["response"]["response"]["headers"]:
                            self.setContentType(json["data"]["requests"][0]["response"]["response"]["headers"]["content-type"])
                        if "server" in json["data"]["requests"][0]["response"]["response"]["headers"]:
                            self.setServer(json["data"]["requests"][0]["response"]["response"]["headers"]["server"])
                    if "status" in json["data"]["requests"][0]["response"]["response"]:
                        self.setResponse(str(json["data"]["requests"][0]["response"]["response"]["status"]))
                    if "securityState" in json["data"]["requests"][0]["response"]["response"]:
                        self.setSecurityStatus(json["data"]["requests"][0]["response"]["response"]["securityState"])
                if "asn" in json["data"]["requests"][0]["response"]:
                    self.setIP(json["data"]["requests"][0]["response"]["asn"]["ip"])
                    if "country" in json["data"]["requests"][0]["response"]["asn"]:
                        tempCountry = pycountry.countries.get(alpha_2=json["data"]["requests"][0]["response"]["asn"]["country"])
                        self.setCountry(tempCountry.name)
                    if "registrar" in json["data"]["requests"][0]["response"]["asn"]:
                        self.setRegistrar(json["data"]["requests"][0]["response"]["asn"]["registrar"])
                    if "date" in json["data"]["requests"][0]["response"]["asn"]:
                        self.setRegisterDate(json["data"]["requests"][0]["response"]["asn"]["date"])
                if "geoip" in json["data"]["requests"][0]["response"]:
                    if len(json["data"]["requests"][0]["response"]["geoip"]["city"]) > 0:
                        self.setCity(json["data"]["requests"][0]["response"]["geoip"]["city"])
                    else:
                        self.setCity("N/A")
        if "task" in json:
            self.setReportLink(json["task"]["reportURL"])
            self.setScreenshot(json["task"]["screenshotURL"])
            self.setLastAnalysed(json["task"]["time"])

    # Generates HTML for URLscan card
    def generate(self, count):
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">UrlScan Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/urlscan.png" class="rounded mx-auto d-block" id="urllogo" style="width: 70%; height: 16%;"> <br><img src="' + self.screenshot + '" class="rounded mx-auto d-block" id="screenshot" style="height: 370px; width: 100%;"> <br><ul class="list-group"> <li class="list-group-item" style="padding-left: 4.5em;"><b>Date Last Analysed:</b> ' + self.lastAnalysed + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingThree"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(3 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(3 + 6*(count - 1)) + '" style="padding-left: 5.8em;"> <b>URL Information:</b> </button> </h2> <div id="collapse' + str(3 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 6.1em;"><b>Content Type:</b> ' + self.contentType + '</li> <li class="list-group-item" style="padding-left: 4.9em;"><b>Document Type:</b> ' + self.documentType + '</li> <li class="list-group-item" style="padding-left: 7.8em;"><b>Final URL:</b> ' + self.finalUrl + '</li> </ul> </div> </div> </li> <li class="accordion-item"> <h2 class="accordion-header" id="headingFive"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(4 + 6*(count - 1)) + '" aria-expanded="false" aria-controls="collapse' + str(4 + 6*(count - 1)) + '" style="padding-left: 1.8em;"> <b>Domain & IP Information:</b> </button> </h2> <div id="collapse' + str(4 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingFive" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 7.3em;"><b>IP Address:</b> ' + self.ipAddress + '</li> <li class="list-group-item" style="padding-left: 6em;"><b>Security State:</b> ' + self.securityStatus + '</li> <li class="list-group-item" style="padding-left: 9.3em;"><b>Server:</b> ' + self.server + '</li> <li class="list-group-item" style="padding-left: 8.6em;"><b>Country:</b> ' + self.country + '</li> <li class="list-group-item" style="padding-left: 10.3em;"><b>City:</b> ' + self.city + '</li> <li class="list-group-item" style="padding-left: 8.1em;"><b>Registrar:</b> ' + self.registrar + '</li> <li class="list-group-item" style="padding-left: 6.1em;"><b>Register Date:</b> ' + self.registerDate + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 6.5em;"><b>Response Code:</b> ' + str(self.response) + '</li> <li class="list-group-item" style="padding-left: 7.5em;"><b>URLScan Link:</b><a href=' + self.reportLink + ' target="_blank"> View the UrlScan Report</a></li> </ul> </div> </div>'
        return html
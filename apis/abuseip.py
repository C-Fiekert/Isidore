import requests, pycountry, dataclasses

# AbuseIPDB Class ########################################################################################################
@dataclasses.dataclass
class AbuseIP:
    
    # Class Initialiser
    def __init__(self, ipAddress, publicIP, ipVersion, whitelisted, abuseConfidence, country, usageType, isp, domain, totalReports, lastReported, reportLink):
        self.ipAddress = ipAddress
        self.publicIP = publicIP
        self.ipVersion = ipVersion
        self.whitelisted = whitelisted
        self.abuseConfidence = abuseConfidence
        self.country = country
        self.usageType = usageType
        self.isp = isp
        self.domain = domain
        self.totalReports = totalReports
        self.lastReported = lastReported
        self.reportLink = reportLink
 
    # IP Address setter
    def setIP(self, ipAddress):
        self.ipAddress = ipAddress

    # Public IP Address setter
    def setPublicIP(self, publicIP):
        self.publicIP = publicIP

    # IP Address Version setter
    def setIPVersion(self, ipVersion):
        self.ipVersion =ipVersion

    # Whitelisted IP setter
    def setWhitelisted(self, whitelisted):
        self.whitelisted = whitelisted

    # Abuse Confidence setter
    def setAbuseConfidence(self, abuseConfidence):
        self.abuseConfidence = abuseConfidence

    # Country setter
    def setCountry(self, country):
        self.country = country

    # Usage Type setter
    def setUsageType(self, usageType):
        self.usageType = usageType

    # ISP setter
    def setISP(self, isp):
        self.isp = isp

    # Domain setter
    def setDomain(self, domain):
        self.domain = domain

    # Total Reports setter
    def setTotalReports(self, totalReports):
        self.totalReports = totalReports

    # Last Reported setter
    def setLastReported(self, lastReported):
        self.lastReported = lastReported

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink

    # Converts object to dictionary
    def todict(self):
        return {"IP Address": self.ipAddress, "Public IP": self.publicIP, "IP Version": self.ipVersion, "Whitelisted": self.whitelisted, 
                "Abuse Confidence": self.abuseConfidence, "Country": self.country, "Usage Type": self.usageType, "ISP": self.isp, 
                "Domain": self.domain, "Total Reports": self.totalReports, "Last Reported": self.lastReported, "Report Link": self.reportLink}

    # Converts dictionary to object
    def fromdict(self, item):
        self.ipAddress = item.val()["AbuseIP"]["IP Address"]
        self.publicIP = item.val()["AbuseIP"]["Public IP"]
        self.ipVersion = item.val()["AbuseIP"]["IP Version"]
        self.whitelisted = item.val()["AbuseIP"]["Whitelisted"]
        self.abuseConfidence = item.val()["AbuseIP"]["Abuse Confidence"]
        self.country = item.val()["AbuseIP"]["Country"]
        if "Usage Type" in item.val()["AbuseIP"]:
            self.usageType = item.val()["AbuseIP"]["Usage Type"]
        self.isp = item.val()["AbuseIP"]["ISP"]
        self.domain = item.val()["AbuseIP"]["Domain"]
        self.totalReports = item.val()["AbuseIP"]["Total Reports"]
        self.lastReported = item.val()["AbuseIP"]["Last Reported"]
        self.reportLink = item.val()["AbuseIP"]["Report Link"]

        return AbuseIP(self.ipAddress, self.publicIP, self.ipVersion, self.whitelisted, self.abuseConfidence, self.country, self.usageType, self.isp, self.domain,
        self.totalReports, self.lastReported, self.reportLink)
    
    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # Request parameters
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': query, 'maxAgeInDays': '90' }
        headers = {'Accept': 'application/json','Key': key }
        # API request for IP address information
        result = requests.request(method='GET', url=url, headers=headers, params=querystring)
        response_json = result.json()

        # Throws an erorr if the API key provided is invalid
        if "errors" in response_json:
            if "Your API key is either missing, incorrect, or revoked" in response_json["errors"][0]["detail"]:
                return
        # Passes query to the parse function
        self.parse(query, response_json)

    # Generates HTML for AbuseIP card
    def generate(self, count):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"><h3 class="card-title">AbuseIPDB Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><br><br><br><img src="/static/abuseip.png" class="rounded mx-auto d-block" id="aiplogo" style="width: 80%; height: 13%;"><br><div id="chart2div' + str(count) + '"></div><br><ul class="list-group"><li class="list-group-item" style="padding-left: 4em;"><b>IP Address: </b>' + str(self.ipAddress) + '</li><li class="list-group-item" style="padding-left: 4.8em;"><b>Public IP: </b>' + str(self.publicIP) + '</li><li class="list-group-item" style="padding-left: 4.3em;"><b>IP Version: </b>' + str(self.ipVersion) + '</li><li class="list-group-item" style="padding-left: 3.6em;"><div data-bs-toggle="tooltip" title="Shows if this IP is on AbuseIPDBs Whitelist"><b>Whitelisted: </b>' + str(self.whitelisted) + '</div></li><li class="list-group-item" style="padding-left: 0.5em;"><div data-bs-toggle="tooltip" title="AbuseIPDBs confidence that this is malicious"><b>Abuse Confidence: </b>' + str(self.abuseConfidence) + '</div></li><li class="list-group-item" style="padding-left: 5.2em;"><b>Country: </b>' + str(self.country) + '</li><li class="list-group-item" style="padding-left: 3.8em;"><b>Usage Type: </b>' + str(self.usageType) + '</li><li class="list-group-item" style="padding-left: 7.7em;"><b>ISP: </b>' + str(self.isp) + '</li><li class="list-group-item" style="padding-left: 5.5em;"><b>Domain: </b>' + str(self.domain) + '</li><li class="accordion-item"><h2 class="accordion-header" id="headingTwo"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(2 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(2 + 6*(count - 1)) + '"  style="padding-left: 1.2em;"><b>View Report Info: </b></button></h2><div id="collapse' + str(2 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group"><li class="list-group-item" style="padding-left: 3em;"><b>Total Reports: </b>' + str(self.totalReports) + '</li><li class="list-group-item" style="padding-left: 2.9em;"><b>Last Reported: </b>' + str(self.lastReported) + '</li><li class="list-group-item" style="padding-left: 3.3em;"><b>AbuseIP Link:</b><a href=' + str(self.reportLink) + ' target="_blank"> View the AbuseIP Report</a></li></ul></ul> </div></div>'
        return html

    # Parse Virustotal query response
    def parse(self, query, json):
        if "data" in json:
            if "ipAddress" in json["data"]:
                self.setIP(json["data"]["ipAddress"])
            if "isPublic" in json["data"]:
                self.setPublicIP(json["data"]["isPublic"])
            if "ipVersion" in json["data"]:
                self.setIPVersion(json["data"]["ipVersion"])
            if "isWhitelisted" in json["data"]:
                if json["data"]["isWhitelisted"] != None:
                    self.setWhitelisted(json["data"]["isWhitelisted"])
                else:
                    self.setWhitelisted("False")
            if "abuseConfidenceScore" in json["data"]:
                aipConf = str(json["data"]["abuseConfidenceScore"])
                self.setAbuseConfidence(aipConf + "%")
            if "countryCode" in json["data"]:
                tempCountry = pycountry.countries.get(alpha_2=json["data"]["countryCode"])
                self.setCountry(tempCountry.name)
            if "usageType" in json["data"]:
                self.setUsageType(json["data"]["usageType"])
            if "isp" in json["data"]:
                self.setISP(json["data"]["isp"])
            if "domain" in json["data"]:
                self.setDomain(json["data"]["domain"])
            if "totalReports" in json["data"]:
                self.setTotalReports(json["data"]["totalReports"])
            if "lastReportedAt" in json["data"]:
                if json["data"]["lastReportedAt"] != None:
                    self.setLastReported(json["data"]["lastReportedAt"])
                else:
                    self.setLastReported("N/A")
            self.setReportLink("https://www.abuseipdb.com/check/" + query)
import base64, requests, datetime, pycountry, time, re, json

# AbuseIPDB Class ########################################################################################################
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

        self.parse(query, response_json)

        
    def generate(self, count):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61;" class="card-header ui-sortable-handle"><h3 class="card-title">AbuseIPDB Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><br><br><br><img src="/static/abuseip.png" class="rounded mx-auto d-block" id="aiplogo" style="width: 80%; height: 13%;"><br><div id="chart2div' + str(count) + '"></div><br><ul class="list-group"><li class="list-group-item" style="padding-left: 4em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 4.8em;"><b>Public IP: </b>' + str(self.publicIP) + '</li><li class="list-group-item" style="padding-left: 4.3em;"><b>IP Version: </b>' + str(self.ipVersion) + '</li><li class="list-group-item" style="padding-left: 3.6em;"><div data-bs-toggle="tooltip" title="Shows if this IP is on AbuseIPDBs Whitelist"><b>Whitelisted: </b>' + str(self.whitelisted) + '</div></li><li class="list-group-item" style="padding-left: 0.5em;"><div data-bs-toggle="tooltip" title="AbuseIPDBs confidence that this is malicious"><b>Abuse Confidence: </b>' + self.abuseConfidence + '</div></li><li class="list-group-item" style="padding-left: 5.2em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 3.8em;"><b>Usage Type: </b>' + self.usageType + '</li><li class="list-group-item" style="padding-left: 7.7em;"><b>ISP: </b>' + self.isp + '</li><li class="list-group-item" style="padding-left: 5.5em;"><b>Domain: </b>' + self.domain + '</li><li class="accordion-item"><h2 class="accordion-header" id="headingTwo"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(2 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(2 + 6*(count - 1)) + '"  style="padding-left: 1.2em;"><b>View Report Info: </b></button></h2><div id="collapse' + str(2 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group"><li class="list-group-item" style="padding-left: 3em;"><b>Total Reports: </b>' + str(self.totalReports) + '</li><li class="list-group-item" style="padding-left: 2.9em;"><b>Last Reported: </b>' + self.lastReported + '</li><li class="list-group-item" style="padding-left: 2em;"><b>AbuseIP Link:</b><a href=' + self.reportLink + ' target="_blank"> View the UrlScan Report</a></li></ul></ul> </div></div>'
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


# Greynoise Class ########################################################################################################
class Greynoise:
    
    # Class Initialiser
    def __init__(self, ipAddress, noise, riot, verdict, name, lastSeen, reportLink):
        self.ipAddress = ipAddress
        self.noise = noise
        self.riot = riot
        self.verdict = verdict
        self.name = name
        self.lastSeen = lastSeen
        self.reportLink = reportLink
 
    # IP Address setter
    def setIP(self, ipAddress):
        self.ipAddress = ipAddress

    # Noise setter
    def setNoise(self, noise):
        self.noise = noise

    # RIOT setter
    def setRIOT(self, riot):
        self.riot = riot

    # Verdict setter
    def setVerdict(self, verdict):
        self.verdict = verdict

    # Name setter
    def setName(self, name):
        self.name = name

    # Last Seen setter
    def setLastSeen(self, lastSeen):
        self.lastSeen = lastSeen

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink

    
    # Retrieve information
    def retrieve(self, query):
        # Request parameters
        url = "https://api.greynoise.io/v3/community/" + query
        headers = {"Accept": "application/json"}
        # API request for IP address information
        result = requests.request('GET', url, headers=headers)
        response_json = result.json()

        # Throws an erorr if the API key provided is invalid
        if response_json["message"] != "Success":
            print("Greynoise was unable to retrieve information on this")
            return

        self.parse(response_json)

        
    def generate(self):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61;" class="card-header ui-sortable-handle"><h3 class="card-title">Greynoise Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/greynoise.png" class="rounded mx-auto d-block" id="gnlogo" style="width: 85%; height: 25%;"><br><ul class="list-group"><li class="list-group-item" style="padding-left: 5em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 7.3em;"><div data-bs-toggle="tooltip" title="Has been observed scanning the internet"><b>Noise: </b>' + str(self.noise) + '</div></li><li class="list-group-item" style="padding-left: 7.7em;"><div data-bs-toggle="tooltip" title="Rule It OuT: Declared safe by Greynoise"><b>RIOT: </b>' + str(self.riot) + '</div></li><li class="list-group-item" style="padding-left: 6.6em;"><b>Verdict: </b>' + self.verdict + '</li><li class="list-group-item" style="padding-left: 7.1em;"><b>Name: </b>' + self.name + '</li><li class="list-group-item" style="padding-left: 5.4em;"><b>Last Seen: </b>' + self.lastSeen + '</li><li class="list-group-item" style="padding-left: 2.9em;"><b>Greynoise Link: </b><a href=' + self.reportLink + ' target="_blank">View the Greynoise Report</a></li></ul></div></div>'
        return html

    
    # Parse Greynoise query response
    def parse(self, json):
        self.setIP(json['ip'])
        self.setNoise(json['noise'])
        self.setRIOT(json['riot'])
        self.setVerdict(json['classification'])
        self.setName(json['name'])
        self.setLastSeen(json['last_seen'])
        self.setReportLink(json['link'])


# Hybrid Analysis Class ##################################################################################################
class HybridAnalysis:
    
    # Class Initialiser
    def __init__(self, submissionName, verdict, analysisTime):
        self.submissionName = submissionName
        self.verdict = verdict
        self.analysisTime = analysisTime
 
    # Submission Name setter
    def setSubmissionName(self, submissionName):
        self.submissionName = submissionName

    # Verdict setter
    def setVerdict(self, verdict):
        self.verdict = verdict

    # Analysis Time setter
    def setAnalysisTime(self, analysisTime):
        self.analysisTime = analysisTime


    def retrieve(self, query, key):
        if key == "":
            return

        extension = re.findall("jpg$|png$|aif$|cda$|mid$|midi$|mp3$|mpa$|ogg$|wav$|wma$|wpl$|7z$|arj$|deb$|pkg$|rar$|rpm$|tar.gz$|z$|zip$|bin$|dmg$|iso$|toast$|vcd$|csv$|dat$|db$|dbf$|log$|mdb$|sav$|sql$|tar$|xml$|email$|eml$|emlx$|msg$|oft$|ost$|pst$|vcf$|apk$|bat$|cgi$|pl$|exe$|gadget$|jar$|msi$|py$|wsf$|ai$|bmp$|gif$|ico$|jpeg$|ps$|psd$|svg$|tif$|tiff$|js$|key$|odp$|pps$|ppt$|pptx$|c$|class$|cpp$|cs$|java$|php$|sh$|swift$|vb$|ods$|xls$|xlsm$|xlsx$|cfg$|dll$|dmp$|ini$|lnk$|sys$|tmp$|mov$|mp4$|wmv$|doc$|docx$|pdf$|txt$", query)
        # Runs if the URL has one of the listed extensions
        if len(extension) == 0:
            headers = {'api-key': key, "accept": "application/json", "user-agent": "Falcon Sandbox", "Content-Type": "application/x-www-form-urlencoded"}
            # API request for Hybrid Analsyis information on the provided URL
            response = requests.post("https://www.hybrid-analysis.com/api/v2/search/terms", headers=headers , data = "url=" + query)
            response_json = response.json()

            # Checks for valid API key
            if "message" in response_json:
                if "The provided API key is incompatible" in response_json["message"]:
                    return

            # Queries and returns information
            if response_json["count"] == 0:
                self.quickScan(query, headers, response_json)
            else:
                self.sort(response_json)


    # Scans Url for new results and parses information
    def quickScan(self, query, headers, response_json):
        if response_json["count"] == 0:
            response = requests.post("https://www.hybrid-analysis.com/api/v2/quick-scan/url", headers=headers , data = "scan_type=all&url=" + query + "&allow_community_access=false")
            response_json = response.json()
            tries = 50
            # Keeps requesting for the URL information until it is received or when the max number of attempts is reached
            while tries >=0:
                ## GET URL ANALYSIS
                if "sha256" in response_json:
                    search = requests.post("https://www.hybrid-analysis.com/api/v2/search/hash", headers=headers, data = 'hash=' + response_json["sha256"])
                    retrieved = search.json()
                    if retrieved[0]["state"] == "SUCCESS":
                        break
                    else:
                        tries -= 1
                        time.sleep(1)
                        continue
            self.parse(retrieved)

    # Sorts retrieved results by most relevant
    def sort(self, response_json):
        datelist = []
        for info in response_json["result"]:
            temp = info["analysis_start_time"]
            if temp != None:
                if temp[10] == "T":
                    temp = temp[0:10] + " " + temp[11:19]
                datelist.append(temp)
        datelist.sort(key=lambda date: datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S"))
        selection = response_json["result"][0]
        for info in response_json["result"]:
            if info["analysis_start_time"] != None:
                check = info["analysis_start_time"][0:10] + " " + info["analysis_start_time"][11:19]
                if check == datelist[len(datelist)-1]:
                    selection = info
        if response_json["search_terms"][0]["value"] != None:
            self.setSubmissionName(response_json["search_terms"][0]["value"])
        if selection["verdict"] != None:
            self.setVerdict(selection["verdict"])
        if selection["analysis_start_time"] != None:
            self.setAnalysisTime(selection["analysis_start_time"])

    # Parses newly retrieved information
    def parse(self, json):
        if json[0]["submit_name"] != None:
            self.setSubmissionName(json[0]["submit_name"])
        if json[0]["verdict"] != None:
            self.setVerdict(json[0]["verdict"])
        if json[0]["analysis_start_time"] != None:
            self.setAnalysisTime(json[0]["analysis_start_time"])

    def generate(self):
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">Hybrid Analysis Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/hybrid-analysis.png" class="rounded mx-auto d-block" id="halogo"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 2.8em;"><b>Submission Name: </b>' + self.submissionName + '</li> <li class="list-group-item" style="padding-left: 7.8em;"><b>Verdict: </b>' + self.verdict + '</li> <li class="list-group-item" style="padding-left: 4.6em;"><b>Analysis Time: </b>' + self.analysisTime + '</li> </ul> <br><br><br> </div> </div>'
        return html
    

# IPinfo Class ###########################################################################################################
class IPinfo:
    
    # Class Initialiser
    def __init__(self, ipAddress, hostName, city, region, country, postalArea, org, timezone, latitude, longitude):
        self.ipAddress = ipAddress
        self.hostName = hostName
        self.city = city
        self.region = region
        self.country = country
        self.postalArea = postalArea
        self.org = org
        self.timezone = timezone
        self.latitude = latitude
        self.longitude = longitude
 
    # IP Address setter
    def setIP(self, ipAddress):
        self.ipAddress = ipAddress

    # Host Name setter
    def setHostName(self, hostname):
        self.hostName = hostname

    # City setter
    def setCity(self, city):
        self.city = city

    # Region setter
    def setRegion(self, region):
        self.region = region

    # Country setter
    def setCountry(self, country):
        self.country = country

    # Postal Area setter
    def setPostalArea(self, postalArea):
        self.postalArea = postalArea

    # Organisation setter
    def setOrg(self, org):
        self.org = org

    # Timezone setter
    def setTimezone(self, timezone):
        self.timezone = timezone

    # Latitude setter
    def setLatitude(self, latitude):
        self.latitude = latitude

    # Longitude setter
    def setLongitude(self, longitude):
        self.longitude = longitude

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # Request parameters
        url = "https://ipinfo.io/" + query + "/json?token=" + key
        headers = {"Accept": "application/json"}
        result = requests.request("GET", url, headers=headers)
        response_json = result.json()

        if "error" in response_json:
            if "Unknown token" in response_json["error"]["title"]:
                print("Invalid API key")
                return
        self.parse(response_json)


    # Parse IPinfo query response
    def parse(self, json):
        if "ip" in json:
            self.setIP(json["ip"])
        if "hostname" in json:
            self.setHostName(json["hostname"])
        if "city" in json:
            self.setCity(json["city"])
        if "region" in json:
            self.setRegion(json["region"])
        if "country" in json:
            tempCountry = pycountry.countries.get(alpha_2=json["country"])
            try:
                self.setCountry(tempCountry.name)
            except:
                self.setCountry("")
        if "org" in json:
            self.setOrg(json["org"])
        if "postal" in json:
            self.setPostalArea(json["postal"])
        if "timezone" in json:
            self.setTimezone(json["timezone"])
        if "loc" in json:
            self.setLatitude(json["loc"].split(',')[0])
            self.setLongitude(json["loc"].split(',')[1])

    def generate(self):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61;" class="card-header ui-sortable-handle"><h3 class="card-title">Shodan Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/ipinfo.png" class="rounded mx-auto d-block" id="ipilogo"><br><div style="width: 100%"><iframe scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?width=100%25&amp;height=400&amp;hl=en&amp;q=' + self.latitude + ',' + self.longitude + '&amp;t=&amp;z=14&amp;ie=UTF8&amp;iwloc=B&amp;output=embed" width="100%" height="400" frameborder="0"></iframe></div> <br><ul class="list-group"><li class="list-group-item" style="padding-left: 2.8em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 3em;"><b>Hostname: </b>' + self.hostName + '</li><li class="list-group-item" style="padding-left: 6em;"><b>City: </b>' + self.city + '</li><li class="list-group-item" style="padding-left: 4.6em;"><b>Region: </b>' + self.region + '</li><li class="list-group-item" style="padding-left: 4.1em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 2.6em;"><b>Postal Area: </b>' + str(self.postalArea) + '</li><li class="list-group-item" style="padding-left: 6.1em;"><b>Org: </b>' + self.org + '</li><li class="list-group-item" style="padding-left: 3.3em;"><b>Timezone: </b>' + self.timezone + '</li></ul></div></div>'
        return html
        


# Shodan Class ###########################################################################################################
class Shodan:
    
    # Class Initialiser
    def __init__(self, ipAddress, country, city, latitude, longitude, lastUpdated, org, isp, asn, vulnerabilities, ports, reportLink):
        self.ipAddress = ipAddress
        self.country = country
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
        self.lastUpdated = lastUpdated
        self.org = org
        self.isp = isp
        self.asn = asn
        self.vulnerabilities = vulnerabilities
        self.ports = ports
        self.reportLink = reportLink
 
    # IP Address setter
    def setIP(self, ipAddress):
        self.ipAddress = ipAddress

    # Country setter
    def setCountry(self, country):
        self.country = country

    # City setter
    def setCity(self, city):
        self.city = city

    # Latitude setter
    def setLatitude(self, latitude):
        self.latitude = latitude

    # Longitude setter
    def setLongitude(self, longitude):
        self.longitude = longitude

    # Last Updated setter
    def setLastUpdated(self, lastUpdated):
        self.lastUpdated = lastUpdated

    # Organisation setter
    def setOrg(self, org):
        self.org = org

    # ISP setter
    def setISP(self, isp):
        self.isp = isp

    # ASN setter
    def setASN(self, asn):
        self.asn = asn

    # Vulnerabilities setter
    def setVulnerabilities(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    # Ports setter
    def setPorts(self, ports):
        self.ports = ports

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink


    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # Request parameters
        url = "https://api.shodan.io/shodan/host/" + query + "?key=" + key
        headers = {"Accept": "application/json"}
        # API request for IP address information
        result = requests.request('GET', url, headers=headers)
        if "401 Unauthorized" in result.text:
            print("Please provide a valid API key")
            return
        response_json = result.json()

        if "error" not in response_json:
            self.parse(query, response_json)
        
    def generate(self, count):

        # Ports list
        portsHtml = ""
        for i in self.ports:
            portsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>Port:</b> ' + str(i) + '</li>'

        # Vulnerabilities list
        vulnsHtml = ""
        referenceHtml = ""
        temp = 0
        for vuln in self.vulnerabilities:
            referenceItems = ""
            for reference in vuln[4]:
                referenceItems += '<li class="list-group-item" style="padding-left: 3em;"><a href="' + str(reference) + '" target="_blank">' + str(reference) + '</a></li>'
            referenceHtml = '<li class="accordion-item"> <h2 class="accordion-header" id="heading' + str(5000 + temp + 10000*count) + '"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(5000 + temp + 10000*count) + '" aria-expanded="true" aria-controls="collapse' + str(5000 + temp + 10000*count) + '"  style="padding-left: 2.2em;"><b>References: </b></button> </h2> <div id="collapse' + str(5000 + temp + 10000*count) + '" class="accordion-collapse collapse" aria-labelledby="heading' + str(5000 + temp + 10000*count) + '" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + referenceItems + '</ul></div> </div> </li>'
            vulnsHtml += '<li class="accordion-item"> <h2 class="accordion-header" id="heading' + str(temp + 10000*count) + '"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(temp + 10000*count) + '" aria-expanded="true" aria-controls="collapse' + str(temp + 10000*count) + '"  style="padding-left: 1.2em;"><b>' + str(vuln[0]) + ': </b></button> </h2> <div id="collapse' + str(temp + 10000*count) + '" class="accordion-collapse collapse" aria-labelledby="heading' + str(temp + 10000*count) + '" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"><li class="list-group-item" style="padding-left: 4em;"><b>Verified: </b>' + str(vuln[1]) + '</li> <li class="list-group-item" style="padding-left: 5.5em;"><b>CVSS: </b>' + str(vuln[2]) + '</li> <li class="list-group-item" style="padding-left: 3em;"><b>Summary: </b>' + str(vuln[3]) + '</li>' + referenceHtml + '</ul> </div> </div> </li>'
            temp += 1
        
        # vulns = []
        # if "data" in json:
        #     for fields in json["data"]:
        #         if "vulns" in fields:
        #             id = 0
        #             for vulnerability in fields["vulns"]:
        #                 id+=1
        #                 name = fields["vulns"][vulnerability]
        #                 verified = fields["vulns"][vulnerability]["verified"]
        #                 cvss = str(fields["vulns"][vulnerability]["cvss"])
        #                 summary = fields["vulns"][vulnerability]["summary"]
        #                 references = []
        #                 if "references" in fields["vulns"][vulnerability]:
        #                     for reference in fields["vulns"][vulnerability]["references"]:
        #                         references.append(reference)

        #                 info = [name, verified, cvss, summary, references]
        #                 vulns.append(info)
        # self.setVulnerabilities(vulns)



        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61;" class="card-header ui-sortable-handle"><h3 class="card-title">Shodan Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/shodan.png" id="shlogo" class="rounded mx-auto d-block" style="width: 85%; height: 14%;"><br> <div style="width: 100%"><iframe scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?width=100%25&amp;height=400&amp;hl=en&amp;q=' + str(self.latitude) + ',%20' + str(self.longitude) + '+(My%20Business%20Name)&amp;t=&amp;z=14&amp;ie=UTF8&amp;iwloc=B&amp;output=embed" width="100%" height="400" frameborder="0"></iframe></div> <br><ul class="list-group"><li class="list-group-item" style="padding-left: 5em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 6.1em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 8em;"><b>City: </b>' + self.city + '</li><li class="list-group-item" style="padding-left: 5.9em;"><b>Latitude: </b>' + str(self.latitude) + '</li><li class="list-group-item" style="padding-left: 5em;"><b>Longitude: </b>' + str(self.longitude) + '</li><li class="list-group-item" style="padding-left: 3.5em;"><b>Last Updated: </b>' + self.lastUpdated + '</li><li class="list-group-item" style="padding-left: 7.9em;"><b>Org: </b>' + self.org + '</li><li class="list-group-item" style="padding-left: 8.1em;"><b>ISP: </b>' + self.isp + '</li><li class="list-group-item" style="padding-left: 7.5em;"><b>ASN: </b>' + self.asn + '</li><li class="accordion-item"><h2 class="accordion-header" id="headingThree"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree" aria-expanded="true" aria-controls="collapseThree"  style="padding-left: 2.7em;"><b>Vulnerabilities:</b></button></h2><div id="collapseThree" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + vulnsHtml + ' </ul></div></div></li><li class="accordion-item"><h2 class="accordion-header" id="headingFour"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour" aria-expanded="true" aria-controls="collapseFour"  style="padding-left: 6.9em;"><b>Ports: </b></button></h2><div id="collapseFour" class="accordion-collapse collapse" aria-labelledby="headingFour" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + portsHtml + '</ul></div></div></li><li class="list-group-item" style="padding-left: 7.5em;"><b>Shodan Link:</b><a href=' + self.reportLink + ' target="_blank"> View the Shodan Report</a></li> </ul></div></div>'
        return html

    
    # Parse Shodan query response
    def parse(self, query, json):
        self.setIP(query)
        self.setCountry(json['country_name'])
        self.setCity(json['city'])
        self.setLastUpdated(json['last_update'])
        self.setLatitude(json['latitude'])
        self.setLongitude(json['longitude'])
        self.setOrg(json['org'])
        self.setISP(json['isp'])
        self.setASN(json['asn'])
        # Vulnerabilities and their information
        vulns = []
        if "data" in json:
            for fields in json["data"]:
                if "vulns" in fields:
                    id = 0
                    for vulnerability in fields["vulns"]:
                        id+=1
                        name = vulnerability
                        verified = fields["vulns"][vulnerability]["verified"]
                        cvss = str(fields["vulns"][vulnerability]["cvss"])
                        summary = fields["vulns"][vulnerability]["summary"]
                        references = []
                        if "references" in fields["vulns"][vulnerability]:
                            for reference in fields["vulns"][vulnerability]["references"]:
                                references.append(reference)

                        info = [name, verified, cvss, summary, references]
                        vulns.append(info)
        self.setVulnerabilities(vulns)
        ports = []
        for port in json['ports']:
            ports.append(port)
        self.setPorts(ports)
        self.setReportLink("https://www.shodan.io/host/" + query)


# Urlscan Class ##########################################################################################################
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

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
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

        # If there are no existing results, run code
        if len(response_json['results']) == 0:
            print("Submitted")
            # API request to scan the URL
            data = {"url": query, "visibility": "unlisted"}
            urlScan = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
            usResult = urlScan.json()
            print(usResult)
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

    def generate(self, count):
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">UrlScan Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/urlscan.png" class="rounded mx-auto d-block" id="urllogo" style="width: 70%; height: 16%;"> <br><img src="' + self.screenshot + '" class="rounded mx-auto d-block" id="screenshot" style="height: 370px; width: 100%;"> <br><ul class="list-group"> <li class="list-group-item" style="padding-left: 4.5em;"><b>Date Last Analysed:</b> ' + self.lastAnalysed + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingThree"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(3 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(3 + 6*(count - 1)) + '" style="padding-left: 5.8em;"> <b>URL Information:</b> </button> </h2> <div id="collapse' + str(3 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 6.1em;"><b>Content Type:</b> ' + self.contentType + '</li> <li class="list-group-item" style="padding-left: 4.9em;"><b>Document Type:</b> ' + self.documentType + '</li> <li class="list-group-item" style="padding-left: 7.8em;"><b>Final URL:</b> ' + self.finalUrl + '</li> </ul> </div> </div> </li> <li class="accordion-item"> <h2 class="accordion-header" id="headingFive"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(4 + 6*(count - 1)) + '" aria-expanded="false" aria-controls="collapse' + str(4 + 6*(count - 1)) + '" style="padding-left: 1.8em;"> <b>Domain & IP Information:</b> </button> </h2> <div id="collapse' + str(4 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingFive" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 7.3em;"><b>IP Address:</b> ' + self.ipAddress + '</li> <li class="list-group-item" style="padding-left: 6em;"><b>Security State:</b> ' + self.securityStatus + '</li> <li class="list-group-item" style="padding-left: 9.3em;"><b>Server:</b> ' + self.server + '</li> <li class="list-group-item" style="padding-left: 8.6em;"><b>Country:</b> ' + self.country + '</li> <li class="list-group-item" style="padding-left: 10.3em;"><b>City:</b> ' + self.city + '</li> <li class="list-group-item" style="padding-left: 8.1em;"><b>Registrar:</b> ' + self.registrar + '</li> <li class="list-group-item" style="padding-left: 6.1em;"><b>Register Date:</b> ' + self.registerDate + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 6.5em;"><b>Response Code:</b> ' + str(self.response) + '</li> <li class="list-group-item" style="padding-left: 7.5em;"><b>URLScan Link:</b><a href=' + self.reportLink + ' target="_blank"> View the UrlScan Report</a></li> </ul> </div> </div>'
        return html


# Virustotal Class #######################################################################################################
class Virustotal:
    
    # Class Initialiser
    def __init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink):
        self.cleanDetection = cleanDetection
        self.malDetection = malDetection
        self.undetected = undetected
        self.susDetection = susDetection
        self.detections = detections
        self.firstSubmitted = firstSubmitted
        self.lastSubmitted = lastSubmitted
        self.totalSubmissions = totalSubmissions
        self.vtGraph = vtGraph
        self.reportLink = reportLink
 
    # Clean Detection setter
    def setCleanDetection(self, cleanDetection):
        self.cleanDetection = cleanDetection

    # Malicious Detection setter
    def setMalDetection(self, malDetection):
        self.malDetection = malDetection

    # Undetected setter
    def setUndetected(self, undetected):
        self.undetected = undetected

    # Suspicious Detection setter
    def setSusDetection(self, susDetection):
        self.susDetection = susDetection

    # Detections setter
    def setDetections(self, detections):
        self.detections = detections

    # First Submitted setter
    def setFirstSubmitted(self, firstSubmitted):
        self.firstSubmitted = firstSubmitted

    # Last Submitted setter
    def setLastSubmitted(self, lastSubmitted):
        self.lastSubmitted = lastSubmitted

    # Total Submitted setter
    def setTotalSubmissions(self, totalSubmissions):
        self.totalSubmissions = totalSubmissions

    # Virustotal Graph setter
    def setVirustotalGraph(self, virustotalGraph):
        self.vtGraph = virustotalGraph

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink

# Virustotal Domain Sub-Class ############################################################################################
class VtDomain(Virustotal):
    
    # Class Initialiser
    def __init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink, domain, categories, registrar, dateCreated, lastModified, certStarted, certExpires, certIssuer):
        self.domain = domain
        self.categories = categories
        self.registrar = registrar
        self.dateCreated = dateCreated
        self.lastModified = lastModified
        self.certStarted = certStarted
        self.certExpires = certExpires
        self.certIssuer = certIssuer
        # Invoking the __init__ of the Virustotal class
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # Domain setter
    def setDomain(self, domain):
        self.domain = domain
    
    # Categories setter
    def setCategories(self, categories):
        self.categories = categories
    
    # Registrar setter
    def setRegistrar(self, registrar):
        self.registrar = registrar

    # Date Created setter
    def setDateCreated(self, dateCreated):
        self.dateCreated = dateCreated

    # Last Modified setter
    def setLastModified(self, lastModified):
        self.lastModified = lastModified

    # Certificate Started setter
    def setCertStarted(self, certStarted):
        self.certStarted = certStarted

    # Certificate Expires setter
    def setCertExpires(self, certExpires):
        self.certExpires = certExpires

    # Certificate Issuer setter
    def setCertIssuer(self, certIssuer):
        self.certIssuer = certIssuer

# Virustotal File Hash Sub-Class #########################################################################################
class VtFileHash(Virustotal):
    
    # Class Initialiser
    def __init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink, description, knownNames, fileSize, threatLabel, magic, product, productDesc, productVersion, md5, sha1, sha256):
        self.description = description
        self.knownNames = knownNames
        self.fileSize = fileSize
        self.threatLabel = threatLabel
        self.magic = magic
        self.product = product
        self.productDesc = productDesc
        self.productVersion = productVersion
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        # Invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)

    # Description setter
    def setDescription(self, description):
        self.description = description

    # Known Names setter
    def setKnownNames(self, knownNames):
        self.knownNames = knownNames

    # File Size setter
    def setFileSize(self, fileSize):
        self.fileSize = fileSize

    # Threat Label setter
    def setThreatLabel(self, threatLabel):
        self.threatLabel = threatLabel

    # Magic setter
    def setMagic(self, magic):
        self.magic = magic

    # Product setter
    def setProduct(self, product):
        self.product = product

    # Product Description setter
    def setProductDesc(self, productDesc):
        self.productDesc = productDesc

    # Product Version setter
    def setProductVersion(self, productVersion):
        self.productVersion = productVersion

    # MD5 setter
    def setMD5(self, md5):
        self.md5 = md5

    # SHA1 setter
    def setSHA1(self, sha1):
        self.sha1 = sha1

    # SHA256 setter
    def setSHA256(self, sha256):
        self.sha256 = sha256

# Virustotal IP Address Sub-Class ########################################################################################
class VtIP(Virustotal):
    
    # Class Initialiser
    def __init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink, network, country, continent, aso, asn, registrar):
        self.network = network
        self.country = country
        self.continent = continent
        self.aso = aso
        self.asn = asn
        self.registrar = registrar
        # Invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # Network setter
    def setNetwork(self, network):
        self.network = network

    # Country setter
    def setCountry(self, country):
        self.country = country
    
    # Continent setter
    def setContinent(self, continent):
        self.continent = continent

    # ASO setter
    def setASO(self, aso):
        self.aso = aso

    # ASN setter
    def setASN(self, asn):
        self.asn = asn

    # Registrar setter
    def setRegistrar(self, registrar):
        self.registrar = registrar

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # API call headers
        headers = {'x-apikey': key}
        # API request to retrieve URL information from VirusTotal
        analysis_ip = "https://www.virustotal.com/api/v3/ip_addresses/" + query
        response = requests.get(analysis_ip, headers=headers)
        response_json = response.json()
        if "error" in response_json:
            if "Wrong API key" in response_json["error"]["message"]:
                print("Wrong API key")
                return
            else:
                print("Big Problemo")

        self.parse(query, response_json)

    
    # Parse Virustotal query response
    def parse(self, query, json):
        if "data" in json:
            if "network" in json["data"]["attributes"]:
                self.setNetwork(str(json["data"]["attributes"]["network"]))
            if "country" in json["data"]["attributes"]:
                tempCountry = pycountry.countries.get(alpha_2=json["data"]["attributes"]["country"])
                self.setCountry(tempCountry.name)
            if "continent" in json["data"]["attributes"]:
                vtContinent = str(json["data"]["attributes"]["continent"])
                if vtContinent == "EU":
                    self.setContinent("Europe")
                elif vtContinent == "NA":
                    self.setContinent("North America")
                elif vtContinent == "SA":
                    self.setContinent("South America")
                elif vtContinent == "AS":
                    self.setContinent("Asia")
                elif vtContinent == "OC":
                    self.setContinent("Oceania")
                elif vtContinent == "AF":
                    self.setContinent("Africa")
                else:
                    self.setContinent("Antarctica")
            if "as_owner" in json["data"]["attributes"]:
                self.setASO(str(json["data"]["attributes"]["as_owner"]))
            if "asn" in json["data"]["attributes"]:
                self.setASN(str(json["data"]["attributes"]["asn"]))
            
            detections = []
            if "last_analysis_results" in json["data"]["attributes"]:
                for engine in json["data"]["attributes"]["last_analysis_results"]:
                    if json["data"]["attributes"]["last_analysis_results"][engine]["category"] == "malicious" or json["data"]["attributes"]["last_analysis_results"][engine]["category"] == "suspicious":
                        detection = [json["data"]["attributes"]["last_analysis_results"][engine]["engine_name"], json["data"]["attributes"]["last_analysis_results"][engine]["category"]]
                        detections.append(detection)
            self.setDetections(detections)
            self.setCleanDetection(json["data"]["attributes"]["last_analysis_stats"]["harmless"])
            self.setMalDetection(json["data"]["attributes"]["last_analysis_stats"]["malicious"])
            self.setSusDetection(json["data"]["attributes"]["last_analysis_stats"]["suspicious"])
            self.setUndetected(json["data"]["attributes"]["last_analysis_stats"]["undetected"])
            self.setRegistrar(str(json["data"]["attributes"]["regional_internet_registry"]))
            self.setReportLink("https://www.virustotal.com/gui/ip-address/" + query + "/detection")


    def generate(self, count):
        # Detections list
        detectionsHtml = ""
        for i in self.detections:
            detectionsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61;" class="card-header ui-sortable-handle"><h3 class="card-title">VirusTotal Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/vt.png" class="rounded mx-auto d-block" id="vtlogo" style="width: 70%;   height: 22%;"><div id="chartdiv' + str(count) + '"></div><br><br><div id="detections"><center><button type="button" class="btn btn-success"> Clean Detections <span class="badge bg-dark">' + str(self.cleanDetection) + '</span></button><button type="button" class="btn btn-danger"> Malicious Detections <span class="badge bg-dark">' + str(self.malDetection) + '</span></button><button type="button" class="btn btn-secondary"> Undetected Detections <span class="badge bg-dark">' + str(self.undetected) + '</span></button></center></div><br><ul class="list-group"><li class="accordion-item"><h2 class="accordion-header" id="headingOne"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(1 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(1 + 6*(count - 1)) + '"  style="padding-left: 6.5em;"><b> View Detections: </b></button></h2><div id="collapse' + str(1 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + detectionsHtml + '</ul></div></div></li><li class="list-group-item" style="padding-left: 10em;"><b>Network: </b>' + self.network + '</li><li class="list-group-item" style="padding-left: 10.2em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 9.5em;"><b>Continent: </b>' + self.continent + '</li><li class="list-group-item" style="padding-left: 1em;"><b>Autonomous System Owner: </b>' + self.aso + '</li><li class="list-group-item" style="padding-left: 0.2em;"><b>Autonomous System Number: </b>' + self.asn + '</li><li class="list-group-item" style="padding-left: 9.9em;"><b>Registrar: </b>' + self.registrar + '</li><li class="list-group-item" style="padding-left: 7.3em;"><b>VirusTotal Link: </b><a href=' + self.reportLink + ' target="_blank">View the VirusTotal Report</a></li> </ul></div></div>'
        return html




# Virustotal Url Sub-Class ###############################################################################################
class VtUrl(Virustotal):
    
    # Class Initialiser
    def __init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink, categories, finalUrl, siteTitle, contentType, server, response):
        self.categories = categories
        self.finalUrl = finalUrl
        self.siteTitle = siteTitle
        self.contentType = contentType
        self.server = server
        self.response = response
        # Invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # Categories setter
    def setCategories(self, categories):
        self.categories = categories

    # Final URL setter
    def setFinalURL(self, finalURL):
        self.finalUrl = finalURL

    # Site Title setter
    def setSiteTitle(self, siteTitle):
        self.siteTitle = siteTitle

    # Content Type setter
    def setContentType(self, contentType):
        self.contentType = contentType

    # Server setter
    def setServer(self, server):
        self.server = server

    # Response setter
    def setResponse(self, response):
        self.response = response

    
    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        url_id = base64.urlsafe_b64encode(query.encode('UTF-8')).decode('ascii').strip("=")
        # API call headers
        headers = {'x-apikey': key}
        # API request to retrieve URL information from VirusTotal
        analysis_url = "https://www.virustotal.com/api/v3/urls/" + url_id
        response = requests.get(analysis_url, headers=headers)
        response_json = response.json()
        if "error" in response_json:
            if response_json["error"]["code"] == "NotFoundError":
                requests.post("https://www.virustotal.com/api/v3/urls", headers=headers , data = {'url':query})
                time.sleep(10)
                response = requests.get(analysis_url, headers=headers)
                response_json = response.json()
            else:
                print("Big Problemo")

        self.parse(response_json)
        
    def generate(self, count):
        # Detections list
        detectionsHtml = ""
        for i in self.detections:
            detectionsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        # Category list
        categoriesHtml = ""
        for i in self.categories:
            categoriesHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">VirusTotal Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/vt.png" class="rounded mx-auto d-block" id="vtlogo" style="width: 70%; height: 22%;"> <div id="chartdiv' + str(count) + '"></div> <br><br> <div id="detections"> <center> <button type="button" class="btn btn-success"> Clean Detections <span class="badge bg-dark">' + str(self.cleanDetection) + '</span> </button> <button type="button" class="btn btn-danger"> Malicious Detections <span class="badge bg-dark">' + str(self.malDetection) + '</span> </button> <button type="button" class="btn btn-secondary"> Undetected Detections <span class="badge bg-dark">' + str(self.undetected) + '</span> </button> </center> </div> <br> <ul class="list-group"> <li class="accordion-item"> <h2 class="accordion-header" id="headingOne"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(1 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(1 + 6*(count - 1)) + '"  style="padding-left: 4.9em;"><b> View Detections: </b></button> </h2> <div id="collapse' + str(1 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + detectionsHtml + '</ul> </div> </div> </li> <li class="accordion-item"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(2 + 6*(count - 1)) + '" aria-expanded="false" aria-controls="collapse' + str(2 + 6*(count - 1)) + '"  style="padding-left: 4.9em;"><b> View Categories: </b></button> <div id="collapse' + str(2 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + categoriesHtml + '</ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 3em;"><b>Date First Submitted: </b>' + self.firstSubmitted + '</li> <li class="list-group-item" style="padding-left: 3.7em;"><b>Date Last Analysed: </b>' + self.lastSubmitted + '</li> <li class="list-group-item" style="padding-left: 4em;"><b>Total Submissions: </b>' + str(self.totalSubmissions) + '</li> <li class="list-group-item" style="padding-left: 7.8em;"><b>Final URL: </b>' + self.finalUrl + '</li> <li class="list-group-item" style="padding-left: 8.2em;"><b>Site Title: </b>' + self.siteTitle + '</li> <li class="list-group-item" style="padding-left: 6.1em;"><b>Content Type: </b>' + self.contentType + '</li> <li class="list-group-item" style="padding-left: 9.1em;"><b>Server: </b>' + self.server + '</li> <li class="list-group-item" style="padding-left: 5.1em;"><b>Response Code: </b>' + str(self.response) + '</li> <li class="list-group-item" style="padding-left: 5.5em;"><b>VirusTotal Link: </b><a href=' + self.reportLink + ' target="_blank">View the VirusTotal Report</a></li> </ul> </div> </div>'
        return html

    # Parse Virustotal query response
    def parse(self, json):
        if "data" in json:
            if "title" in json["data"]["attributes"]:
                self.setSiteTitle(str(json["data"]["attributes"]["title"]))
            if "last_http_response_code" in json["data"]["attributes"]:
                self.setResponse(str(json["data"]["attributes"]["last_http_response_code"]))
            if "last_http_response_headers" in json["data"]["attributes"]:
                if "server" in json["data"]["attributes"]["last_http_response_headers"]:
                    self.setServer(str(json["data"]["attributes"]["last_http_response_headers"]["server"]))
                if "content-type" in json["data"]["attributes"]["last_http_response_headers"]:
                    self.setContentType(str(json["data"]["attributes"]["last_http_response_headers"]["content-type"]))

            detections = []
            categories = []
            if "last_analysis_results" in json["data"]["attributes"]:
                for engine in json["data"]["attributes"]["last_analysis_results"]:
                    if json["data"]["attributes"]["last_analysis_results"][engine]["category"] == "malicious" or json["data"]["attributes"]["last_analysis_results"][engine]["category"] == "suspicious":
                        detection = [json["data"]["attributes"]["last_analysis_results"][engine]["engine_name"], json["data"]["attributes"]["last_analysis_results"][engine]["category"]]
                        detections.append(detection)
            self.setDetections(detections)

            if "categories" in json["data"]["attributes"]:
                for comment in json["data"]["attributes"]["categories"]:
                    category = [comment, json["data"]["attributes"]["categories"][comment]]
                    categories.append(category)
            self.setCategories(categories)

            self.setCleanDetection(json["data"]["attributes"]["last_analysis_stats"]["harmless"])
            self.setMalDetection(json["data"]["attributes"]["last_analysis_stats"]["malicious"])
            self.setSusDetection(json["data"]["attributes"]["last_analysis_stats"]["suspicious"])
            self.setUndetected(json["data"]["attributes"]["last_analysis_stats"]["undetected"])
            
            self.setFirstSubmitted(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["first_submission_date"]).replace(tzinfo=datetime.timezone.utc)))

            self.setLastSubmitted(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["last_analysis_date"]).replace(tzinfo=datetime.timezone.utc)))
            self.setTotalSubmissions(str(json["data"]["attributes"]["times_submitted"]))
            self.setFinalURL(str(json["data"]["attributes"]["url"]))
            self.setReportLink("https://www.virustotal.com/gui/url/" + str(json["data"]["id"]) + "/detection")
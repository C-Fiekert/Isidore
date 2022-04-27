import requests, dataclasses

# Shodan Class ###########################################################################################################
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        return {"IP Address": self.ipAddress, "Country": self.country, "City": self.city, "Latitude": self.latitude, 
                "Longitude": self.longitude, "Last Updated": self.lastUpdated, "Org": self.org, "ISP": self.isp, 
                "ASN": self.asn, "Vulnerabilities": self.vulnerabilities, "Ports": self.ports, "Report Link": self.reportLink}

    # Converts dictionary to object
    def fromdict(self, item):
        self.ipAddress = item.val()["Shodan"]["IP Address"]
        self.country = item.val()["Shodan"]["Country"]
        self.city = item.val()["Shodan"]["City"]
        self.latitude = item.val()["Shodan"]["Latitude"]
        self.longitude = item.val()["Shodan"]["Longitude"]
        self.lastUpdated = item.val()["Shodan"]["Last Updated"]
        self.org = item.val()["Shodan"]["Org"]
        self.isp = item.val()["Shodan"]["ISP"]
        self.asn = item.val()["Shodan"]["ASN"]
        if "Vulnerabilities" in item.val()["Shodan"]:
            self.vulnerabilities = item.val()["Shodan"]["Vulnerabilities"]
        self.ports = item.val()["Shodan"]["Ports"]
        self.reportLink = item.val()["Shodan"]["Report Link"]

        return Shodan(self.ipAddress, self.country, self.city, self.latitude, self.longitude, self.lastUpdated, self.org, 
        self.isp, self.asn, self.vulnerabilities, self.ports, self.reportLink)

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
    
    # Generates HTML for Shodan card
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

        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"><h3 class="card-title">Shodan Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/shodan.png" id="shlogo" class="rounded mx-auto d-block" style="width: 85%; height: 14%;"><br> <div style="width: 100%"><iframe scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?width=100%25&amp;height=400&amp;hl=en&amp;q=' + str(self.latitude) + ',%20' + str(self.longitude) + '+(My%20Business%20Name)&amp;t=&amp;z=14&amp;ie=UTF8&amp;iwloc=B&amp;output=embed" width="100%" height="400" frameborder="0"></iframe></div> <br><ul class="list-group"><li class="list-group-item" style="padding-left: 5em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 6.1em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 8em;"><b>City: </b>' + self.city + '</li><li class="list-group-item" style="padding-left: 5.9em;"><b>Latitude: </b>' + str(self.latitude) + '</li><li class="list-group-item" style="padding-left: 5em;"><b>Longitude: </b>' + str(self.longitude) + '</li><li class="list-group-item" style="padding-left: 3.5em;"><b>Last Updated: </b>' + self.lastUpdated + '</li><li class="list-group-item" style="padding-left: 7.9em;"><b>Org: </b>' + self.org + '</li><li class="list-group-item" style="padding-left: 8.1em;"><b>ISP: </b>' + self.isp + '</li><li class="list-group-item" style="padding-left: 7.5em;"><b>ASN: </b>' + self.asn + '</li><li class="accordion-item"><h2 class="accordion-header" id="headingThree"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree" aria-expanded="true" aria-controls="collapseThree"  style="padding-left: 2.7em;"><b>Vulnerabilities:</b></button></h2><div id="collapseThree" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + vulnsHtml + ' </ul></div></div></li><li class="accordion-item"><h2 class="accordion-header" id="headingFour"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour" aria-expanded="true" aria-controls="collapseFour"  style="padding-left: 6.9em;"><b>Ports: </b></button></h2><div id="collapseFour" class="accordion-collapse collapse" aria-labelledby="headingFour" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + portsHtml + '</ul></div></div></li><li class="list-group-item" style="padding-left: 3.8em;"><b>Shodan Link:</b><a href=' + self.reportLink + ' target="_blank"> View the Shodan Report</a></li> </ul></div></div>'
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
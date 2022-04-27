import requests, pycountry, dataclasses

# IPinfo Class ###########################################################################################################
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        return {"IP Address": self.ipAddress, "Hostname": self.hostName, "City": self.city, "Region": self.region, 
                "Country": self.country, "Postal Area": self.postalArea, "Org": self.org, "Timezone": self.timezone, 
                "Latitude": self.latitude, "Longitude": self.longitude}

    # Converts dictionary to object
    def fromdict(self, item):
        self.ipAddress = item.val()["IPinfo"]["IP Address"]
        self.hostName = item.val()["IPinfo"]["Hostname"]
        self.city = item.val()["IPinfo"]["City"]
        self.region = item.val()["IPinfo"]["Region"]
        self.country = item.val()["IPinfo"]["Country"]
        self.postalArea = item.val()["IPinfo"]["Postal Area"]
        self.org = item.val()["IPinfo"]["Org"]
        self.timezone = item.val()["IPinfo"]["Timezone"]
        self.latitude = item.val()["IPinfo"]["Latitude"]
        self.longitude = item.val()["IPinfo"]["Longitude"]

        return IPinfo(self.ipAddress, self.hostName, self.city, self.region, self.country, self.postalArea, self.org, 
        self.timezone, self.latitude, self.longitude)

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

    # Generates HTML for IPinfo card
    def generate(self):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"><h3 class="card-title">Shodan Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/ipinfo.png" class="rounded mx-auto d-block" id="ipilogo"><br><div style="width: 100%"><iframe scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?width=100%25&amp;height=400&amp;hl=en&amp;q=' + self.latitude + ',' + self.longitude + '&amp;t=&amp;z=14&amp;ie=UTF8&amp;iwloc=B&amp;output=embed" width="100%" height="400" frameborder="0"></iframe></div> <br><ul class="list-group"><li class="list-group-item" style="padding-left: 2.8em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 3em;"><b>Hostname: </b>' + self.hostName + '</li><li class="list-group-item" style="padding-left: 6em;"><b>City: </b>' + self.city + '</li><li class="list-group-item" style="padding-left: 4.6em;"><b>Region: </b>' + self.region + '</li><li class="list-group-item" style="padding-left: 4.1em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 2.6em;"><b>Postal Area: </b>' + str(self.postalArea) + '</li><li class="list-group-item" style="padding-left: 6.1em;"><b>Org: </b>' + self.org + '</li><li class="list-group-item" style="padding-left: 3.3em;"><b>Timezone: </b>' + self.timezone + '</li></ul></div></div>'
        return html
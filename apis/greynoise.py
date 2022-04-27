import requests, dataclasses

# Greynoise Class ########################################################################################################
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        return {"IP Address": self.ipAddress, "Noise": self.noise, "RIOT": self.riot, "Verdict": self.verdict, 
                "Name": self.name, "Last Seen": self.lastSeen, "Report Link": self.reportLink}

    # Converts dictionary to object
    def fromdict(self, item):
        self.ipAddress = item.val()["Greynoise"]["IP Address"]
        self.noise = item.val()["Greynoise"]["Noise"]
        self.riot = item.val()["Greynoise"]["RIOT"]
        self.verdict = item.val()["Greynoise"]["Verdict"]
        self.name = item.val()["Greynoise"]["Name"]
        self.lastSeen = item.val()["Greynoise"]["Last Seen"]
        self.reportLink = item.val()["Greynoise"]["Report Link"]

        return Greynoise(self.ipAddress, self.noise, self.riot, self.verdict, self.name, self.lastSeen, self.reportLink)
    
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

        # Passes query to parse function
        self.parse(response_json)

    # Generates HTML for Greynoise card
    def generate(self):
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"><h3 class="card-title">Greynoise Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/greynoise.png" class="rounded mx-auto d-block" id="gnlogo" style="width: 85%; height: 25%;"><br><ul class="list-group"><li class="list-group-item" style="padding-left: 5em;"><b>IP Address: </b>' + self.ipAddress + '</li><li class="list-group-item" style="padding-left: 7.3em;"><div data-bs-toggle="tooltip" title="Has been observed scanning the internet"><b>Noise: </b>' + str(self.noise) + '</div></li><li class="list-group-item" style="padding-left: 7.7em;"><div data-bs-toggle="tooltip" title="Rule It OuT: Declared safe by Greynoise"><b>RIOT: </b>' + str(self.riot) + '</div></li><li class="list-group-item" style="padding-left: 6.6em;"><b>Verdict: </b>' + self.verdict + '</li><li class="list-group-item" style="padding-left: 7.1em;"><b>Name: </b>' + self.name + '</li><li class="list-group-item" style="padding-left: 5.4em;"><b>Last Seen: </b>' + self.lastSeen + '</li><li class="list-group-item" style="padding-left: 2.9em;"><b>Greynoise Link: </b><a href=' + self.reportLink + ' target="_blank">View the Greynoise Report</a></li></ul></div></div>'
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
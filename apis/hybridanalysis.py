import requests, datetime, time, re, dataclasses

# Hybrid Analysis Class ##################################################################################################
@dataclasses.dataclass
class HybridAnalysis:
    
    # Class Initialiser
    def __init__(self, submissionName, verdict, analysisTime, filetype="", filesize="", md5="", sha1="", sha256=""):
        self.submissionName = submissionName
        self.verdict = verdict
        self.analysisTime = analysisTime
        self.filetype = filetype
        self.filesize = filesize
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
 
    # Submission Name setter
    def setSubmissionName(self, submissionName):
        self.submissionName = submissionName

    # Verdict setter
    def setVerdict(self, verdict):
        self.verdict = verdict

    # Analysis Time setter
    def setAnalysisTime(self, analysisTime):
        self.analysisTime = analysisTime

    # Converts object to dictionary
    def todict(self):
        return {"Submission Name": self.submissionName, "Verdict": self.verdict, "Analysis Time": self.analysisTime, "File Type": self.filetype, 
                "File Size": self.filesize, "MD5": self.md5, "SHA1": self.sha1, "SHA256": self.sha256}

    # Converts dictionary to object
    def fromdict(self, item):
        self.submissionName = item.val()["Hybrid Analysis"]["Submission Name"]
        self.verdict = item.val()["Hybrid Analysis"]["Verdict"]
        self.analysisTime = item.val()["Hybrid Analysis"]["Analysis Time"]
        self.filetype = item.val()["Hybrid Analysis"]["File Type"]
        self.filesize = item.val()["Hybrid Analysis"]["File Size"]
        self.md5 = item.val()["Hybrid Analysis"]["MD5"]
        self.sha1 = item.val()["Hybrid Analysis"]["SHA1"]
        self.sha256 = item.val()["Hybrid Analysis"]["SHA256"]

        return HybridAnalysis(self.submissionName, self.verdict, self.analysisTime, self.filetype, self.filesize, self.md5, self.sha1, self.sha256)

    # Queries API for information
    def retrieve(self, query, type, key):
        if key == "":
            return

        if type == "url":
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
                    self.sort(response_json, "url")
        else:
            headers = {'api-key': key, "accept": "application/json", "user-agent": "Falcon Sandbox", "Content-Type": "application/x-www-form-urlencoded"}
            # API request for Hybrid Analsyis information on the provided URL
            response = requests.post("https://www.hybrid-analysis.com/api/v2/search/hash", headers=headers , data = 'hash=' + query)
            response_json = response.json()

            # Checks for valid API key
            if "message" in response_json:
                if "The provided API key is incompatible" in response_json["message"]:
                    return

            # Queries and returns information
            if len(response_json) > 0:
                self.sort(response_json, "filehash")

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
    def sort(self, json, type):
        if type == "url":
            datelist = []
            for info in json["result"]:
                temp = info["analysis_start_time"]
                if temp != None:
                    if temp[10] == "T":
                        temp = temp[0:10] + " " + temp[11:19]
                    datelist.append(temp)
            datelist.sort(key=lambda date: datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S"))
            selection = json["result"][0]
            for info in json["result"]:
                if info["analysis_start_time"] != None:
                    check = info["analysis_start_time"][0:10] + " " + info["analysis_start_time"][11:19]
                    if check == datelist[len(datelist)-1]:
                        selection = info

            if json["search_terms"][0]["value"] != None:
                self.setSubmissionName(json["search_terms"][0]["value"])
            if selection["verdict"] != None:
                self.setVerdict(selection["verdict"])
            if selection["analysis_start_time"] != None:
                self.setAnalysisTime(selection["analysis_start_time"])
        else:
            if json[0]["state"] == "SUCCESS":
                # Sorts through the Hybrid Analysis response for all relevant information and parses it correctly
                if json[0]["verdict"] != None:
                    self.setVerdict(json[0]["verdict"])
                if json[0]["analysis_start_time"] != None:
                    self.setAnalysisTime(json[0]["analysis_start_time"])
                if json[0]["size"] != None:
                    temp = json[0]["size"] / 1000
                    self.filesize = str(temp) + " KB"
                if json[0]["type"] != None:
                    self.filetype = json[0]["type"]
                if json[0]["md5"] != None:
                    self.md5 = json[0]["md5"]
                if json[0]["sha1"] != None:
                    self.sha1 = json[0]["sha1"]
                if json[0]["sha256"] != None:
                    self.sha256 = json[0]["sha256"]

    # Parses newly retrieved information
    def parse(self, json):
        if json[0]["submit_name"] != None:
            self.setSubmissionName(json[0]["submit_name"])
        if json[0]["verdict"] != None:
            self.setVerdict(json[0]["verdict"])
        if json[0]["analysis_start_time"] != None:
            self.setAnalysisTime(json[0]["analysis_start_time"])

    # Generates the HTML for Hybrid Analysis card
    def generate(self, type):
        if type == "url":
            html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">Hybrid Analysis Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/hybrid-analysis.png" class="rounded mx-auto d-block" id="halogo"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 2.8em;"><b>Submission Name: </b>' + self.submissionName + '</li> <li class="list-group-item" style="padding-left: 7.8em;"><b>Verdict: </b>' + self.verdict + '</li> <li class="list-group-item" style="padding-left: 4.6em;"><b>Analysis Time: </b>' + self.analysisTime + '</li> </ul> <br><br><br> </div> </div>'
        else:
            html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">Hybrid Analysis Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/hybrid-analysis.png" class="rounded mx-auto d-block" id="urllogo" style="width: 70%; height: 16%;"> <br> <center> <h4> Hybrid Analysis detected this as ' + self.verdict + '</h4> </center> <br> <ul class="list-group"> <li class="list-group-item" style="padding-left: 2.8em;"><b>Analysis Time: </b>' + self.analysisTime + '</li> <li class="list-group-item" style="padding-left: 5.9em;"><b>Verdict: </b>' + self.verdict + '</li> <li class="list-group-item" style="padding-left: 5em;"><b>File Type: </b>' + self.filetype + '</li> <li class="list-group-item" style="padding-left: 5.3em;"><b>File Size: </b>' + self.filesize + '</li> <li class="list-group-item" style="padding-left: 4.2em;"><b>MD5 Hash: </b>' + self.md5 + '</li> <li class="list-group-item" style="padding-left: 3.9em;"><b>SHA1 Hash: </b>' + self.sha1 + '</li> <li class="list-group-item" style="padding-left: 2.7em;"><b>SHA256 Hash: </b>' + self.sha256 + '</li> </ul> </div> </div>'
        return html
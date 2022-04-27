import base64, requests, datetime, pycountry, time, re, json, dataclasses

# Virustotal Class #######################################################################################################
@dataclasses.dataclass
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
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        detect = {}
        category = {}
        for item in self.detections:
            detect[item[0].replace('.', '')] = item[1]
        for item in self.categories:
            category[item[0].replace('.', '')] = item[1]
        return {"Clean Detection": self.cleanDetection, "Malicious Detection": self.malDetection, "Undetected": self.undetected, "Suspicious Detection": self.susDetection, 
                "Detections": detect, "First Submitted": self.firstSubmitted, "Last Submitted": self.lastSubmitted, "Total Submissions": self.totalSubmissions, 
                "Report Link": self.reportLink, "Domain": self.domain, "registrar": self.registrar, "Categories": category, "Date Created": self.dateCreated, 
                "Last Modified": self.lastModified, "Cert Started": self.certStarted, "Cert Expires": self.certExpires, "Cert Issuer": self.certIssuer}

    # Converts dictionary to object
    def fromdict(self, item):
        self.cleanDetection = item.val()["Virustotal"]["Clean Detection"]
        self.malDetection = item.val()["Virustotal"]["Malicious Detection"]
        self.undetected = item.val()["Virustotal"]["Undetected"]
        self.susDetection = item.val()["Virustotal"]["Suspicious Detection"]
        if self.malDetection > 0 or self.susDetection > 0:
            self.detections = item.val()["Virustotal"]["Detections"]
        self.firstSubmitted = item.val()["Virustotal"]["First Submitted"]
        self.lastSubmitted = item.val()["Virustotal"]["Last Submitted"]
        self.totalSubmissions = item.val()["Virustotal"]["Total Submissions"]
        self.reportLink = item.val()["Virustotal"]["Report Link"]
        self.domain = item.val()["Virustotal"]["Domain"]
        if "Categories" in item.val()["Virustotal"]:
            self.categories = item.val()["Virustotal"]["Categories"]
        if "Registrar" in item.val()["Virustotal"]:
            self.registrar = item.val()["Virustotal"]["Registrar"]
        self.dateCreated = item.val()["Virustotal"]["Date Created"]
        self.lastModified = item.val()["Virustotal"]["Last Modified"]
        self.certStarted = item.val()["Virustotal"]["Cert Started"]
        self.certExpires = item.val()["Virustotal"]["Cert Expires"]
        self.certIssuer = item.val()["Virustotal"]["Cert Issuer"]

        return VtDomain(self.cleanDetection, self.malDetection, self.undetected, self.susDetection, self.detections, self.firstSubmitted, self.lastSubmitted, 
        self.totalSubmissions, self.vtGraph, self.reportLink, self.domain, self.categories, self.registrar, self.dateCreated, self.lastModified, self.certStarted,
        self.certExpires, self.certIssuer)

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # API call headers
        headers = {'x-apikey': key}
        # API request to retrieve URL information from VirusTotal
        result = "https://www.virustotal.com/api/v3/domains/" + query
        response = requests.get(result, headers=headers)
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
            if "creation_date" in json["data"]["attributes"]:
                self.setDateCreated(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["creation_date"]).replace(tzinfo=datetime.timezone.utc)))
            if "last_modification_date" in json["data"]["attributes"]:
                self.setLastModified(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["last_modification_date"]).replace(tzinfo=datetime.timezone.utc)))
            if "id" in json["data"]:
                self.setDomain(json["data"]["id"])
            
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
            if "registrar" in json["data"]["attributes"]:
                self.setRegistrar(json["data"]["attributes"]["registrar"])
            if "last_https_certificate" in json["data"]["attributes"]:
                self.setCertStarted(json["data"]["attributes"]["last_https_certificate"]["validity"]["not_before"])
                self.setCertExpires(json["data"]["attributes"]["last_https_certificate"]["validity"]["not_after"])
                self.setCertIssuer(json["data"]["attributes"]["last_https_certificate"]["issuer"]["O"])
            self.setCleanDetection(json["data"]["attributes"]["last_analysis_stats"]["harmless"])
            self.setMalDetection(json["data"]["attributes"]["last_analysis_stats"]["malicious"])
            self.setSusDetection(json["data"]["attributes"]["last_analysis_stats"]["suspicious"])
            self.setUndetected(json["data"]["attributes"]["last_analysis_stats"]["undetected"])
            self.setReportLink("https://www.virustotal.com/gui/domain/" + query + "/detection")

    # Generates HTML for Virustotal Domain
    def generate(self, count):
        # Detections list
        detectionsHtml = ""
        for i in self.detections:
            detectionsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        # Category list
        categoriesHtml = ""
        for i in self.categories:
            categoriesHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">VirusTotal Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/vt.png" class="rounded mx-auto d-block" id="vtlogo" style="width: 70%; height: 18%;"> <div id="chartdiv' + str(count) + '"></div> <br><br> <div id="detections"> <center> <button type="button" class="btn btn-success"> Clean Detections <span class="badge bg-dark">' + str(self.cleanDetection) + '</span> </button> <button type="button" class="btn btn-danger"> Malicious Detections <span class="badge bg-dark">' + str(self.malDetection) + '</span> </button> <button type="button" class="btn btn-secondary"> Undetected Detections <span class="badge bg-dark">' + str(self.undetected) + '</span> </button> </center> </div> <br> <ul class="list-group"> <li class="list-group-item" style="padding-left: 7.3em;"><b>Domain: </b>' + self.domain + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingOne"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(1 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(1 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> View Detections: </b></button> </h2> <div id="collapse' + str(1 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + detectionsHtml + '</ul> </div> </div> </li> <li class="accordion-item"> <h2 class="accordion-header" id="headingTwo"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(2 + 6*(count - 1)) + '" aria-expanded="false" aria-controls="collapse' + str(2 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> View Categories: </b></button> </h2> <div id="collapse' + str(2 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + categoriesHtml + ' </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 6.7em;"><b>Registrar: </b>' + self.registrar + '</li> <li class="list-group-item" style="padding-left: 4.5em;"><b>Creation Date: </b>' + self.dateCreated + '</li> <li class="list-group-item" style="padding-left: 4.5em;"><b>Last Modified: </b>' + self.lastModified + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingThree"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(5 + 6*(count - 1)) + '" aria-expanded="false" aria-controls="collapse' + str(5 + 6*(count - 1)) + '"  style="padding-left: 0.5em;"><b>Last HTTPS Certificate: </b></button> </h2> <div id="collapse' + str(5 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"><li class="list-group-item" style="padding-left: 3em;"><b>Certificate Started:</b> ' + self.certStarted + '</li><li class="list-group-item" style="padding-left: 3em;"><b>Certificate Expires:</b> ' + self.certExpires + '</li><li class="list-group-item" style="padding-left: 7.1em;"><b>Issued By:</b> ' + self.certIssuer + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 5.5em;"><b>VirusTotal Link: </b><a href=' + self.reportLink + ' target="_blank">View the VirusTotal Report</a></li> </ul> </div> </div>'
        return html

# Virustotal File Hash Sub-Class #########################################################################################
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        detect = {}
        for item in self.detections:
            detect[item[0].replace('.', '')] = item[1]
        return {"Clean Detection": self.cleanDetection, "Malicious Detection": self.malDetection, "Undetected": self.undetected, "Suspicious Detection": self.susDetection, 
                "Detections": detect, "First Submitted": self.firstSubmitted, "Last Submitted": self.lastSubmitted, "Total Submissions": self.totalSubmissions, 
                "Report Link": self.reportLink, "Description": self.description, "Known Names": self.knownNames, "File Size": self.fileSize, "Threat Label": self.threatLabel, 
                "Magic": self.magic, "Product": self.product, "Product Description": self.productDesc, "Product Version": self.productVersion, "MD5": self.md5, 
                "SHA1": self.sha1, "SHA256": self.sha256}

    # Converts dictionary to object
    def fromdict(self, item):
        self.cleanDetection = item.val()["Virustotal"]["Clean Detection"]
        self.malDetection = item.val()["Virustotal"]["Malicious Detection"]
        self.undetected = item.val()["Virustotal"]["Undetected"]
        self.susDetection = item.val()["Virustotal"]["Suspicious Detection"]
        if self.malDetection > 0 or self.susDetection > 0:
            self.detections = item.val()["Virustotal"]["Detections"]
        self.firstSubmitted = item.val()["Virustotal"]["First Submitted"]
        self.lastSubmitted = item.val()["Virustotal"]["Last Submitted"]
        self.totalSubmissions = item.val()["Virustotal"]["Total Submissions"]
        self.reportLink = item.val()["Virustotal"]["Report Link"]
        self.description = item.val()["Virustotal"]["Description"]
        self.knownNames = item.val()["Virustotal"]["Known Names"]
        self.fileSize = item.val()["Virustotal"]["File Size"]
        self.threatLabel = item.val()["Virustotal"]["Threat Label"]
        self.magic = item.val()["Virustotal"]["Magic"]
        self.product = item.val()["Virustotal"]["Product"]
        self.productDesc = item.val()["Virustotal"]["Product Description"]
        self.productVersion = item.val()["Virustotal"]["Product Version"]
        self.md5 = item.val()["Virustotal"]["MD5"]
        self.sha1 = item.val()["Virustotal"]["SHA1"]
        self.sha256 = item.val()["Virustotal"]["SHA256"]

        return VtFileHash(self.cleanDetection, self.malDetection, self.undetected, self.susDetection, self.detections, self.firstSubmitted, self.lastSubmitted, 
        self.totalSubmissions, self.vtGraph, self.reportLink, self.description, self.knownNames, self.fileSize, self.threatLabel, self.magic, self.product, 
        self.productDesc, self.productVersion, self.md5, self.sha1, self.sha256)

    # Retrieve information
    def retrieve(self, query, key):
        if key == "":
            return
        
        # API call headers
        headers = {'x-apikey': key}
        # API request to retrieve URL information from VirusTotal
        result = "https://www.virustotal.com/api/v3/files/" + query
        response = requests.get(result, headers=headers)
        response_json = response.json()
        if "error" in response_json:
            if "Wrong API key" in response_json["error"]["message"]:
                print("Wrong API key")
                return
            else:
                print("Big Problemo")

        self.parse(response_json)


    # Parse Virustotal query response
    def parse(self, json):
        if "data" in json:
            if "type_description" in json["data"]["attributes"]:
                self.setDescription(str(json["data"]["attributes"]["type_description"]))
            names = []
            if "names" in json["data"]["attributes"]:
                vtNames = json["data"]["attributes"]["names"]
                for i in vtNames:
                    names.append(i)
            self.setKnownNames(names)
            if "size" in json["data"]["attributes"]:
                temp1 = json["data"]["attributes"]["size"] / 1000
                self.setFileSize(str(temp1) + " KB")
            if "popular_threat_classification" in json["data"]["attributes"]:
                self.setThreatLabel(json["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"])
            if "signature_info" in json["data"]["attributes"]:
                if "product" in json["data"]["attributes"]["signature_info"]:
                    self.setProduct(json["data"]["attributes"]["signature_info"]["product"])
                if "description" in json["data"]["attributes"]["signature_info"]:
                    self.setProductDesc(json["data"]["attributes"]["signature_info"]["description"])
                if "file version" in json["data"]["attributes"]["signature_info"]:
                    self.setProductVersion(json["data"]["attributes"]["signature_info"]["file version"])
            if "magic" in json["data"]["attributes"]:
                self.setMagic(json["data"]["attributes"]["magic"])
            if "md5" in json["data"]["attributes"]:
                self.setMD5(json["data"]["attributes"]["md5"])
            if "sha1" in json["data"]["attributes"]:
                self.setSHA1(json["data"]["attributes"]["sha1"])
            if "sha256" in json["data"]["attributes"]:
                self.setSHA256(json["data"]["attributes"]["sha256"])
            
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
            
            self.setFirstSubmitted(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["first_submission_date"]).replace(tzinfo=datetime.timezone.utc)))
            self.setLastSubmitted(str(datetime.datetime.utcfromtimestamp(json["data"]["attributes"]["last_analysis_date"]).replace(tzinfo=datetime.timezone.utc)))
            self.setTotalSubmissions(str(json["data"]["attributes"]["times_submitted"]))
            self.setReportLink("https://www.virustotal.com/gui/file/" + str(json["data"]["id"]) + "/detection")

    # Generates HTML for Virustotal Filehash card
    def generate(self, count):
        # Detections list
        detectionsHtml = ""
        for i in self.detections:
            detectionsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'

        namesHtml = ""
        for i in self.knownNames:
            namesHtml += '<li class="list-group-item" style="padding-left: 3em;">' + i + '</li>'
        
        html = '<div class="card shadow-lg"> <div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"> <h3 class="card-title">VirusTotal Results</h3> <div class="card-tools"> <button type="button" class="btn btn-tool" data-card-widget="collapse"> <i class="fas fa-minus"></i> </button> </div> </div> <div class="card-body"> <img src="/static/vt.png" class="rounded mx-auto d-block" id="vtlogo" style="width: 70%; height: 22%;"> <div id="chartdiv' + str(count) + '"></div> <br><br> <div id="detections"> <center> <button type="button" class="btn btn-success"> Clean Detections <span class="badge bg-dark">' + str(self.cleanDetection) + '</span> </button> <button type="button" class="btn btn-danger"> Malicious Detections <span class="badge bg-dark">' + str(self.malDetection) + '</span> </button> <button type="button" class="btn btn-secondary"> Undetected Detections <span class="badge bg-dark">' + str(self.undetected) + '</span> </button> </center> </div> <br> <ul class="list-group"> <li class="accordion-item"> <h2 class="accordion-header" id="headingOne"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(1 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(1 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> View Detections: </b></button> </h2> <div id="collapse' + str(1 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + detectionsHtml + '</ul> </div> </div> </li> <li class="accordion-item"> <h2 class="accordion-header" id="headingTwo"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(2 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(2 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> Submission Details: </b></button> </h2> <div id="collapse' + str(2 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"> <li class="list-group-item" style="padding-left: 2.8em;"><b>First Submitted: </b>' + self.firstSubmitted + '</li> <li class="list-group-item" style="padding-left: 2.8em;"><b>Last Analysed: </b>' + self.lastSubmitted + '</li> <li class="list-group-item" style="padding-left: 2.8em;"><b>Total Submissions: </b>' + str(self.totalSubmissions) + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 3em;"><b>Description: </b>' + self.description + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingThree"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(3 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(3 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> Known Names: </b></button> </h2> <div id="collapse' + str(3 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group">' + namesHtml + '</ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 3.7em;"><b>File Size: </b>' + self.fileSize + '</li> <li class="list-group-item" style="padding-left: 4em;"><b>Threat label: </b>' + self.threatLabel + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingFour"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(4 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(4 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> Signature Info: </b></button> </h2> <div id="collapse' + str(4 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingFour" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"><li class="list-group-item" style="padding-left: 3em;"><b> Product: </b>' + self.product + '</li><li class="list-group-item" style="padding-left: 3em;"><b> Description: </b>' + self.productDesc + '</li><li class="list-group-item" style="padding-left: 3em;"><b> Version: </b>' + self.productVersion + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 3.7em;"><b>Magic: </b>' + self.magic + '</li> <li class="accordion-item"> <h2 class="accordion-header" id="headingFive"> <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(5 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(5 + 6*(count - 1)) + '"  style="padding-left: 3.4em;"><b> Hashes: </b></button> </h2> <div id="collapse' + str(5 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingFive" data-bs-parent="#accordionExample"> <div class="accordion-body"> <ul class="list-group"><li class="list-group-item" style="padding-left: 3em;"><b> MD5: </b>' + self.md5 + '</li><li class="list-group-item" style="padding-left: 3em;"><b> SHA1: </b>' + self.sha1 + '</li><li class="list-group-item" style="padding-left: 3em;"><b> SHA256: </b>' + self.sha256 + '</li> </ul> </div> </div> </li> <li class="list-group-item" style="padding-left: 5.5em;"><b>VirusTotal Link: </b><a href=' + self.reportLink + ' target="_blank">View the VirusTotal Report</a></li> </ul> </div> </div>'
        return html

# Virustotal IP Address Sub-Class ########################################################################################
@dataclasses.dataclass
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

    # Convert object to dictionary
    def todict(self):
        detect = {}
        for item in self.detections:
            detect[item[0].replace('.', '')] = item[1]
        return {"Clean Detection": self.cleanDetection, "Malicious Detection": self.malDetection, "Undetected": self.undetected, "Suspicious Detection": self.susDetection, 
                "Detections": detect, "First Submitted": self.firstSubmitted, "Last Submitted": self.lastSubmitted, "Total Submissions": self.totalSubmissions, 
                "Report Link": self.reportLink, "Network": self.network, "Country": self.country, "Continent": self.continent, "ASO": self.aso, "ASN": self.asn, 
                "Registrar": self.registrar}

    # Convert dictionary to object
    def fromdict(self, item):
        self.cleanDetection = item.val()["Virustotal"]["Clean Detection"]
        self.malDetection = item.val()["Virustotal"]["Malicious Detection"]
        self.undetected = item.val()["Virustotal"]["Undetected"]
        self.susDetection = item.val()["Virustotal"]["Suspicious Detection"]
        if self.malDetection > 0 or self.susDetection > 0:
            self.detections = item.val()["Virustotal"]["Detections"]
        self.firstSubmitted = item.val()["Virustotal"]["First Submitted"]
        self.lastSubmitted = item.val()["Virustotal"]["Last Submitted"]
        self.totalSubmissions = item.val()["Virustotal"]["Total Submissions"]
        self.reportLink = item.val()["Virustotal"]["Report Link"]
        self.network = item.val()["Virustotal"]["Network"]
        self.country = item.val()["Virustotal"]["Country"]
        self.continent = item.val()["Virustotal"]["Continent"]
        self.aso = item.val()["Virustotal"]["ASO"]
        self.asn = item.val()["Virustotal"]["ASN"]
        self.registrar = item.val()["Virustotal"]["Registrar"]

        return VtIP(self.cleanDetection, self.malDetection, self.undetected, self.susDetection, self.detections, self.firstSubmitted, self.lastSubmitted, 
        self.totalSubmissions, self.vtGraph, self.reportLink, self.network, self.country, self.continent, self.aso, self.asn, self.registrar)

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

    # Generates HTML for Virustotal IP card
    def generate(self, count):
        # Detections list
        detectionsHtml = ""
        for i in self.detections:
            detectionsHtml += '<li class="list-group-item" style="padding-left: 3em;"><b>' + i[0] + ':</b> ' + i[1] + '</li>'
        
        html = '<div class="card shadow-lg"><div style="background-color: #0E4F61; color: white;" class="card-header ui-sortable-handle"><h3 class="card-title">VirusTotal Results</h3><div class="card-tools"><button type="button" class="btn btn-tool" data-card-widget="collapse"><i class="fas fa-minus"></i></button></div></div><div class="card-body"><img src="/static/vt.png" class="rounded mx-auto d-block" id="vtlogo" style="width: 70%;   height: 22%;"><div id="chartdiv' + str(count) + '"></div><br><br><div id="detections"><center><button type="button" class="btn btn-success"> Clean Detections <span class="badge bg-dark">' + str(self.cleanDetection) + '</span></button><button type="button" class="btn btn-danger"> Malicious Detections <span class="badge bg-dark">' + str(self.malDetection) + '</span></button><button type="button" class="btn btn-secondary"> Undetected Detections <span class="badge bg-dark">' + str(self.undetected) + '</span></button></center></div><br><ul class="list-group"><li class="accordion-item"><h2 class="accordion-header" id="headingOne"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + str(1 + 6*(count - 1)) + '" aria-expanded="true" aria-controls="collapse' + str(1 + 6*(count - 1)) + '"  style="padding-left: 6.5em;"><b> View Detections: </b></button></h2><div id="collapse' + str(1 + 6*(count - 1)) + '" class="accordion-collapse collapse" aria-labelledby="headingOne" data-bs-parent="#accordionExample"><div class="accordion-body"><ul class="list-group">' + detectionsHtml + '</ul></div></div></li><li class="list-group-item" style="padding-left: 10em;"><b>Network: </b>' + self.network + '</li><li class="list-group-item" style="padding-left: 10.2em;"><b>Country: </b>' + self.country + '</li><li class="list-group-item" style="padding-left: 9.5em;"><b>Continent: </b>' + self.continent + '</li><li class="list-group-item" style="padding-left: 1em;"><b>Autonomous System Owner: </b>' + self.aso + '</li><li class="list-group-item" style="padding-left: 0.2em;"><b>Autonomous System Number: </b>' + self.asn + '</li><li class="list-group-item" style="padding-left: 9.9em;"><b>Registrar: </b>' + self.registrar + '</li><li class="list-group-item" style="padding-left: 7.3em;"><b>VirusTotal Link: </b><a href=' + self.reportLink + ' target="_blank">View the VirusTotal Report</a></li> </ul></div></div>'
        return html

# Virustotal Url Sub-Class ###############################################################################################
@dataclasses.dataclass
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

    # Converts object to dictionary
    def todict(self):
        detect = {}
        category = {}
        for item in self.detections:
            detect[item[0].replace('.', '')] = item[1]
        for item in self.detections:
            category[item[0].replace('.', '')] = item[1]
        return {"Clean Detection": self.cleanDetection, "Malicious Detection": self.malDetection, "Undetected": self.undetected, "Suspicious Detection": self.susDetection, 
                "Detections": detect, "First Submitted": self.firstSubmitted, "Last Submitted": self.lastSubmitted, "Total Submissions": self.totalSubmissions, 
                "Report Link": self.reportLink, "Categories": category, "Final URL": self.finalUrl, "Site Title": self.siteTitle, "Content Type": self.contentType, 
                "Server": self.server, "Response": self.response}

    # Converts dictionary to object
    def fromdict(self, item):
        self.cleanDetection = item.val()["Virustotal"]["Clean Detection"]
        self.malDetection = item.val()["Virustotal"]["Malicious Detection"]
        self.undetected = item.val()["Virustotal"]["Undetected"]
        self.susDetection = item.val()["Virustotal"]["Suspicious Detection"]
        if self.malDetection > 0 or self.susDetection > 0:
            self.detections = item.val()["Virustotal"]["Detections"]
        self.firstSubmitted = item.val()["Virustotal"]["First Submitted"]
        self.lastSubmitted = item.val()["Virustotal"]["Last Submitted"]
        self.totalSubmissions = item.val()["Virustotal"]["Total Submissions"]
        self.reportLink = item.val()["Virustotal"]["Report Link"]
        if "Categories" in item.val()["Virustotal"]:
            self.categories = item.val()["Virustotal"]["Categories"]
        self.finalUrl = item.val()["Virustotal"]["Final URL"]
        self.siteTitle = item.val()["Virustotal"]["Site Title"]
        self.contentType = item.val()["Virustotal"]["Content Type"]
        self.server = item.val()["Virustotal"]["Server"]
        self.response = item.val()["Virustotal"]["Response"]

        return VtUrl(self.cleanDetection, self.malDetection, self.undetected, self.susDetection, self.detections, self.firstSubmitted, self.lastSubmitted, 
        self.totalSubmissions, self.vtGraph, self.reportLink, self.categories, self.finalUrl, self.siteTitle, self.contentType, self.server, self.response)
    
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
    
    # Generates HTML for Virustotal URL card
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
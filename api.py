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
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


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
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


# Hybrid Analysis Class ##################################################################################################
class HybridAnalysis:
    
    # Class Initialiser
    def __init__(self, submissionName, verdict, analysisTime):
        self.submissionName = submissionName
        self.verdict = verdict
        self.analysisTime = analysisTime
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


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
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


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
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


# Urlscan Class ##########################################################################################################
class Urlscan:
    
    # Class Initialiser
    def __init__(self, lastAnalysed, contentType, documentType, finalUrl, ipAddress, securityStatus, server, country, city, registrar, registerDate, verdicts, response, reportLink):
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
        self.verdicts = verdicts
        self.response = response
        self.reportLink = reportLink
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


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
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

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

        # invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

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

        # invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

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

        # invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

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

        # invoking the __init__ of the Virustotal class 
        Virustotal.__init__(self, cleanDetection, malDetection, undetected, susDetection, detections, firstSubmitted, lastSubmitted, totalSubmissions, vtGraph, reportLink)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)
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
        self.registrar - registrar

    # Register Date setter
    def setRegisterDate(self, registerDate):
        self.registerDate = registerDate

    # Verdicts setter
    def setVerdicts(self, verdicts):
        self.verdicts = verdicts

    # Response setter
    def setResponse(self, response):
        self.response = response

    # Report Link setter
    def setReportLink(self, reportLink):
        self.reportLink = reportLink


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
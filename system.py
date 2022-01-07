import re

# Query Class #######################################################################################################
class Query:
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime):
        self.id = id
        self.query = query
        self.submissionTime = submissionTime
 
    # Query setter
    def setQuery(self, query):
        self.query = query

    # Submission Time setter
    def setSubmissionTime(self, submissionTime):
        self.submissionTime = submissionTime

# Domain Query Sub-Class ############################################################################################
class DomainQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, urlscan):
        self.queryType = queryType
        self.virustotal = virustotal
        self.urlscan = urlscan
        # Invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)

    # Query Type setter
    def setQueryType(self, queryType):
        self.queryType = queryType

    # Virustotal object setter
    def setVirustotal(self, virustotal):
        self.virustotal = virustotal

    # UrlScan object setter
    def setUrlscan(self, urlscan):
        self.urlscan = urlscan
 
    # Fixes defanged Domain names
    def defang(self):
        # Takes the user query input and validates the Domain format
        self.query = self.query.replace("[.]", ".")

# File Hash Query Sub-Class #########################################################################################
class FileHashQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, hybridAnalysis):
        self.queryType = queryType
        self.virustotal = virustotal
        self.hybridAnalysis = hybridAnalysis
        # Invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)
 
    # Query Type setter
    def setQueryType(self, queryType):
        self.queryType = queryType

    # Virustotal object setter
    def setVirustotal(self, virustotal):
        self.virustotal = virustotal

    # Hybrid Analysis object setter
    def setHybridAnalysis(self, hybridAnalysis):
        self.hybridAnalysis = hybridAnalysis

# IP Address Query Sub-Class ########################################################################################
class IPQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, abuseIP, greynoise, shodan, ipInfo):
        self.queryType = queryType
        self.virustotal = virustotal
        self.abuseIP = abuseIP
        self.greynoise = greynoise
        self.shodan = shodan
        self.ipInfo = ipInfo
        # Invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)

    # Query Type setter
    def setQueryType(self, queryType):
        self.queryType = queryType

    # Virustotal object setter
    def setVirustotal(self, virustotal):
        self.virustotal = virustotal

    # AbuseIP object setter
    def setAbuseIP(self, abuseIP):
        self.abuseIP = abuseIP

    # Greynoise object setter
    def setGreynoise(self, greynoise):
        self,greynoise = greynoise

    # Shodan object setter
    def setShodan(self, shodan):
        self.shodan = shodan

    # IPInfo object setter
    def setIPInfo(self, ipinfo):
        self.ipInfo = ipinfo
 
    # Fixes defanged IP Addresses
    def defang(self):
        # Takes the user query input and validates the IP Address format
        self.query = self.query.replace("[.]", ".")

    # Validates IP Addresses
    def validate(self):
        # Checks for IP Address formatting
        match = re.search("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", self.query)
        if match == None:
            return False
        else:
            return True

# Url Query Sub-Class ###############################################################################################
class UrlQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, urlscan, hybridAnalysis):
        self.queryType = queryType
        self.virustotal = virustotal
        self.urlscan = urlscan
        self.hybridAnalysis = hybridAnalysis
        # Invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)

    # Query Type setter
    def setQueryType(self, queryType):
        self.queryType = queryType

    # Virustotal object setter
    def setVirustotal(self, virustotal):
        self.virustotal = virustotal

    # UrlScan object setter
    def setUrlscan(self, urlscan):
        self.urlscan = urlscan

    # Hybrid Analysis object setter
    def setHybridAnalysis(self, hybridAnalysis):
        self.hybridAnalysis = hybridAnalysis
 
    # Fixes defanged URLs
    def defang(self):
        # Takes the user query input and validates the URL format
        self.query = self.query.replace("hxxp://", "http://")
        self.query = self.query.replace("hxxps://", "https://")
        self.query = self.query.replace("[.]", ".")

    # Validates URLs
    def validate(self):
        # Checks for URL prefix
        match = re.search("^www.|^http://|^https://|^http://www.|^https://www.", self.query)
        if match == None:
            self.query = "www." + self.query
        # Checks for valid URL format
        match = re.search("https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,}", self.query)
        if match == None:
            return False
        else:
            return True

# Settings Class ########################################################################################################
class Settings:
    
    # Class Initialiser
    def __init__(self, virustotalKey, urlscanKey, hybridAnalysisKey, abuseIPKey, shodanKey, ipInfoKey):
        self.virustotalKey = virustotalKey
        self.urlscanKey = urlscanKey
        self.hybridAnalysisKey = hybridAnalysisKey
        self.abuseIPKey = abuseIPKey
        self.shodanKey = shodanKey
        self.ipInfoKey = ipInfoKey
 
    # Virustotal key setter
    def setVirustotalKey(self, key):
        self.virustotalKey = key
    
    # URLScan key setter
    def setURLScanKey(self, key):
        self.urlscanKey = key
    
    # Hybrid Analysis key setter
    def setHybridAnalysisKey(self, key):
        self.hybridAnalysisKey = key
    
    # AbuseIPDB key setter
    def setAbuseIPKey(self, key):
        self.abuseIPKey = key
    
    # Shodan key setter
    def setShodanKey(self, key):
        self.shodanKey = key
    
    # IPInfo key setter
    def setIPInfoKey(self, key):
        self.ipInfoKey = key

    # Update API key in Settings
    def updateApiKey(self, service, key):
        if service == "Virustotal":
            self.setVirustotalKey(key)
        elif service == "URLScan":
            self.setURLScanKey(key)
        elif service == "Hybrid Analysis":
            self.setHybridAnalysisKey(key)
        elif service == "AbuseIPDB":
            self.setAbuseIPKey(key)
        elif service == "Shodan":
            self.setShodanKey(key)
        elif service == "IPInfo":
            self.setIPInfoKey(key)
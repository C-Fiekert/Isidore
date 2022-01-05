# Query Class #######################################################################################################
class Query:
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime):
        self.id = id
        self.query = query
        self.submissionTime = submissionTime
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

# Domain Query Sub-Class ############################################################################################
class DomainQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, urlscan):
        self.queryType = queryType
        self.virustotal = virustotal
        self.urlscan = urlscan

        # invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

# File Hash Query Sub-Class #########################################################################################
class FileHashQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, hybridAnalysis):
        self.queryType = queryType
        self.virustotal = virustotal
        self.hybridAnalysis = hybridAnalysis

        # invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

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

        # invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)

# Url Query Sub-Class ###############################################################################################
class UrlQuery(Query):
    
    # Class Initialiser
    def __init__(self, id, query, submissionTime, queryType, virustotal, urlscan, hybridAnalysis):
        self.queryType = queryType
        self.virustotal = virustotal
        self.urlscan = urlscan
        self.hybridAnalysis = hybridAnalysis

        # invoking the __init__ of the Query class 
        Query.__init__(self, id, query, submissionTime)
 
    # A sample method 
    def fun(self):
        print("I'm a", self.attr1)
        print("I'm a", self.attr2)


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
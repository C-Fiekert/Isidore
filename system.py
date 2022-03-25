import re, os, datetime

def initialise(userSettings):
    # Read in API keys from text file
    cwd = os.path.dirname(os.path.abspath(__file__))
    os.chdir(cwd)
    f = open("keys.txt", "r")

    userSettings.setVirustotalKey(f.readline()[3:-1])
    userSettings.setURLScanKey(f.readline()[3:-1])
    userSettings.setHybridAnalysisKey(f.readline()[3:-1])
    userSettings.setAbuseIPKey(f.readline()[4:-1])
    userSettings.setShodanKey(f.readline()[3:-1])
    userSettings.setIPInfoKey(f.readline()[3:-1])
    f.close()


# Query Class #######################################################################################################
class Query:
    
    # Class Initialiser
    def __init__(self, qId, query, submissionTime):
        self.qId = qId
        self.query = query
        self.submissionTime = submissionTime

    # ID setter
    def setQID(self, qId):
        self.qId = qId
 
    # Query setter
    def setQuery(self, query):
        self.query = query

    # Submission Time setter
    def setSubmissionTime(self, submissionTime):
        self.submissionTime = submissionTime

# Domain Query Sub-Class ############################################################################################
class DomainQuery(Query):
    
    # Class Initialiser
    def __init__(self, qId, query, submissionTime, queryType, virustotal, urlscan):
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
    def __init__(self, qId, query, submissionTime, queryType, virustotal, hybridAnalysis):
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
    def __init__(self, qId, query, submissionTime, queryType, virustotal, abuseIP, greynoise, shodan, ipInfo):
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
        self.greynoise = greynoise

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

    def generateHTML(self, virustotal, abuseIP, greynoise, shodan, ipInfo, count):
        if count == 0:
            status = " active"
        else:
            status = ""
        html = '<div class="carousel-item' + status + '"><div><h3> <b>Submission: </b>' + self.query + '<br><b> Date: </b>' + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '</h3><br> <center><a style="background-color: #0E4F61; color: white; width: 10em;" role="button" href="#services" class="btn btn btn-lg"  data-slide="prev"><i class="fas fa-long-arrow-alt-left"></i> Previous</a> <span>            </span> <a style="background-color: #0E4F61; color: white; width: 10em;" role="button" href="#services" class="btn btn btn-lg"  data-slide="next">Next <i class="fas fa-long-arrow-alt-right"></i></a><center> <br></div>  <div class="row"> <section class="col-lg-6 connectedSortable ui-sortable">' + virustotal + greynoise + ipInfo + '</section> <section class="col-lg-6 connectedSortable ui-sortable">' + abuseIP + shodan + '</section> </div> </div>'
        
        return html

    def generateChart(self, virustotal, count):
        chart = '<script> am4core.ready(function() {am4core.useTheme(am4themes_animated); var chart = am4core.create("chartdiv' + str(count) + '", am4charts.PieChart3D); chart.innerRadius = am4core.percent(40); chart.data = [{"detection": "Clean", "count": ' + str(virustotal.cleanDetection) + ' }, {"detection": "Malicious", "count": ' + str(virustotal.malDetection) + ' }, {"detection": "Suspicious", "count": ' + str(virustotal.susDetection) + ' }, {"detection": "Undetected", "count": ' + str(virustotal.undetected) + ' }]; var pieSeries = chart.series.push(new am4charts.PieSeries3D()); pieSeries.dataFields.value = "count"; pieSeries.dataFields.category = "detection"; pieSeries.slices.template.stroke = am4core.color("#fff"); pieSeries.slices.template.strokeWidth = 2; pieSeries.slices.template.strokeOpacity = 1; pieSeries.labels.template.disabled = false; pieSeries.ticks.template.disabled = false; pieSeries.slices.template.states.getKey("hover").properties.shiftRadius = 0; pieSeries.slices.template.states.getKey("hover").properties.scale = 1.1; }); </script>'
        return chart

# Url Query Sub-Class ###############################################################################################
class UrlQuery(Query):
    
    # Class Initialiser
    def __init__(self, qId, query, submissionTime, queryType, virustotal, urlscan, hybridAnalysis):
        self.queryType = queryType
        self.virustotal = virustotal
        self.urlscan = urlscan
        self.hybridAnalysis = hybridAnalysis
        # Invoking the __init__ of the Query class 
        Query.__init__(self, qId, query, submissionTime)

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
        # Checks if query ends with '/'
        match = re.search("/$", self.query)
        if match != None:
            self.query = self.query[:-1]
        # Checks for valid URL format
        match = re.search("https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,}", self.query)
        if match == None:
            return False
        else:
            return True

    
    def generateHTML(self, virustotal, urlscan, hybridAnalysis, count):
        if count == 0:
            status = " active"
        else:
            status = ""
        html = '<div class="carousel-item' + status + '"><div><h3> <b>Submission: </b>' + self.query + '<br><b> Date: </b>' + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '</h3><br> <center><a style="background-color: #0E4F61; color: white; width: 10em;" role="button" href="#services" class="btn btn btn-lg"  data-slide="prev"><i class="fas fa-long-arrow-alt-left"></i> Previous</a> <span>            </span> <a style="background-color: #0E4F61; color: white; width: 10em;" role="button" href="#services" class="btn btn btn-lg"  data-slide="next">Next <i class="fas fa-long-arrow-alt-right"></i></a><center> <br></div>  <div class="row"> <section class="col-lg-6 connectedSortable ui-sortable">' + virustotal + '</section> <section class="col-lg-6 connectedSortable ui-sortable">' + urlscan + hybridAnalysis + '</section> </div> </div>'
        return html

    def generateChart(self, virustotal, count):
        chart = '<script> am4core.ready(function() {am4core.useTheme(am4themes_animated); var chart = am4core.create("chartdiv' + str(count) + '", am4charts.PieChart3D); chart.innerRadius = am4core.percent(40); chart.data = [{"detection": "Clean", "count": ' + str(virustotal.cleanDetection) + ' }, {"detection": "Malicious", "count": ' + str(virustotal.malDetection) + ' }, {"detection": "Suspicious", "count": ' + str(virustotal.susDetection) + ' }, {"detection": "Undetected", "count": ' + str(virustotal.undetected) + ' }]; var pieSeries = chart.series.push(new am4charts.PieSeries3D()); pieSeries.dataFields.value = "count"; pieSeries.dataFields.category = "detection"; pieSeries.slices.template.stroke = am4core.color("#fff"); pieSeries.slices.template.strokeWidth = 2; pieSeries.slices.template.strokeOpacity = 1; pieSeries.labels.template.disabled = false; pieSeries.ticks.template.disabled = false; pieSeries.slices.template.states.getKey("hover").properties.shiftRadius = 0; pieSeries.slices.template.states.getKey("hover").properties.scale = 1.1; }); </script>'
        return chart

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
        if service == "1":
            self.setVirustotalKey(key)
        elif service == "2":
            self.setURLScanKey(key)
        elif service == "3":
            self.setHybridAnalysisKey(key)
        elif service == "4":
            self.setAbuseIPKey(key)
        elif service == "5":
            self.setShodanKey(key)
        elif service == "6":
            self.setIPInfoKey(key)
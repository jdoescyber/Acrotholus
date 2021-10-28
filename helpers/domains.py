"""
    domains.py
    Purpose: Handle a txt document of domains and look up against various API endpoints.
    Author: Jackson Nestler
    Source: https://github.com/jdoescyber/acrotholus
"""

import requests, time, json
from helpers import text
from random import randrange

def checkThreatCrowd(domainFileLocation):

    """
    Checks each domain in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        with open(domainFileLocation, "r") as file:
            for line in file:
            
                # This is the API endpoint for domain lookups.
                result =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params = {"domain": line})
                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['response_code'] == "1": # ThreatCrowd uses its own 0 and 1 response codes, different from HTTP status codes.
                        text.printGreen("Found data for " + line)
                        
                        # We'll examine information about DNS resolution history.
                        for resolutions in jsonData['resolutions']: # for each result we get back...
                            resolvedTime = resolutions['last_resolved'] # Grab the time it was resolved at.
                            resolvedIP = resolutions['ip_address'] # Grab the IP the domain resolved to.
                            print("Domain had IP " + str(resolvedIP) + " on date " + resolvedTime)

                        # Now we check for subdomains
                        for subdomain in jsonData['subdomains']:
                            print("Known subdomain: " + str(subdomain))

                        # Check for any external references to support findings.
                        for reference in jsonData['references']:
                            print("Reference: " + str(reference))
                        
                        # Finally, look at the overall votes.
                        communityScore = jsonData['votes']
                        communityScore = str(communityScore)
                        print("The domain has an overall vote of " + communityScore + ". This is a community score.")

                    elif jsonData['response_code'] == "0": # If ThreatCrowd doesn't find any results.
                        text.printRed("No results for domain: " + line)
                        #print ("**DEBUG**: " + result.text) # Uncomment line to show the JSON response.
                else: 
                    # If the web server turns a non-200 HTTP status code.
                    text.printRed("ThreatCrowd API returned a non-200 status code. API may be down or you may be rate limited.")
                
                # ThreatCrowd requests a sleep of at least 10 seconds between requests, but allows bursting.
                # Subsequently, we're going to sleep between 5 and 10 seconds to be kind.
                # Adjust the TIME_MIN and TIME_MOST variables if you're willing to burst.
                # But bare in mind you may be temporarily banned from ThreatCrowd searches.

                TIME_MIN = 5
                TIME_MOST = 10

                courtesySleepDuration = randrange(TIME_MIN, TIME_MOST)
                #print ("sleeping for " + str(courtesySleepDuration)) # if you'd like to see how long you're sleeping for, uncomment.
                time.sleep(courtesySleepDuration)
    except Exception as e:
        print(e)

def checkThreatMiner(domainFileLocation):

    """
    Checks each domain in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        
        with open(domainFileLocation, 'r') as file:
            for line in file:
                url = "https://api.threatminer.org/v2/domain.php"

                # Start with passive DNS:
                params = {'q': line, 'rt': '2'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            knownIP = result['ip']
                            first_seen = result['first_seen']
                            last_seen = result['last_seen']
                            print("Domain had IP " + knownIP + " first seen at " + first_seen + " and last seen at " + last_seen)
                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
                
                # Now we'll move to subdomains
                params = {'q': line, 'rt':'5'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            print("Domain has known subdomain " + result)
                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
                
                # Check out related samples
                params = {'q': line, 'rt':'5'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            print("Associated hash: " + result)
                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
                        
                # Check for APTNotes
                params = {'q':line, 'rt':'6'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            text.printGreen("Found an APTNotes report.")
                            reportName = str(result['filename'])
                            reportDate = str(result['year'])
                            reportURL = str(result['URL'])
                            print("Name: " + reportName)
                            print("From year " + reportDate)
                            print("URL: " + reportURL)
                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
    except Exception as e:
        print(e)
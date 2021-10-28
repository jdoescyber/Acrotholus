"""
    ips.py
    Purpose: Handle a txt document of IP addresses and look up against various API endpoints.
    Author: Jackson Nestler
    Source: https://github.com/jdoescyber/acrotholus
"""

import requests, time, json
from helpers import text
from random import randrange

def checkThreatCrowd(ipFileLocation):

    """
    Checks each IP in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        with open(ipFileLocation, "r") as file:
            for line in file:
            
                # This is the API endpoint for IP lookups.
                result =  requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/", params = {"ip": line})

                jsonData = json.loads(result.text)
                if jsonData['response_code'] == "1":
                    text.printGreen("Found data for " + line)
                
                    # Looking at domains that pointed to this IP.
                    for resolutions in jsonData['resolutions']: # for each result we get back...
                        resolvedTime = resolutions['last_resolved'] # Grab the time it was resolved at.
                        resolvedDomain = resolutions['domain'] # Grab the domain the IP resolved to.
                        print("IP had domain " + str(resolvedDomain) + " on date " + resolvedTime)
                    
                    # Hashes known to communicate with this IP:
                    for hash in jsonData['hashes']:
                        print("The following hash was known to contact this IP: " + hash)

                    # Any references:
                    for reference in jsonData['references']:
                        print("Reference: " + reference)
                    
                    # Community vote:
                    communityScore = jsonData['votes']
                    communityScore = str(communityScore)
                    print("The vote for this IP is " + communityScore + ". This is a community score.")

                elif jsonData['response_code'] == "0":
                    text.printRed("No results for IP: " + line)
                    #print ("**DEBUG**: " + result.text) # Uncomment line to show the JSON response.
                
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

def checkThreatMiner(ipFileLocation):

    """
    Checks each domain in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        
        with open(ipFileLocation, 'r') as file:
            for line in file:
                url = "https://api.threatminer.org/v2/host.php"

                # Start with passive DNS:
                time.sleep(1)
                params = {'q': line, 'rt': '2'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            knownDomain = result['domain']
                            first_seen = result['first_seen']
                            last_seen = result['last_seen']
                            print("Domain had IP " + knownDomain + " first seen at " + first_seen + " and last seen at " + last_seen)

                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
            
                time.sleep(1)
                # Check out related samples
                params = {'q': line, 'rt':'4'}
                result = requests.get(url, params)

                if result.status_code == 200:
                    jsonData = json.loads(result.text)
                    if jsonData['status_code'] == "200":
                        for result in jsonData['results']:
                            print("Associated hash: " + result)

                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")

                time.sleep(1)    
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
                            time.sleep(1)
                else:
                    text.printRed("Received non-200 status code from ThreatMiner. API may be down or you may be rate limited.")
    except Exception as e:
        print(e)
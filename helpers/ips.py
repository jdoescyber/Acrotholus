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

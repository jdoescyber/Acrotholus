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
                    print("ThreatCrowd API returned a non-200 status code. API may be down or you may be rate limited.")
                
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

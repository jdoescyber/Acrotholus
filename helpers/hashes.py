"""
    hashes.py
    Purpose: Handle a txt document of hashes and look up against various API endpoints.
    Author: Jackson Nestler
    Source: https://github.com/jdoescyber/acrotholus
"""

import requests, time, json
from helpers import text
from random import randrange

def checkThreatCrowd(hashesFileLocation):

    """
    Checks each hash in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        with open(hashesFileLocation, "r") as file:
            for line in file:
            
                # This is the API endpoint for hash lookups.
                result =  requests.get("https://www.threatcrowd.org/searchApi/v2/file/report/", params = {"resource": line})
                jsonData = json.loads(result.text)
                if jsonData['response_code'] == "1":
                    text.printGreen("Found data for " + line)
                    
                    # AV Results
                    for avresult in jsonData['scans']:
                        avresult = str(avresult)
                        print ("AV flagged this hash as " + avresult)
                    
                    # IPs contacted
                    for contactedIP in jsonData['ips']:
                        contactedIP = str(contactedIP)
                        print ("File is known to contact IP " + contactedIP)
                    
                    # Domains contacted
                    for domainscontacted in jsonData['domains']:
                        domainscontacted = str(domainscontacted)
                        print ("File is known to contact domain " + domainscontacted)
                    
                    # References
                    for reference in jsonData['references']:
                        reference = str(reference)
                        print("External reference: " + reference)

                elif jsonData['response_code'] == "0":
                    text.printRed("No results for hash: " + line)
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

def checkThreatMiner(hashesFileLocation):

    """
    Checks each hash in a given file against the ThreatCrowd API. Does *not* require an API key.

    Returns:
        Nothing, just prints to terminal.
        In the future, may write to a CSV or text doc.
    """

    try:
        
        with open(hashesFileLocation, 'r') as file:
            for line in file:
                url = "https://api.threatminer.org/v2/sample.php"
                # NEED TO EVALUATE AND ADJUST THIS ENTIRE FUNCTION.
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
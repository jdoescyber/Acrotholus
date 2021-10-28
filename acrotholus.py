"""
    acrotholus.py
    Purpose: Reiteration of my previous project, SpookySOC. Speed up OSINT and artifact vetting through APIs.
    Author: Jackson Nestler (@jksn / @jdoescyber)
    Source: https://github.com/jdoescyber/acrotholus

"""

import argparse, os, yaml, pathlib
from typing import Text
from colorama import Fore, Back, Style
from helpers import text, ips, domains, hashes

def readAPIKeys():
    """
    Opens apiconfig.yaml and reads the API keys into a list. Does not attempt to check formatting or key validity.

    Returns:
        provider_dict [Dictionary] -- A simple dictionary containing the API keys.
    """
    try:
        with open("apiconfig.yaml") as apifile:
            provider_dict = yaml.load(apifile, Loader=yaml.FullLoader)
            return provider_dict
    except:
        text.printRed("Unable to open apiconfig.yaml. Have you created the file? Copy api_config_example.yaml if you need help.")
        exit(1)

def validateFile(f):
    if not os.path.exists(f):
        raise argparse.ArgumentTypeError("{0} does not exist. Please fix this.".format(f))

if __name__ == '__main__':

    # Setup argparse
    scriptDescription = "Acrotholus aims to speed up OSINT and artifact vetting through API usage."
    parser = argparse.ArgumentParser(description=scriptDescription)
    parser.add_argument("-ips","--ips-file", action="extend", 
                        nargs="+", dest="ipsfile", help="A file location with IP addresses.")
    parser.add_argument("--hashes-file", action="extend", 
                        nargs="+", dest="hashesfile", help="A file location with hashes.")
    parser.add_argument("--domains-file", action="extend", 
                        nargs="+", dest="domainsfile", help="A file location with domains.")
    args = parser.parse_args()

    # API_KEYS_LIST = readAPIKeys() # Working with API-less options right now.

    if args.ipsfile:
        text.printGreen("IP list selected.")
        for eachFileInList in args.ipsfile:
            ips.checkThreatCrowd(eachFileInList)
    if args.domainsfile:
        text.printGreen("Domain list selected.")
        for eachFileInList in args.domainsfile:
            domains.checkThreatCrowd(eachFileInList)
    if args.hashesfile:
        text.printGreen("Hash list selected.")
        for eachFileInList in args.hashesfile:
            hashes.checkThreatCrowd(eachFileInList)



"""
    text.py
    Purpose: Print green or red text, reducing colorama usage in other modules.
    Author: Jackson Nestler
    Source: https://github.com/jdoescyber/acrotholus
"""


from colorama import Fore, Back, Style

def printGreen(toprint):
    print(Fore.GREEN + toprint + Style.RESET_ALL)

def printRed(toprint):
    print(Fore.RED + toprint + Style.RESET_ALL)
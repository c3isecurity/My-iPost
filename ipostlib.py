#!/usr/bin/env python
"""
 This script explores and demonstrates the Risk Scoring algorithms and
 formulas used in the Department of State (DoS) iPost program.
 The examples below are based on the US Department of State Case Study.
 This is meant for testing and learning and should not be used for
 production environments. Have fun and use at your own risk

 This script provides results based on the DoS formulas. The risk
 scores are for an individual host.
 The ending total score could be used to aggregate a site, and
 enterprise score.
"""

# This python module is for the iPost Risk Scoring forumlas.


# The math module is need for some of the formulas.
import math

__author__ = "Luis NUnez"
__copyright__ = "Copyright 2014, C3isecurity"

__license__ = "GPLv3"
__version__ = "0.2.0"
__maintainer__ = "Luis Nunez"
__email__ = "lnunez@c3isecurity.com"
__status__ = "Prototype"


# Functions: Formula

# Vulnerability (VUL) score formula to convert CVSS to DoS score.
# DoS VUL Score = (CVSS Score)N / 10(N-1) where N=3
def Vul_Score(CVSS):
    return math.pow(CVSS, 3) / math.pow(10, 2)


# Anti-Virus AVR Formula
# Host
# AVR Score = (IF Signature File Age > 6 THEN 1 Else 0) * 6.0
#    * Signature File Age
def Host_AVR_Score(AVR_Age):
    if AVR_Age > 6:
        return 1 * 6.0 * AVR_Age
    else:
        return 6.0 * AVR_Age


# Patch (PAT) -
# Host PAT Score = SUM(PAT scores of all incompletely installed patches)
def Host_PAT_Score(): 
    pass


if __name__ == '__main__':
    print "ipostlib"

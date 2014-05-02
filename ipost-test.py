#!/usr/bin/env python
"""
 Ipost-test.py is a self test of the functions.
 This script explores and demonstrates the Risk Scoring algorithms and formulas used in the 
 Department of State (DoS) iPost program.
 The examples below are based on the US Department of State Case Study found at 
 http://www.counciloncybersecurity.org/attachments/article/46/US%20Dept%20of%20State%20Case%20Study.pdf 
 This is meant for testing and learning and should not be used for production environments.  
 Have fun and use at your own risk

 This script provides results based on the DoS formulas. The risk scores are for an individual host.  
 The ending total score could be used to aggregate a site, and enterprise score.
"""

# The math module is need for some of the formulas.
import math

# Variables
# Adjust the AV_Age and CVSS scores to see results.
AV_Age = 70
CVSS = [10.0, 9.0, 8, 7, 6, 5, 4, 3, 2, 1]
Host_Vul_Score = 0
Count_Vuls = 0
#PAT_Missing []


# CVSS Severity Levels
High = 7
Low = 3


# Functions: Formula 

# Vulnerability (VUL) score formula to convert CVSS to DoS score. 
# DoS VUL Score = (CVSS Score)N / 10(N-1) where N=3
def Vul_Score(CVSS):
	return math.pow(CVSS,3) / math.pow(10,2)

# Anti-Virus AVR Formula 
# Host AVR Score = (IF Signature File Age > 6 THEN 1 Else 0) * 6.0 * Signature File Age
def Host_AVR_Score(AVR_Age):
	return 1 * 6.0 * AVR_Age
		
# Patch (PAT) - 
# Host PAT Score = SUM(PAT scores of all incompletely installed patches)
def Host_PAT_Score ():
	Host_PAT_Score += Host_PAT_Score
	print test


# Start of main body of script


# This route reads the CVSS list as vulnerability score to process
# it then gets the total 
print "CVSS\tDoS"
for i in CVSS:
	int(i)
	print "%d\t\t%d " % (i,  Vul_Score(i))
	Host_Vul_Score += Vul_Score(i)
	if Host_Vul_Score >= High: 	# Higher or equal to 7
		Severity = "High"
	elif Host_Vul_Score < High and Host_Vul_Score > Low:
		Severity = "Medium" 	# Less the 7 but higher than 3
	elif Host_Vul_Score <= Low: # less than or equal to 3
		Severity = "Low"
	Count_Vuls += 1



# Report section

# Print to standard out.

print "Start Self Test of Script"
print "iPost Results\n"
print "Number Vuls calculated:", Count_Vuls
#print "Host Vulnerability  Score:\t\t\t", Vul_Score(10)
print "Host_AVR_Score:\t\t\t", Host_AVR_Score(3.1)
print "Total Host Vul Score:\t", Host_Vul_Score
print "Severity:\t\t\t\t", Severity

print "\nend of script"
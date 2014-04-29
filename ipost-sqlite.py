# This script explores and demonstrates the Risk Scoring algorithms and formulas used in the 
# Department of State (DoS) iPost program.
# The examples below are based on the US Department of State Case Study found at 
#	http://www.counciloncybersecurity.org/attachments/article/46/US%20Dept%20of%20State%20Case%20Study.pdf 
# This is meant for testing and learning and should not be used for production environments.  
# Have fun and use at your own risk

# This script provides results based on the DoS formulas. The risk scores are for an individual host.  
# The ending total score could be used to aggregate a site, and enterprise score.


# The math module is need for some of the formulas.
import math
import sqlite3

# Variables
# Adjust the AV_Age and CVSS scores to see results.
AV_Age = 70
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
print "Starting iPost Risk Scoring Script"
# Connect to ipost.db
conn = sqlite3.connect('ipost.db')
c = conn.cursor()


# This route reads the CVSS list as vulnerability score to process
# it then gets the total 
print "---------------------------------------"
print "CVSS|DoS|Severity|\tCVE-ID\t\t\tTitle"

# Read all the ipost.db entries in the vuls table and sort by date
for row in c.execute('SELECT * FROM vuls ORDER BY date'):
        #print row[2]
        #print row[3]
        cveid = row[2]
        #print "CVE ID: ", cveid
	i = row[3]
	#int(i)
	Host_Vul_Score += Vul_Score(i)
	
	if Host_Vul_Score >= High: 	# Higher or equal to 7
		Severity = "High"
	elif Host_Vul_Score < High and Host_Vul_Score > Low:
		Severity = "Medium" 	# Less the 7 but higher than 3
	elif Host_Vul_Score <= Low: # less than or equal to 3
		Severity = "Low"
	print "  %d\t  %d\t\t%s\t%s\t%s " % (i,  Vul_Score(i), Severity, row[2],row[1])
	Count_Vuls += 1

# Report section

# Print to standard out.

print "iPost Results\n"
print "Number Vuls calculated:", Count_Vuls
#print "Host Vulnerability  Score:\t\t\t", Vul_Score(10)
print "Total Host Vul Score:\t%d" % Host_Vul_Score
print "Anti-Virus Score(AVS):\t", Host_AVR_Score(3.1)

print "\nEnd of script"

# Close database connection
conn.commit()
conn.close()
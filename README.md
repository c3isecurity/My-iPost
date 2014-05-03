My-iPost
========

The examples in this repository are based off the case study of the Department of State implementation of iPost.  The iPost program aggregates and presents a security view of an organization in the form of a dashboard.  

Link to paper: http://www.counciloncybersecurity.org/attachments/article/46/US%20Dept%20of%20State%20Case%20Study.pdf 

- ipost-sqlite.py - Python script with iPost Risk Scoring formulas.  The script connects to a SQLite3 database and extracts information need to perform calculations.
 
- ipost.db - Simple SQLite database that contains April Microsoft Security Advisories.  Fields include date, CVE-ID, CVSS Score, and Title.

- ipostlib.py – Contains the risk scoring formulas.

- ipost.sql - This is a simple sql script to create a database with test information.  ipost-sqlite.py reads and writes to this database.

- ipost-test.py - This a sample test script to test the functionality of the ipostlib.  

* EXAMPLE output from ipost-sqlite.py::

        $ python ipost-sqlite.py 
        
        Starting iPost Risk Scoring Script
        ---------------------------------------
        CVSS|DoS|Severity|	CVE-ID			Title
          9	  8		High	CVE-2014-1758	Microsoft Word Stack Overflow Vulnerability 
          9	  8		High	CVE-2014-1761	Word RTF Memory Corruption Vulnerability 
          9	  8		High	CVE-2014-0235	Internet Explorer Memory Corruption Vulnerability  
          9	  8		High	CVE-2014-1757	MS Office File Format Converter Vulnerability 
        iPost Results
        
        Number Vuls calculated: 4
        Total Host Vul Score:	32
        Anti-Virus Score(AVS):	18.6
        
        End of script

 

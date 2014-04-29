My-iPost
========

The examples in this repository are based off the case study of the Department of State implementation of iPost.  The iPost program aggregates and presents a security view of an organization in the form of a dash board.  

Link to paper: http://www.counciloncybersecurity.org/attachments/article/46/US%20Dept%20of%20State%20Case%20Study.pdf 

- ipost-sqlite.py - Python script with iPost Risk Scoring formulas.  The script connects to a SQLite3 database and extracts information need to perform calculations.
 
- ipost.db - Simple SQLite database that contains April Microsoft Security Advisories.  Fields include date, CVE-ID, CVSS Score, and Title.

- ipostlib.py – Contains the risk scoring formulas.




 

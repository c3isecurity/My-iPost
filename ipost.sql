/* SQL script to create and insert sample ipost.db */
/* To run the script:
/* $ sqlite3 ipost.db < ipost.sql */

CREATE TABLE results(date,hostname,score);
CREATE TABLE vuls
			(date text, title text, CVE text, cvss real, ipost real);


/* Bulk insert */
INSERT INTO "vuls" VALUES('2014-04-28','MS Office File Format Converter Vulnerability','CVE-2014-1757',9.3,0.0);
INSERT INTO "vuls" VALUES('2013-04-28','Microsoft Word Stack Overflow Vulnerability','CVE-2014-1758',9.3,0.0);
INSERT INTO "vuls" VALUES('2013-04-28','Word RTF Memory Corruption Vulnerability','CVE-2014-1761',9.3,0.0);
INSERT INTO "vuls" VALUES('2013-04-28','Internet Explorer Memory Corruption Vulnerability ','CVE-2014-0235',9.3,0.0);
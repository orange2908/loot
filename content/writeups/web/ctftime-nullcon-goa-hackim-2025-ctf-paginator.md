---
title: "Paginator - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "base64", "exec", "sqlite", "paginator", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "exec(\"CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)\");"
source:
  name: "CTFtime writeup #40001"
  url: "https://ctftime.org/writeup/40001"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40001>

---
# Paginator V1

### Application code :  
```  
exec("CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)");  
$db->exec("INSERT INTO pages (title, content) VALUES ('Flag', '" . base64_encode($FLAG) . "')");  
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
The application processes a GET parameter `p` which is expected to contain two comma-separated values (a lower and an upper bound for page IDs).

### Vulnerability  
The vulnerable part is in the SQL query construction:

`$q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";`

While `$min` is effectively sanitized by the check using intval(`$min`) (ensuring it is greater than 1), `$max` is not sanitized at all. This makes it a candidate for SQL injection.

Since only `$min` is validated (and must be greater than 1), you can inject SQL through `$max`

Payload-> `?p=2,10 OR 1=1`  
The query become `SELECT * FROM pages WHERE id >= 2 AND id <= 10 OR 1=1` 

The resultant query becomes `(id >= 2 AND id <= 10) OR 1=1`

The resultant will give Flag which will be in base64 encoded   
and after decoding

`ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow!}`

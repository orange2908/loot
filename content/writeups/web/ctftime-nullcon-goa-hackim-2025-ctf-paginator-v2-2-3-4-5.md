---
title: "Paginator v2 - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "union-select", "base64", "exec", "sqlite", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Ok, we moved the critical information to a different table now..."
source:
  name: "CTFtime writeup #39862"
  url: "https://ctftime.org/writeup/39862"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator v2
- **Author team:** bi0sblr
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39862>

---
## Question  
Ok, we moved the critical information to a different table now... Can't go wrong this time, right?

## Solution  
We were given a webpage with the source code as follows.  
[![image.png](<https://i.postimg.cc/3rSd3S31/image.png>)](<https://postimg.cc/kDSncy6R>)

The source code was given as follows-  
```php  
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
} catch(Exception $e) {  
//var_dump($e);  
}

if(isset($_GET['p']) && str_contains($_GET['p'], ",")) {  
[$min, $max] = explode(",",$_GET['p']);  
if(intval($min) <= 1 ) {  
die("This post is not accessible...");  
}  
try {  
$q = "SELECT * FROM pages WHERE id >= $min AND id <= $max";  
$result = $db->query($q);  
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {  
echo $row['title'] . " (ID=". $row['id'] . ") has content: \"" . $row['content'] . "\"  
";  
}  
}catch(Exception $e) {  
echo "Try harder!";  
}  
} else {  
echo "Try harder!";  
}  
?>  
```

Looking at the source code, assuming the table name is `flag` we do a basic union injection: `/?p=2,3 UNION SELECT * FROM flag` and we get the flag in base64 encoded format and we decode it to get the flag: `ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow_AgA1n_And_Ag41n!}`

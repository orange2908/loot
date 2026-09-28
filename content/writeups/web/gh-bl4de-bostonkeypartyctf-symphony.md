---
title: "Symphony - BostonKeyPartyCTF 2015"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "symphony", "web-exploitation", "bostonkeypartyctf", "bl4de", "ctf"]
summary: "A less than four characters number, bigger than 999?Maybe the bug is elsewhere."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/Symphony.md"
ctf:
  name: "BostonKeyPartyCTF"
  year: 2015
  challenge: "Symphony"
---

## Source

- **CTF:** BostonKeyPartyCTF 2015
- **Challenge:** Symphony
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/Symphony.md>

---
# Symphony
---

A less than four characters number, bigger than 999?Maybe the bug is elsewhere. : 25

## Source code

```
<html>
<head>
	<title>level2</title>
    <link rel='stylesheet' href='style.css' type='text/css'>
</head>
<body>

<?php
require 'flag.php';

if (isset($_GET['password'])) {
	if (is_numeric($_GET['password'])){
		if (strlen($_GET['password']) < 4){
			if ($_GET['password'] > 999)
				die('Flag: '.$flag);
			else
				print '<p class="alert">Too little</p>';
		} else
				print '<p class="alert">Too long</p>';
	} else
		print '<p class="alert">Password is not numeric</p>';
}
?>

<section class="login">
        <div class="title">
                <a href="https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/BostonKeyPartyCTF_2015/index.txt">Level 2</a>
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

We have to pass 3-digit number, but bigger than 999 :) Tricky.

But notice that is_numeric() allows exponential numbers (see )http://php.net/manual/en/function.is-numeric.php):


http://52.10.107.64:8002/?password=4e3

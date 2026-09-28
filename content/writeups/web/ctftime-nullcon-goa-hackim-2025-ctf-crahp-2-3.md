---
title: "crahp - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "crahp", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The source at http://52.59.124.14:5006/?source indicates that our goal is to find a password that is not equal to $MYPASSWORD = \"AdM1nP@assW0rd!\" yet has the same length, crc16, and crc8 checksum."
source:
  name: "CTFtime writeup #39858"
  url: "https://ctftime.org/writeup/39858"
original_source: "https://gopherhack.com/posts/nullcongoahackim2025ctf-crahp/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "crahp"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** crahp
- **Author team:** GopherHack
- **CTFtime:** <https://ctftime.org/writeup/39858>
- **Original writeup:** <https://gopherhack.com/posts/nullcongoahackim2025ctf-crahp/>

---
The source at [http://52.59.124.14:5006/?source](http://52.59.124.14:5006/?source) indicates that our goal is to find a password that is not equal to `$MYPASSWORD = "AdM1nP@assW0rd!"` yet has the same length, `crc16`, and `crc8` checksum.

```php  
$MYPASSWORD = "AdM1nP@assW0rd!";  
include "flag.php";

if(isset($_POST['password']) && strlen($MYPASSWORD) == strlen($_POST['password'])) {  
$pwhash1 = crc16($MYPASSWORD);  
$pwhash2 = crc8($MYPASSWORD);

$password = $_POST['password'];  
$pwhash3 = crc16($password);  
$pwhash4 = crc8($password);

if($MYPASSWORD == $password) {  
die("oops. Try harder!");  
}  
if($pwhash1 != $pwhash3) {  
die("Oops. Nope. Try harder!");  
}  
if($pwhash2 != $pwhash4) {  
die("OoOps. Not quite. Try harder!");  
}  
$access = true;

if($access) {  
echo "You win a flag: $FLAG";  
} else {  
echo "Denied! :-(";  
}  
} else {  
echo "Try harder!";  
}  
```

`crc8` and `crc16` produce 8-bit and 16-bit checksums respectively, which we can verify by checking `crc8("AdM1nP@assW0rd!")` and `crc16("AdM1nP@assW0rd!")`.  
```php  
$c8 = crc8("AdM1nP@assW0rd!");  
$c16 = crc16("AdM1nP@assW0rd!");  
echo $c8; // 167  
echo "\n";  
echo $c16; // 25010  
echo "\n";  
```

We should therefore expect to test around `(2 ** 8) * (2 ** 16) = 16777216` strings before we find a collision, which is brute-forceable.  
```php  
$c8 = crc8("AdM1nP@assW0rd!");  
$c16 = crc16("AdM1nP@assW0rd!");  
for ($x = 100000010000000; $x <= 100000000000000 + 1e8; $x++) {  
if (crc8(strval($x)) == $c8 && crc16(strval($x)) == $c16) {  
echo strval($x);  
echo "\n";  
}  
}  
```

Submitting `100000010130312` to the website yields the flag.

Flag: `ENO{Cr4hP_CRC_Collison_1N_P@ssw0rds!}`

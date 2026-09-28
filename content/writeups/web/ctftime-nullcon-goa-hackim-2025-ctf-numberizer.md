---
title: "numberizer - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "integer"
type: "writeup"
tags: ["web", "integer-overflow", "php", "numberizer", "integer", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Numberizer is a seemingly simple web-based CTF challenge, where users are required to submit five numbers in an HTML form such that the sum of all the numbers is negative."
source:
  name: "CTFtime writeup #40420"
  url: "https://ctftime.org/writeup/40420"
original_source: "https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/numberizer/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "numberizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** numberizer
- **Author team:** fish3r
- **CTFtime tags:** web, integer-overflow, php
- **CTFtime:** <https://ctftime.org/writeup/40420>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/numberizer/>

---
## Introduction

### Context Explanation   
*Numberizer* is a seemingly simple web-based CTF challenge, where users are required to submit **five numbers** in an HTML form such that the **sum of all the numbers is negative.** However, the challenge implements input validation and sanitization mechanisms to prevent trivial solutions like using negative numbers. 

Our goal is to bypass these controls and successfully achieve the required negative sum to retrieve the flag.

![Numberizer Home](<https://blog.hitc.at/images/nullcon/web/numberizer_home.png>)

\---

## Solution

### Analyzing the Code and Validation Mechanisms

The provided PHP source code implements a number of validation checks:

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

<html>  
<head>  
<title>Numberizer</title>  
</head>  
<body>  
<h1>Numberizer</h1>  
<form action="/" method="post">  
<label for="numbers">Give me at most 10 numbers to sum!</label>  
  
  
';  
}  
?>  
<button type="submit">Submit</button>  
</form>  


To view the source code, [click here.](https://ctftime.org/?source)  
</body>  
</html>  
```

The key authentication logic imposes validation rules through several mechanisms:

\---

### Input Validation Rules:

1\. **Input must exist:**   
Each user-provided field is confirmed to have been submitted using `isset($_POST['numbers'][$i])`.

2\. **Input character length limit (≤4):**   
The input must not exceed 4 characters in length, as verified by the `strlen($_POST['numbers'][$i])` check.

3\. **Input must be numeric:**   
Inputs must pass `is_numeric()`, ensuring they are numbers or valid numeric representations.

4\. **Negative numbers are rejected:**   
Even if a negative number is submitted and passes the above checks, the condition `if ($the_number < 0)` will exclude it from further processing.

5\. **Fixed number of inputs:**   
Only the first `$MAX_NUMS = 5` inputs are processed; additional inputs are ignored.

6\. **Summation and validation:**   
The sum of valid inputs is calculated using `array_sum()` and cast back to an integer using `intval()`. The challenge requires this sum to be negative in order to retrieve the flag:  
```php  
if ($sum < 0) {  
echo "You win a flag: $FLAG";  
}  
```

\---

### Observations and Vulnerability Analysis 

While these constraints appear robust, the **root vulnerability** lies in how PHP handles **numeric input in scientific notation** (e.g., `9e99`) and its interaction with the `intval()` function.

\---

### Behavior of `intval()` with Large Numbers

PHP's `intval()` function behaves inconsistently depending on the provided input:

\- Small and normal-sized numbers or valid numeric strings (`'42'`, `'+42'`) are converted directly to integers.  
\- Numbers in *scientific notation* (e.g., `9e99`) are treated as floating-point doubles.  
\- If these floating-point values exceed the maximum range of integers on a 64-bit system (**`9223372036854775807`** for signed integers), **integer overflow** occurs, converting the number into either the maximum or minimum range value.

To demonstrate:  
```php

---
title: "numberizer - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "numberizer", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Are you good with numbers?"
source:
  name: "CTFtime writeup #39860"
  url: "https://ctftime.org/writeup/39860"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "numberizer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** numberizer
- **Author team:** bi0sblr
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39860>

---
## Question  
Are you good with numbers?

## Solution  
Here we'd been given a webpage to submit 5 numbers, which had the source code like this-

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
```html  
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

Focus on the intval function, and by this logic, we'd have to somewhat do an overflow where the result is overall negative. So writing the first 4 numbers as `9e18` and the last number as `-9e18` and submit it, we get the flag: `ENO{INTVAL_IS_NOT_ALW4S_P0S1TiV3!}`

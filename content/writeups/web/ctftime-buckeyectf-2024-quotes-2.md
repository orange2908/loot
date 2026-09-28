---
title: "quotes - BuckeyeCTF 2024"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "javascript", "parseint", "jwt", "quotes", "buckeyectf", "buckeyectf-2024", "2024", "ctf-writeup"]
summary: "Unfortunately I did not have much time to try more challenges so this will be a short one."
source:
  name: "CTFtime writeup #39486"
  url: "https://ctftime.org/writeup/39486"
original_source: "https://www.thesecuritywind.com/post/buckeyectf-2024-quotes-web"
ctf:
  name: "BuckeyeCTF 2024"
  year: 2024
  challenge: "quotes"
---

## Metadata

- **CTF:** BuckeyeCTF 2024
- **Task:** quotes
- **Author team:** WindTeam
- **CTFtime tags:** javascript, parseint
- **CTFtime:** <https://ctftime.org/writeup/39486>
- **Original writeup:** <https://www.thesecuritywind.com/post/buckeyectf-2024-quotes-web>

---
Unfortunately I did not have much time to try more challenges so this will be a short one.  
The challenge provided the URL for the web app and its source code.  
When I accessed the URL, the web app displayed this message:  
The source code contained these files:  
After checking where the flag should be, I noticed it is the 8th quote in the 'quotes' file.  
Let's check 'app.js' to understand how to retrieve it.  
By sending a GET request to '/register' we can generate a JWT  
The web app reads the contents the 'quotes' file, and splits it into an array, where each element represents a single quote  
There are some other functionalities in the web app, but after reading the code and thinking they are irrelevant, I focused on this part  
By sending a GET request to '/quote' with the 'id' parameter which is the quote id, we might somehow retrieve the flag.   
Let's break this code  
line 66: Number() converts 'id' to a number (i).  
line 68-72: checks if 'i' is equal or bigger than FREE_TIER_QUOTE_LIMIT (which is 5. I did not add this code section).  
It means that it limits us from retrieving our flag which has id '7'.  
line 74-78: checks if 'i' is in the array bounds.  
line 80-85: performs parseInt() on 'i', and will display the corresponding quote depending on the result (5 will show the 5th quote).  
I knew that parseInt() has certain behaviors that might be related to the vulnerability. It reminded me of a challenge I already solved before, but this time it was a bit different: <https://www.thesecuritywind.com/post/uoftctf-2024-writeups#viewer-qdfm150837>  
In summary:  
We provide an 'id'.   
The 'id' is converted to a number ('i').   
If it can't convert it, the result will be 'NaN'.  
If it can, the value will stay the same.  
parseInt(i) will remove any additional characters and keep only the first characters which are numbers. For example '1b' will be converted to '1'.  
So we need to find a value which is considered a number that will stay the same after the Number() function, but will be converted to 7 after the parseInt() function.  
I tried some values and fuzzed a little bit. All of my tries resulted in quotes I permitted to read, 'null' or errors.  
Then I found a certain number representation that could work for our conditions (different representations can be found here: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number>).  
Number("7e-310") is converted to 7e-310.  
7e-310 is between 0 and 7 (7*10^-310 is a positive number close to 0).  
parseInt(7e-310) is 7.

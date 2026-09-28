---
title: "buttcoin_trading - Midnight Sun CTF 2025 Quals"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "race-condition", "burp", "buttcoin", "trading", "race", "midnight-sun-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Vulnerability: Race condition"
source:
  name: "CTFtime writeup #40261"
  url: "https://ctftime.org/writeup/40261"
ctf:
  name: "Midnight Sun CTF 2025 Quals"
  year: 2025
  challenge: "buttcoin_trading"
---

## Metadata

- **CTF:** Midnight Sun CTF 2025 Quals
- **Task:** buttcoin_trading
- **Author team:** thetimeloop
- **CTFtime:** <https://ctftime.org/writeup/40261>

---
Tools: BurpSuite

Vulnerability: Race condition

1\. Open Burp Suite, navigate to the site, log in, and then register.  
2\. Save the following data - it will be helpful:  
GET /api/tokens  
  
`json  
{  
"status":200,  
"data":[  
{"name":"fawkyoua","price":1},  
{"name":"buttcoin","price":10},  
{"name":"hehecoin","price":6},  
{"name":"flag","price":10000}  
]  
}  
`

3\. Buy one FawkYoua token and sell it.   
We observe two methods in Burp Suite: `/api/sell` and `/api/buy`.

4\. Send the `/api/sell` request to the Repeater, add the request to a group, and duplicate it.   
You should have two `/api/sell` requests in one tab.

5\. Go back to the site and buy **1000 FawkYoua tokens** for $1000.   
Then, in Burp Repeater, select **"Send group in parallel"**.  
Change the token amount to 1000 in both tabs, then send the grouped request.

6\. You should now see a **$2000 balance** and **-1000 FawkYoua tokens**.

7\. Buy **333 HeheCoin tokens** for $2000, then do the same trick in Burp Suite:   
Send two parallel sell requests with the parameters:   
`token=hehecoin&amount=333`

8\. Your balance should now be **$3998**.   
Repeat the process with ButtCoin: buy 399 tokens, send two parallel sell requests.   
You’ll reach a balance of **$7988**.   
Now buy FawkYoua tokens with all your money, and again, sell them using two parallel requests.

9\. Finally, **buy the flag**

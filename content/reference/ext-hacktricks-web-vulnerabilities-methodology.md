---
title: "Web Vulnerabilities Methodology (HackTricks)"
category: "web"
subcategory: "pentesting-web"
type: "reference"
tags: ["hacktricks", "web", "sqli", "nosql-injection", "xss", "dom-xss", "dom-clobbering", "ssrf", "ssti", "path-traversal", "deserialization", "prototype-pollution", "graphql", "request-smuggling", "cache-poisoning", "command-injection", "open-redirect", "wasm", "nodejs", "xslt"]
summary: "Every web pentest has both obvious and hidden attack surfaces."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/web-vulnerabilities-methodology.md"
license: "CC BY-NC 4.0"
---

# Web Vulnerabilities Methodology


Every web pentest has both obvious and hidden attack surfaces. This page is a checklist for confirming that the major vulnerability classes and application components have been reviewed.

## Proxies

> [!TIP]
> Modern **web applications** commonly use **intermediary proxies**, which may introduce exploitable parsing, caching, or routing behavior. These chains usually require both a proxy weakness and a compatible backend behavior.

- [ ] [**Abusing hop-by-hop headers**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/abusing-hop-by-hop-headers.md)
- [ ] [**Cache Poisoning/Cache Deception**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/cache-deception/index.html)
- [ ] [**HTTP Connection Contamination**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/http-connection-contamination.md)
- [ ] [**HTTP Connection Request Smuggling**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/http-connection-request-smuggling.md)
- [ ] [**HTTP Request Smuggling**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/http-request-smuggling)
- [ ] [**HTTP Response Smuggling / Desync**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/http-response-smuggling-desync.md)
- [ ] [**H2C Smuggling**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/h2c-smuggling.md)
- [ ] [**Server Side Inclusion/Edge Side Inclusion**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.md)
- [ ] [**Uncovering Cloudflare**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/uncovering-cloudflare.md)
- [ ] [**XSLT Server Side Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations.md)
- [ ] [**Proxy / WAF Protections Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/proxy-waf-protections-bypass.md)

## **User input**

> [!TIP]
> Most of the web applications will **allow users to input some data that will be processed later.**\
> Depending on the structure of the data the server is expecting some vulnerabilities may or may not apply.

### **Reflected Values**

If the introduced data may somehow be reflected in the response, the page might be vulnerable to several issues.

- [ ] [**Client Side Path Traversal**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/client-side-path-traversal.md)
- [ ] [**Client Side Template Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/client-side-template-injection-csti.md)
- [ ] [**Command Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/command-injection.md)
- [ ] [**CRLF**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/crlf-0d-0a.md)
- [ ] [**Dangling Markup**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/dangling-markup-html-scriptless-injection/index.html)
- [ ] [**File Inclusion/Path Traversal**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/file-inclusion/index.html)
- [ ] [**Open Redirect**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/open-redirect.md)
- [ ] [**Prototype Pollution to XSS**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/deserialization/nodejs-proto-prototype-pollution/index.html#client-side-prototype-pollution-to-xss)
- [ ] [**Server Side Inclusion/Edge Side Inclusion**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.md)
- [ ] [**Server Side Request Forgery**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/ssrf-server-side-request-forgery/index.html)
- [ ] [**Server Side Template Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/ssti-server-side-template-injection/index.html)
- [ ] [**Reverse Tab Nabbing**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/reverse-tab-nabbing.md)
- [ ] [**XSLT Server Side Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations.md)
- [ ] [**XSS**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/index.html)
- [ ] [**Abusing Service Workers**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)
- [ ] [**WASM linear-memory XSS pivots**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/wasm-linear-memory-template-overwrite-xss.md)
- [ ] [**XSSI**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xssi-cross-site-script-inclusion.md)
- [ ] [**XS-Search**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xs-search/index.html)

Some of these vulnerabilities require special conditions, while others only require reflection in a dangerous context. The following page contains polyglots for quickly testing several classes:


pocs-and-polygloths-cheatsheet/

### Modern client-side code execution pivots

When a reflection bug lands in a **modern SPA**, spend a few extra minutes on the browser-managed primitives and native bridges the page already owns:

- **Service workers**: inspect the active registration path, effective scope, and any `Service-Worker-Allowed` broadening. A low-impact HTML injection or DOM clobbering bug can become **origin-wide persistence** if the page registers a worker or feeds attacker-controlled values into `importScripts()`.<sup>[[3]](#references)</sup>
- **WASM / Emscripten modules**: fuzz length, offset, and type conversions crossing the **JS ↔ WASM** boundary. In practice, a memory bug in linear memory may let you overwrite **trusted HTML templates or state objects** and upgrade a constrained client-side bug into DOM XSS.
- **Generated clients**: minified bundles frequently disclose GraphQL persisted-query hashes, gRPC-Web method paths, `postMessage` handlers, WebSocket event names, and hidden admin routes even when the UI never exposes them.

For deeper exploitation ideas, check [Abusing Service Workers](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md), [WebAssembly linear memory corruption to DOM XSS](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/wasm-linear-memory-template-overwrite-xss.md), and [Code Review Tooling](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/code-review-tools.md).

#### File System Access API: browser-native file read/write abuse

Chromium-family browsers expose **`showOpenFilePicker()`**, **`showSaveFilePicker()`**, and **`showDirectoryPicker()`** to trusted pages in a **secure context** and after a **user gesture**.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup> If a target web app, phishing lure, or malicious dependency can convince the user to approve a directory with **read-write** access, the page can operate on the selected files **without dropping a native payload**.<sup>[[5]](#references)</sup>

Practical abuse patterns:

- Enumerate the selected directory with **`for await (const [name, handle] of dirHandle.entries())`** or `values()`, recurse into subdirectories, and filter by extension/MIME.
- Read file contents with **`handle.getFile()`** and `text()`, `arrayBuffer()`, or `stream()`, then exfiltrate through `fetch`, XHR, or `sendBeacon`.
- Overwrite files with **`createWritable()`** after a `queryPermission()` / `requestPermission({mode: 'readwrite'})` flow. This is the primitive that enables **browser-native ransomware** or destructive tampering.<sup>[[5]](#references)</sup><sup>[[9]](#references)</sup>
- Check **IndexedDB** for serialized `FileSystemFileHandle` / `FileSystemDirectoryHandle` objects because legitimate apps often persist handles and later reuse them after `queryPermission()` / `requestPermission()` checks.
- Review the UX around picker prompts: fake **AI upscalers**, editors, and media tools can plausibly ask for an input file first and an **output folder** second, making the write warning look legitimate.<sup>[[5]](#references)</sup>

Important boundaries:

- This is **not arbitrary disk access**. Chromium blocks or constrains many sensitive locations, but user-chosen media folders can still be high-value targets. In recent public research, **Pictures**, **Videos**, and Android **`DCIM`** roots were practical lure targets.<sup>[[5]](#references)</sup>
- A normal web page still cannot become native malware: global keylogging, arbitrary desktop screenshots, and OS persistence remain outside the browser sandbox unless another vulnerability is present. The real primitive is **user-approved local file read/write**.
- Browser support is concentrated in **Chromium**. Chrome shipped the API on desktop in **Chrome 86** and extended it to **Android/WebView in Chrome 132**; Firefox and Safari do not expose the same picker methods.<sup>[[8]](#references)</sup>

### **Search functionalities**

If the functionality may be used to search some kind of data inside the backend, maybe you can (ab)use it to search arbitrary data.

- [ ] [**File Inclusion/Path Traversal**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/file-inclusion/index.html)
- [ ] [**NoSQL Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/nosql-injection.md)
- [ ] [**LDAP Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/ldap-injection.md)
- [ ] [**ReDoS**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/regular-expression-denial-of-service-redos.md)
- [ ] [**SQL Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/sql-injection/index.html)
- [ ] [**ORM Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/orm-injection.md)
- [ ] [**RSQL Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/rsql-injection.md)
- [ ] [**XPATH Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xpath-injection.md)

### **Forms, WebSockets and PostMsgs**

When a WebSocket sends messages or a form lets users perform actions, request-forgery and message-trust vulnerabilities may arise.

- [ ] [**Cross Site Request Forgery**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/csrf-cross-site-request-forgery.md)
- [ ] [**Cross-site WebSocket hijacking (CSWSH)**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/websocket-attacks.md)
- [ ] [**Phone Number Injections**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/phone-number-injections.md)
- [ ] [**PostMessage Vulnerabilities**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/postmessage-vulnerabilities/index.html)

#### Cross-site WebSocket hijacking & localhost abuse

WebSocket upgrades automatically forward cookies and do not block `ws://127.0.0.1`, so **any web origin can drive desktop IPC endpoints** that skip `Origin` validation. When you spot a launcher exposing a JSON-RPC-like API through a local agent:<sup>[[1]](#references)</sup>

- Observe emitted frames to clone the `type`/`name`/`args` tuples required by each method.
- Bruteforce the listening port directly from the browser (Chromium will handle ~16k failed upgrades) until a loopback socket answers with the protocol banner—Firefox tends to crash quickly under the same load.
- Chain a *create → privileged action* pair: e.g., invoke a `create*` method that returns a GUID and immediately call the corresponding `*Launch*` method with attacker-controlled payloads.

If you can pass arbitrary JVM flags (such as `AdditionalJavaArguments`), force an error with `-XX:MaxMetaspaceSize=<tiny>` and attach `-XX:OnOutOfMemoryError="<cmd>"` to run OS commands without touching application logic. See [WebSocket attacks](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/websocket-attacks.md#localhost-websocket-abuse--browser-port-discovery) for a walk-through.

### Installers / setup wizards / recovery leftovers

First-run installers and recovery endpoints are often forgotten in production. If a live application still exposes paths such as `/install/`, `/setup/`, `/init/`, `/admin/install`, `/setup/setupadministrator.action`, or readable config files such as `/config/database.php`, treat them as **high-value takeover primitives** instead of low-value information leaks.<sup>[[2]](#references)</sup>

Checks to perform:

- Fuzz for installer and reconfiguration paths with `ffuf`, `dirsearch`, or wordlists containing `install`, `setup`, `wizard`, `init`, `upgrade`, `db`, `config`, and `admin`.
- Open the wizard and determine whether it still accepts **database / SMTP / admin** parameters after deployment, or whether a server-side `setupComplete` / lock file can be flipped or bypassed.
- If the installer accepts arbitrary DB settings, test whether the application will connect to an **attacker-controlled external DB** and bootstrap its schema there. This can yield **admin creation**, backend **state disclosure**, or application **DoS** if the remote DB later disappears.
- After any successful reinitialization, revisit old authenticated tabs and test whether **pre-existing sessions remain valid** even after the backend DB/configuration is restored. PHP apps often keep session state outside MySQL, so restoring the DB may not revoke attacker sessions.
- Review incident-response paths: password reset, admin creation, DB restore, installer rerun, maintenance exit. If none of them rotate session IDs or invalidate server-side session stores, keep testing for persistent dashboard access.

Operational notes:

- Outbound connectivity matters: if the web tier can reach arbitrary MySQL hosts, SSRF-style egress restrictions are missing and installer abuse becomes much easier.
- Sudden `500` errors immediately after setup changes can indicate the application is still pointing to attacker-supplied infrastructure.
- Framework/app-specific examples exist (for example Confluence setup reactivation admin creation), but the reusable technique is **production reinstallation / reinitialization abuse**.

### **HTTP Headers**

Depending on the HTTP headers given by the web server some vulnerabilities might be present.

- [ ] [**Clickjacking**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/clickjacking.md)
- [ ] [**Iframe Traps / Click Isolation**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/iframe-traps.md)
- [ ] [**Content Security Policy bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/content-security-policy-csp-bypass/index.html)
- [ ] [**Cookies Hacking**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/hacking-with-cookies/index.html)
- [ ] [**CORS - Misconfigurations & Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/cors-bypass.md)

### **Bypasses**

There are several specific functionalities where some workarounds might be useful to bypass them

- [ ] [**2FA/OTP Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/2fa-bypass.md)
- [ ] [**Bypass Payment Process**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/bypass-payment-process.md)
- [ ] [**Captcha Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/captcha-bypass.md)
- [ ] [**Account Takeover Playbooks**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/account-takeover.md)
- [ ] [**Login Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/login-bypass/index.html)
- [ ] [**Race Condition**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/race-condition.md)
- [ ] [**Rate Limit Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/rate-limit-bypass.md)
- [ ] [**Reset Forgotten Password Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/reset-password.md)
- [ ] [**Registration Vulnerabilities**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/registration-vulnerabilities.md)

### **Structured objects / Specific functionalities**

Some functionalities will require the **data to be structured in a very specific format** (like a language serialized object or XML). Therefore, it's easier to identify if the application might be vulnerable as it needs to be processing that kind of data.\
Some **specific functionalities** may be also vulnerable if a **specific format of the input is used** (like Email Header Injections).

- [ ] [**Deserialization**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/deserialization/index.html)
- [ ] [**Email Header Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/email-injections.md)
- [ ] [**JWT Vulnerabilities**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/hacking-jwt-json-web-tokens.md)
- [ ] [**JSON / XML / YAML Hacking**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/json-xml-yaml-hacking.md)
- [ ] [**XML External Entity**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xxe-xee-xml-external-entity.md)
- [ ] [**GraphQL Attacks**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/graphql.md)
- [ ] [**gRPC-Web Attacks**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/grpc-web-pentest.md)
- [ ] [**SOAP/JAX-WS ThreadLocal Auth Bypass**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/soap-jax-ws-threadlocal-auth-bypass.md)

### Files

Functionalities that allow uploading files might be vulnerable to several issues.\
Functionalities that generate files including user input might execute unexpected code.\
Users that open files uploaded by users or automatically generated including user input might be compromised.

- [ ] [**File Upload**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/file-upload/index.html)
- [ ] [**Formula Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/formula-csv-doc-latex-ghostscript-injection.md)
- [ ] [**PDF Injection**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/pdf-injection.md)
- [ ] [**Server Side XSS**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.md)

### **External Identity Management**

- [ ] [**OAUTH to Account takeover**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/oauth-to-account-takeover.md)
- [ ] [**SAML Attacks**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/saml-attacks/index.html)

#### Passkeys / WebAuthn handoffs

Passkeys are **origin-bound**, so the usual bug is not "steal the secret" but **abuse the workflow around the ceremony**:<sup>[[4]](#references)</sup>

- Try **registration/login confusion**: start a WebAuthn ceremony in one account or browser, then complete it from another session and check whether the signed challenge is still bound to the correct user, RP, and browser state.
- Treat **QR, device-code, wallet, and cross-device approvals** exactly like password-reset tokens: check replay, stale approvals, session swapping, and whether a completed ceremony authenticates a browser different from the one that initiated it.
- If you already have **XSS or strong clickjacking** on the relying-party origin, test whether you can drive extension/browser UI to approve a legitimate passkey login for the victim without exposing the credential material.

See [Account Takeover](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/account-takeover.md#qr--cross-device-login-flows) and [Clickjacking](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/clickjacking.md#browser-extensions-dom-based-autofill-clickjacking) for concrete attack patterns.

### **Other Helpful Vulnerabilities**

These vulnerabilities might help to exploit other vulnerabilities.

- [ ] [**Domain/Subdomain takeover**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/domain-subdomain-takeover.md)
- [ ] [**IDOR**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/idor.md)
- [ ] [**Mass Assignment (CWE-915)**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/mass-assignment-cwe-915.md)
- [ ] [**Parameter Pollution**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/parameter-pollution.md)
- [ ] [**Unicode Normalization vulnerability**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/unicode-injection/index.html)

### **Web Servers & Middleware**

Misconfigurations in the edge stack often unlock more impactful bugs in the application layer.

- [ ] [**Apache**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/apache.md)
- [ ] [**Nginx**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/nginx.md)
- [ ] [**IIS**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/iis-internet-information-services.md)
- [ ] [**Tomcat**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/tomcat)
- [ ] [**Spring Actuators**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/spring-actuators.md)
- [ ] [**PUT Method / WebDAV**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/put-method-webdav.md)
- [ ] [**Special HTTP Headers**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/special-http-headers.md)
- [ ] [**WSGI Deployment**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/wsgi.md)
- [ ] [**Werkzeug Debug Exposure**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/werkzeug.md)

### **Application Frameworks & Stacks**

Framework-specific primitives frequently expose gadgets, dangerous defaults, or framework-owned endpoints.

> [!TIP]
> Always download the **front-end bundles and `*.map` files** before assuming a route or action is unreachable. Modern builds often leak **Next.js Server Actions**, GraphQL persisted-query hashes, tRPC router names, gRPC-Web paths, feature flags, and role strings that are perfect for low-privilege replay and authorization testing.

- [ ] [**Django**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/django.md)
- [ ] [**Flask**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/flask.md)
- [ ] [**NodeJS / Express**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/nodejs-express.md)
- [ ] [**Angular**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/angular.md)
- [ ] [**Vue / Nuxt**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/vuejs.md)
- [ ] [**Next.js**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/nextjs.md)
- [ ] [**Laravel**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/laravel.md)
- [ ] [**Symfony**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/symphony.md)

Quick grep targets inside downloaded bundles:
```bash
rg -n 'sourceMappingURL|createServerReference|Next-Action|queryHash|persistedQuery|grpc-web|protobuf|new WebSocket\(|postMessage\(' ./static ./dist ./_next ./assets 2>/dev/null
```

Useful follow-up reading: [Code Review Tooling](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/code-review-tools.md) and [Next.js](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/nextjs.md#nextjs-server-actions-enumeration-hash-to-function-name-via-source-maps).

### **CMS, SaaS & Managed Platforms**

High-surface products often ship with known exploits, weak plugins, or privileged admin endpoints.

- [ ] [**WordPress**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/wordpress.md)
- [ ] [**Joomla**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/joomla.md)
- [ ] [**Drupal**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/drupal)
- [ ] [**Moodle**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/moodle.md)
- [ ] [**Prestashop**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/prestashop.md)
- [ ] [**Atlassian Jira**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/jira.md)
- [ ] [**Grafana**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/grafana.md)
- [ ] [**Rocket.Chat**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/rocket-chat.md)
- [ ] [**Zabbix**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/zabbix.md)
- [ ] [**Microsoft SharePoint**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/microsoft-sharepoint.md)
- [ ] [**Sitecore**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/sitecore)

### **APIs, Buckets & Integrations**

Server-side helpers and third-party integrations can expose file parsing or storage-layer weaknesses.

- [ ] [**Web API Pentesting**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/web-api-pentesting.md)
- [ ] [**Storage Buckets & Firebase**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/buckets)
- [ ] [**Imagemagick Security**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/imagemagick-security.md)
- [ ] [**Artifactory & Package Registries**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/artifactory-hacking-guide.md)
- [ ] [**Code Review Tooling**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/network-services-pentesting/pentesting-web/code-review-tools.md)

### **Supply Chain & Identifier Abuse**

Attacks that target build pipelines or predictable identifiers can become the initial foothold before exploiting traditional bugs.

- [ ] [**Dependency Confusion**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/dependency-confusion.md)
- [ ] [**Timing Attacks**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/timing-attacks.md)
- [ ] [**UUID Insecurities**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/uuid-insecurities.md)

### **Web3, Extensions & Tooling**

Modern applications extend into browsers, wallets, and automation pipelines—keep these vectors in scope.

- [ ] [**dApps / Decentralized Applications**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/dapps-DecentralizedApplications.md)
- [ ] [**Browser Extension Pentesting**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/browser-extension-pentesting-methodology)
- [ ] [**wfuzz Web Fuzzing**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/web-tool-wfuzz.md)

## References

- [1] [When WebSockets Lead to RCE in CurseForge](https://elliott.diy/blog/curseforge/)
- [2] [I Accidentally Logged as Admin Into a Threat Actor Website](https://potato.id/en/posts/i-accidentally-logged-into-threat-actor-website)
- [3] [Hijacking service workers via DOM Clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
- [4] [Security advisory: Passkey Dialog Clickjacking Issue](https://support.dashlane.com/hc/en-us/articles/28598967624722-Security-advisory-Passkey-Dialog-Clickjacking-Issue)
- [5] [Browser-Only Ransomware: From LLM Hallucinations to a Practical Attack Technique](https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/)
- [6] [File System Access specification](https://wicg.github.io/file-system-access/)
- [7] [The File System Access API: simplifying access to local files](https://developer.chrome.com/docs/capabilities/web-apis/file-system-access)
- [8] [Chrome 132 release notes](https://developer.chrome.com/release-notes/132)
- [9] [RøB: Ransomware over Modern Web Browsers](https://www.usenix.org/conference/usenixsecurity23/presentation/oz)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/web-vulnerabilities-methodology.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.

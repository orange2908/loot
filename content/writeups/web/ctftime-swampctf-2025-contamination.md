---
title: "Contamination - SwampCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "http-parameter-pollution", "reverse-proxy", "contamination", "swampctf", "swampctf-2025", "2025", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40165"
  url: "https://ctftime.org/writeup/40165"
original_source: "https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/ctf-2025/swamp-ctf-2025"
ctf:
  name: "SwampCTF 2025"
  year: 2025
  challenge: "Contamination"
---

## Metadata

- **CTF:** SwampCTF 2025
- **Task:** Contamination
- **Author team:** H4ck_th3_Wh47
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40165>
- **Original writeup:** <https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/ctf-2025/swamp-ctf-2025>

---
For the complete documentation index, see [llms.txt](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/llms.txt). This page is also available as [Markdown](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/ctf-2025/swamp-ctf-2025.md).

**Droppin' some fresh writeups from Swamp CTF 2025!** 🐊💥 Teamed up with my crew, **sh3lldon3** , and we dove deep into the swampy madness. Let’s get straight into the hacks and hijinks—no fluff, just flags. 🚀

## Web

### Contamination

![](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/~gitbook/image?url=https%3A%2F%2F1820343777-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FZsWL2bWgKP7UWM2c8hEJ%252Fuploads%252FDEd5UUpYpEAvoAcPFYXB%252FScreenshot%25202025-04-21%2520074745.png%3Falt%3Dmedia%26token%3Db76e85d2-f176-4709-9a62-ac4bf944c398&width=768&dpr=3&quality=100&sign=cb77b2c2887928752b2f621a0d536882&sv=3)

Analysing the source code provided, we get to know that 

  1. Application has reverse proxy build using Ruby and has endpoint /api?action='getInfo'.

  2. Backend is build using Python which has two endpoints "/api?action='getFlag'" and "/api?action='getInfo'".

  3. We have to send POST requests with some json data.


![](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/~gitbook/image?url=https%3A%2F%2F1820343777-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FZsWL2bWgKP7UWM2c8hEJ%252Fuploads%252FXJqGBx7f6IQLqzLjsKGf%252FScreenshot%25202025-04-21%2520080546.png%3Falt%3Dmedia%26token%3Df0a5208e-6670-457a-b17e-92b65c486811&width=768&dpr=3&quality=100&sign=79f293a819706fd9e3eea7fd8632b6c8&sv=3)

Reverse Proxy Server

![](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/~gitbook/image?url=https%3A%2F%2F1820343777-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FZsWL2bWgKP7UWM2c8hEJ%252Fuploads%252F04cwPQemLjR2BNP7q8iC%252FScreenshot%25202025-04-21%2520075415.png%3Falt%3Dmedia%26token%3D74ba8f9f-7115-4044-9306-71cb273a4adb&width=768&dpr=3&quality=100&sign=36946fcecb13d76a10d21291a4f71d17&sv=3)

Backend code

Now, in order to get flag we have to:

  1. Hit the "/api?action='getFlag'" endpoint at backend, so somehow pass action='getFlag' as Reverse Proxy accepts only action='getInfo' and gives error otherwise.

  2. Cause error in parsing json data so that environment variables containing flag get exposed.


### Exploit

Since the backend and reverse proxy is build using different languages, so there is difference in the handling parameters. Hence, we can do **Parameter Pollution.**

This payload is able to bypass because whenever there are duplicate variables then Ruby will consider the last one while Python considers the first one.

Again, due to difference in the method of parsing JSON data, there are characters that are treated differently in two languages.

Now, "\q" is not a valid special character. 

  1. When Ruby encounters it, then it simply consider it as two characters '\' and 'q' and therefore, pass it to the backend and gives no error.

  2. Since, it is not a valid escape sequence, therefore it will cause parsing error in backend (JSONcode error by Python).


In this way, We successfully expose the environment variables and get the Flag.

[PreviousAbout Us](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47)[NextTexas Instruments Security Week 2025](https://h4ck-th3-wh47.gitbook.io/h4ck_th3_wh47/ctf-2025/texas-instruments-security-week-2025)

Last updated 1 year ago

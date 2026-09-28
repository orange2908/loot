---
title: "CheckPoint CSA writeups"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lwe", "sqli", "base64", "lattice", "cryptography"]
summary: "crypto writeup for \"challenge set\" from CheckPoint CSA - techniques: lwe, sqli, base64, lattice, cryptography."
source:
  name: "Dvd848/CTFs"
  url: "https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/README.md"
ctf:
  name: "CheckPoint CSA"
  year: 2018
---

## Source

- **CTF:** CheckPoint CSA 2018
- **Repository:** [Dvd848/CTFs](https://github.com/Dvd848/CTFs)
- **File:** <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/README.md>

---
<h1 align=center dir=RTL style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אתגר </span><span
lang=EN-US dir=LTR style='font-family:"Arial",sans-serif'>Check Point</span><span
dir=RTL></span><span lang=EN-US style='font-family:"Arial",sans-serif'><span
dir=RTL></span> </span><span lang=HE style='font-family:"Arial",sans-serif'>–
2018</span></h1>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=HE style='font-family:"Arial",sans-serif'>מאת
</span><span lang=EN-US dir=LTR>Dvd848</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>הקדמה</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>חברת צ'ק פוינט פרסמה
סדרה של אתגרים במסגרת מסע הפרסום של &quot;</span><span lang=HE
style='font-family:"Arial",sans-serif'>האקדמיה הראשונה לסייבר מבית צ’ק פוינט&quot;.
האתגרים הגיעו ממספר תחומים, ביניהם </span><span lang=EN-US dir=LTR>Web</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, </span><span lang=EN-US dir=LTR>Reversing</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>, </span><span
lang=EN-US dir=LTR>Programming</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>, </span><span
lang=EN-US dir=LTR>Networking</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ו-</span><span
lang=EN-US dir=LTR>Logic</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 1 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>Return
of the Robots</span><span dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Web</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, 10 נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
Return of the Robots
Robots are cool, but trust me: their access should be limited!
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לפסקה צורף קישור
לאתר עם טקסט על היסטוריית הרובוטיקה:</span></p>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img width=285 height=228
id="Picture 1" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image001.jpg"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מה שהטקסט נמנע
מלהזכיר הוא כמובן שבעולם ה-</span><span lang=EN-US dir=LTR>Web</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, המונח </span><span lang=EN-US dir=LTR>Robots</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> מיד מקפיץ אסוציאציה של הקובץ</span><span dir=LTR></span><span
lang=EN-US dir=LTR><span dir=LTR></span>  <span class=MsoHyperlink><a
href="https://en.wikipedia.org/wiki/Robots_exclusion_standard">robots.txt</a></span></span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, או בשמו הרשמי יותר &quot;פרוטוקול אי הכללת רובוטים&quot;. </span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>זהו פרוטוקול שמאפשר
לבעלי אתרים לבקש מבוטים של מנועי חיפוש שסורקים את האינטרנט להימנע מלכלול דפים
מסוימים של האתר בתוצאות מנוע החיפוש. כאשר מנוע החיפוש מגיע לאתר, הוא אמור לבדוק
את התוכן של הקובץ </span><span lang=EN-US dir=LTR>robots.txt</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> בתיקיית השורש של האתר. אם קובץ כזה קיים, מנוע החיפוש לא אמור
לאנדקס כתובות שמצוינות בקובץ (כמובן שזוהי מוסכמה ושום דבר לא מונע ממנוע חיפוש
לאנדקס מה שהוא רוצה, כל עוד יש לו גישה לדף).</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כלומר, אם קיימים
דפים שמנהל האתר לא מעוניין לחשוף באופן פומבי, הוא יכול לכלול אותם בקובץ הזה. אולם,
זה מייצר בעיה אחרת, מעצם העובדה שהקובץ הזה חייב להיות פומבי: הוא כולל רשימה
ממוקדת ונגישה של כל הדפים שאין להם עניין ציבורי.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אם ננסה לקרוא את
הקובץ מהשרת של האתגר, נמצא את התוכן הבא:</span></p>

```
User-agent: *
Disallow: /secret_login.html
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ניגש לדף ונראה:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=305
height=106 id="Picture 2"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image002.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>קוד המקור של הדף
נראה כך:</span></p>

```html
 <body>
  <script type="text/javascript">
  function r(n) {
    for (var r=0, o=0, e="", t=0; t<n.length; t++)  
       n[t].toLowerCase() != n[t] && (r+=1), 8 == ++o 
        ? (e += String.fromCharCode(r), r=0, o=0) : r <<= 1; alert(e) 
  }
 
  function auth(n) {
    if ("SzMzcFQjM1IwYjB0JDB1dA==" == btoa(n))
    var a = "pVPmwMHevTZoIGjevOQdfpiLwEQwxYINxOBVNyFGhUPimVXUhdMWqrzmjAXIzTpvlZFXgFvisSEnblcPnLfZUBUPnZPtXwQOpnUWfyAUhbANrqOKySBErmflnHfWLVAXvOSKpCqwaWWvLrskwFNxWTYTnCAKteTGjYIxsKpXwGuDNWXLyMTVphBuryEVylptvSDaxrMnmgPSokwcfDIVhNsutQCLppSVjYiQFLNWtCVeRRTZkRQEsMzDhBPMrSycaHGWMDpY";
    else a = "sRnDjXnrzAZVoxXnjSWLUoyWtgQpzziflCuxapkGjYEcrUADyMZlgunEaXLqYncWlHGpIVMvltZxveoE"; 
     r(a)
  }
  </script>
  <h1>No Robots Allowed</h1>
  <label for="userPassword">Password: </label>
  <input id="userPassword" type="password" required>
  <input type="submit" value="Submit" onclick = "auth(userPassword.value);">
 <body>
</html>
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אפשר לראות
שפונקציית </span><span lang=EN-US dir=LTR>auth</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> משווה את
הסיסמא שהתקבלה מהמשתמש אל ערך קבוע (מקודד ב-</span><span lang=EN-US dir=LTR>Base64</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, כפי שאפשר לראות בין השאר מהשימוש בפונקציית </span><span
lang=EN-US dir=LTR>btoa</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> שמקודדת מחרוזת ב-</span><span
lang=EN-US dir=LTR>Base64</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>). נשתמש בפונקציית </span><span
lang=EN-US dir=LTR>atob</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> לפענוח הקידוד
ונקבל את הסיסמא:</span></p>

```javascript
>> atob("SzMzcFQjM1IwYjB0JDB1dA==")
"K33pT#3R0b0t$0ut"
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בתגובה, הדף יקפיץ
את הדגל:</span></p>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=181
height=117 id="Picture 3"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image003.jpg"></span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-size:13.0pt;line-height:
107%;font-family:"Times New Roman",serif;color:#2F5496'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 2 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=en-IL dir=LTR>Diego's
Gallery</span><span dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Web</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, 20 נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
Diego's Gallery
Recently I've been developing a platform to manage my cat's photos and keep my flag.txt safe. Please check out my beta
To avoid security loop holes such as SQL injections I developed my own scheme.
  
Every line in my DB look's like this:
 
> START|||username|||password|||role|||END
 
So for example:
 
> START|||diego|||catnip|||admin|||END
> START|||joe|||1234567|||user|||END
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר מכיל טופס
התחברות פשוט:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=318
height=121 id="Picture 4"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image004.jpg"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כמו ב-</span><span
lang=EN-US dir=LTR>SQL Injection</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> בסיסי, נרצה להכניס
קלט באחד השדות שישפיע על התחביר במקום רק על הנתונים.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למשל, אם במקום הסיסמא,
נכניס:</span></p>

<p class=MsoNormal><b><span lang=EN-US style='font-family:"Courier New";
color:#538135'>some_password|||admin|||END</span></b></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התחביר הסופי יהיה:</span></p>

<p class=MsoNormal><span lang=en-IL style='font-family:"Courier New"'>START|||</span><span
lang=EN-US style='font-family:"Courier New"'>some_</span><span lang=en-IL
style='font-family:"Courier New"'>username|||</span><b><span lang=EN-US
style='font-family:"Courier New";color:#538135'>some_password|||admin|||END</span></b><span
lang=en-IL style='font-family:"Courier New"'>|||</span><span lang=EN-US
style='font-family:"Courier New"'>user</span><span lang=en-IL style='font-family:
"Courier New"'>|||END</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>וכך נצליח לגרום
לקוד לחשוב שהמשתמש שלנו הוא מנהל, ונקבל גישה לדף הניהול:</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=465
height=212 id="Picture 5"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image005.jpg"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כפתורי הניהול לא
עושים שום דבר מעניין, אך שימו לב לשורת הכתובות:</span></p>

<p class=MsoNormal><span lang=EN-US>http://35.194.63.219/csa_2018/diegos_gallery/_trpyyxfhoszl/admin-panel/index.php?view=log.txt</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקובץ </span><span
lang=EN-US dir=LTR>index.php</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מקבל כפרמטר שם של
קובץ ומציג את התוכן שלו. </span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מה יקרה אם במקום </span><span
lang=EN-US dir=LTR>log.txt</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> נבקש קובץ אחר,
למשל </span><span lang=EN-US dir=LTR>flag.txt</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>?</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=602
height=254 id="Picture 6"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image006.jpg"></span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 3 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>Careful
Steps</span><span dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Programming</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, 20 נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
This is a bunch of archives we've found and we believe a secret flag is somehow hidden inside them.

We're pretty sure the information we're looking for is in the comments section of each file.

Can you step carefully between the files and get the flag?

Good luck!
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>קובץ הארכיון מכיל 2000
קבצים, החל מ-</span><span lang=EN-US dir=LTR style='font-family:"Courier New"'>unzipme.0</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> ועד ל-</span><span lang=EN-US dir=LTR style='font-family:"Courier New"'>unzipme.1999</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>שימוש בפקודת </span><span
lang=EN-US dir=LTR style='font-family:"Courier New"'>file</span><span dir=RTL></span><span
lang=EN-US style='font-family:"Arial",sans-serif'><span dir=RTL></span> </span><span
lang=HE style='font-family:"Arial",sans-serif'>מראה שמדובר באוסף של קבצי </span><span
lang=EN-US dir=LTR>RAR</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ו-</span><span
lang=EN-US dir=LTR>ZIP</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=580
height=112 id="Picture 7"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image007.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התוכן לא נראה
מעניין כל כך, מה אבל ההוראות שלחו אותנו להערות (שני הפורמטים תומכים בהוספת
הערות לקובץ הארכיון). </span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אפשר לראות הערה של
קובץ </span><span lang=EN-US dir=LTR>ZIP</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> באמצעות
פקודת </span><span lang=EN-US dir=LTR style='font-family:"Courier New"'>unzip
-z</span><span dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=601
height=190 id="Picture 9"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image008.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נראה שכל הערה כוללת
אות, ומספר. ננסה להתייחס אל המספר בתור הוראות לאיזה קובץ לקפוץ בצעד הבא, ואל
האות בתור חלק מהדגל.</span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לשם כך נוכל להשתמש
בסקריפט הבא:</span></p>

```python
import os
import zipfile
import rarfile
import sys
 
 
print ("Reading comments...")
listOfFiles = sorted(os.listdir('archives'))
comments = {}
for file_name in listOfFiles:
    try:
        with zipfile.ZipFile('archives/' + file_name) as zf:
            comment = zf.comment.decode("utf-8")
    except zipfile.BadZipFile:
        try:
            with rarfile.RarFile('archives/' + file_name) as rf:
                comment = rf.comment
        except e:
            raise e
    #print ("{}\t{}".format(file_name, comment))
    comments[int(file_name.replace("unzipme.", ""))] = comment.rstrip()
 
print ("Following trail...")
current_index = 0
new_offset = 0
while True:
    current_index = current_index + new_offset
    #print ("Trying to access {}".format(current_index + new_offset))
   
    current = comments[current_index]
    char, new_offset = current.split(",")
    new_offset = int(new_offset)
    #print ("{}, {}".format(char, new_offset))
    sys.stdout.write(char)
 
    if new_offset == 0:
        break
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>החלק הראשון קורא את
כל ההערות, והחלק השני עוקב אחרי הצעדים בהערות ומדפיס את התווים המתאימים.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אם נריץ את הסקריפט,
נקבל:</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=78
id="Picture 12"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image009.jpg"></span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 4 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>Ping
Pong</span><span dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Networking</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, 25 נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
I bet you're not fast enough to defeat me. I'm at:
nc 35.157.111.68 10140
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נתחבר לשרת:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=569
height=181 id="Picture 13"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image010.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>השרת מבקש שנשלח לו
מספר אקראי כלשהי. כאשר אנו עושים זאת, הוא מבקש מספר אחר. אם התגובה איטית מדי,
השרת סוגר את החיבור.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כמובן שאנחנו לא רוצים
לשלוח תשובות ידנית ולכן נכתוב סקריפט שעושה זאת עבורנו:</span></p>

```python
import socket
import time
import re


s = socket.socket()         

reg = re.compile('^.+: ([\d]+)\n$')

try:
    port = 10140              

    s.connect(('35.157.111.68', port))

    start_time = time.time()
    print (s.recv(9)) #Read the "Welcome!\n"
    while True:
        msg = (s.recv(1024)).decode("utf-8")
        print (msg)
        match = reg.match(msg)
        if match:
            num = match.group(1)
            print (num)
            s.send(str.encode(num + "\n"))
        else:
            break
    print("--- %s seconds ---" % (time.time() - start_time))
    
            
except:
    raise
finally:
    s.close()    
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הסקריפט משתמש
בביטוי רגולרי כדי לחלץ את המספר ואז שולח אותו חזרה אל השרת:</span></p>

```python
re.compile('^.+:([\d]+)\n$')
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הביטוי הזה מתאים
לשורה שמתחילה בכל תו (</span><span lang=HE style='font-family:"Courier New"'>.</span><span
lang=HE style='font-family:"Arial",sans-serif'>) שמופיע פעם אחת או יותר (</span><span
lang=HE style='font-family:"Courier New"'>+</span><span lang=HE
style='font-family:"Arial",sans-serif'>) כאשר לאחר מכן צריכות להופיע נקודתיים (</span><span
lang=HE style='font-family:"Courier New"'>:</span><span lang=HE
style='font-family:"Arial",sans-serif'>) ואז רווח ( ), ספרה אחת או יותר (</span><a
name="_Hlk518599576"><span dir=LTR></span><span lang=EN-US dir=LTR
style='font-family:"Courier New"'><span dir=LTR></span>[\d]+</span></a><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>) וירידת שורה (</span><span dir=LTR></span><span lang=EN-US
dir=LTR style='font-family:"Courier New"'><span dir=LTR></span>\n</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>). הסימנים &quot;</span><span lang=HE style='font-family:"Courier New"'>^</span><span
lang=HE style='font-family:"Arial",sans-serif'>&quot; ו&quot;</span><span
lang=HE style='font-family:"Courier New"'>$</span><span lang=HE
style='font-family:"Arial",sans-serif'>&quot; מסמלים תחילת וסוף שורה, והסוגריים
מסביב ל-&quot;</span><span dir=LTR></span><span lang=EN-US dir=LTR
style='font-family:"Courier New"'><span dir=LTR></span>[\d]+</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>&quot; מסמנים שזהו הביטוי שנרצה לחלץ.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>את הביטוי אנחנו
מקמפלים מראש כדי להשיג ריצה יעילה יותר.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נריץ את הסקריפט
ונקבל:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=296
height=233 id="Picture 14"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image012.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בדיעבד, מכיוון
שאנחנו יודעים שהשרת תמיד מחזיר את אותה תשובה, היה אפשר לוותר על הביטוי הרגולרי
ולחסוך כמה שניות (במחיר של קריאות וגמישות) על ידי דילוג על &quot;</span><span
lang=EN-US dir=LTR>Good, the next is: </span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>&quot; וקפיצה
ישירה אל המספר שצריך להחזיר (במילים אחרות, נראה שהמספר תמיד מתחיל באותו </span><span
lang=EN-US dir=LTR>offset</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מתחילת השורה).</span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר </span><span dir=LTR></span><span
lang=EN-US dir=LTR><span dir=LTR></span>5</span><span dir=RTL></span><span
lang=EN-US style='font-family:"Times New Roman",serif'><span dir=RTL></span> </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>Protocol</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Networking</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, </span><span dir=LTR></span><span lang=EN-US dir=LTR><span
dir=LTR></span>30</span><span dir=RTL></span><span lang=HE style='font-family:
"Times New Roman",serif'><span dir=RTL></span> נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
Hi there!

We need to extract secret data from a special file server.

We don't have much details about this server, but we did manage to intercept traffic containing communication with the server.

We also know that this secret file's path is: /usr/7Op_sECreT.txt

You can find the sniff file here.

Please tell us what the secret is!

Good luck!
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקובץ שמתקבל הוא
קובץ </span><span lang=EN-US dir=LTR>pcap</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> שמשמש
להצגת תעבורת רשת וניתן לפתיחה באמצעות תוכנת </span><span lang=EN-US dir=LTR>WireShark</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=602
height=354 id="Picture 8"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image013.jpg"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מעבר זריז על
ההודעות השונות ועיון ב-</span><span lang=EN-US dir=LTR>payload</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> מגלה הודעה מעניינת:</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=593 height=75
id="Picture 10"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image014.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ה-</span><span
lang=EN-US dir=LTR>HELLO</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> קופץ מיד לעין.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ניתן לעקוב אחרי כל
ההודעות של החיבור הזה באמצעות קליק ימני ובחירה ב-</span><span lang=EN-US
dir=LTR>Follow TCP Stream</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=195
id="Picture 11"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image015.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נראה שמדובר
בפרוטוקול בסיסי שבו המשתמש מבקש קובץ ומקבל אותו מקודד. ה-</span><span
lang=EN-US dir=LTR>XOR</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> במהלך ההתקשרות
מרמז שכנראה צריך להפעיל פעולת </span><span lang=EN-US dir=LTR>XOR</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> באמצעות המפתח שמתקבל מהשרת על תוכן הקובץ כדי לקבל את ה-</span><span
lang=EN-US dir=LTR>plaintext</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ננסה לחקות את
הפרוטוקול בעצמנו</span><span dir=LTR></span><span lang=HE dir=LTR><span
dir=LTR></span> </span><span dir=RTL></span><span lang=HE style='font-family:
"Arial",sans-serif'><span dir=RTL></span> (הקוד מצורף בשלמותו בעמוד הבא) ונקבל
את התוצאה הבאה:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span dir=LTR></span><span lang=HE dir=LTR><span dir=LTR></span> </span><span
lang=en-IL dir=LTR><img border=0 width=560 height=145 id="Picture 16"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image016.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>את הקוד אפשר לכתוב
בצורה הרבה יותר קצרה, אבל זאת הזדמנות טובה לראות </span><span lang=EN-US
dir=LTR>Context Manager</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> בפעולה על מנת
לשלוט בצורה נקייה בפתיחה ובסגירה של ה-</span><span lang=EN-US dir=LTR>Socket</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מחלקת </span><span
lang=EN-US dir=LTR>Protocol</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מממשת את פרוטוקול
התקשורת עם השרת (עם כמה הנחות בפונקציית </span><span lang=EN-US dir=LTR>recv</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>). פונקציית </span><span lang=EN-US dir=LTR>decode_msg</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> מפענחת את ההודעה על ידי מעבר על ההודעה בחלקים (כל חלק הוא שישה
בתים – תחילית של </span><span dir=LTR></span><span lang=EN-US dir=LTR><span
dir=LTR></span>0x</span><span dir=RTL></span><span lang=HE style='font-family:
"Arial",sans-serif'><span dir=RTL></span> וארבעה בתים של מידע) וביצוע </span><span
lang=EN-US dir=LTR>XOR</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> עם המפתח שהתקבל
בשלב הקודם.</span></p>

```python
import socket, re

class Protocol(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.msg_id = 0
        self.recv_reg = 
           re.compile('^(?P<id>\d+) (?P<len>\d+) (?P<payload>.+)$')

    def __enter__(self):
        self.socket = socket.socket()
        self.socket.connect((self.ip, self.port))
        return self

    def __exit__(self, *args):
        self.socket.close()

    def log(self, msg):
        print(msg)

    def send(self, msg):
        self.log(">> {}".format(msg))
        self.msg_id += 1
        full_msg = "{} {} {}\n".format(self.msg_id, len(msg), msg)
        self.socket.send(full_msg.encode('UTF-8'))

    def recv(self):
        msg = self.socket.recv(1024)
        match = self.recv_reg.match(msg.decode('UTF-8'))
        if match:
            assert(int(match.group("id")) == self.msg_id)
            assert(int(match.group("len")) == len(match.group("payload")))
            self.log("<< {}".format(match.group("payload")))
            return match.group("payload")
        raise Exception("Unexpected format: {}".format(msg))

    def decode_msg(self, xor, msg):
        chunk_len = len("0x") + len(xor)
        frame = bytearray()
        for i in range(0, len(msg), chunk_len):
            s = msg[i:i + chunk_len]
            chunk_val = int(s, 16)
            after_xor = (chunk_val ^ int(xor, 16))
            for b in (after_xor.to_bytes(len(xor) // 2,
                                       byteorder='big',
                                       signed=True) ):
                frame.append(b)
        return frame
        
with Protocol('35.157.111.68', 20001) as p:
    msg = p.recv()
    assert(msg == "Welcome!")
    p.send("HELLO")
    msg = p.recv()
    assert(msg == "HELLO")
    p.send("XOR")
    xor_val = p.recv()
    p.send("/usr/7Op_sECreT.txt")
    encrypted_file = p.recv()
    print ("Decoded Message:")
    print (p.decode_msg(xor_val, encrypted_file))
```

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 6 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>PNG++</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Logic</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, </span><span dir=LTR></span><span lang=EN-US dir=LTR><span
dir=LTR></span>30</span><span dir=RTL></span><span lang=HE style='font-family:
"Times New Roman",serif'><span dir=RTL></span> נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
This image was encrypted using a custom cipher.
We managed to get most of its code here
Unfortunately, while moving things around, someone spilled coffee all over key_transformator.py.
Can you help us decrypt the image?
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקוד להצפנת התמונה
הוא:</span></p>

```python
import key_transformator
import random
import string

key_length = 4

def generate_initial_key():
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(4))

def xor(s1, s2):
    res = [chr(0)]*key_length
    for i in range(len(res)):
        q = ord(s1[i])
        d = ord(s2[i])
        k = q ^ d
        res[i] = chr(k)
    res = ''.join(res)
    return res

def add_padding(img):
    l = key_length - len(img)%key_length
    img += chr(l)*l
    return img

with open('flag.png', 'rb') as f:
    img = f.read()

img = add_padding(img)
key = generate_initial_key()

enc_data = ''
for i in range(0, len(img), key_length):
    enc = xor(img[i:i+key_length], key)
    key = key_transformator.transform(key)
    enc_data += enc

with open('encrypted.png', 'wb') as f:
    f.write(enc_data)
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כאשר אנחנו רואים
שראשית מוגרל מפתח של ארבעה בתים, ולאחר מכן הקוד עובר על תוכן התמונה ומבצע </span><span
lang=EN-US dir=LTR>XOR</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> עם המפתח, מבצע
מניפולציה על המפתח וחוזר על הפעולה.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התמונה עצמה נקראת </span><span
lang=EN-US dir=LTR>encrypted.png</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> וכאשר מנסים לפתוח
אותה, מקבלים שגיאה שהקובץ אינו בפורמט המתאים.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למזלנו, פורמט </span><span
lang=EN-US dir=LTR>PNG</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מכיל </span><span
lang=EN-US dir=LTR>Header</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ידוע מראש,
שבאמצעותו ניתן לנחש מהו מפתח ההצפנה.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לפי </span><span
class=MsoHyperlink><span lang=EN-US><a
href="http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html"><span lang=HE
style='font-family:"Arial",sans-serif'>האתר הזה</span></a></span></span><span
lang=HE style='font-family:"Arial",sans-serif'>:</span></p>

<div align=right>

<table class=MsoTableGrid dir=rtl border=1 cellspacing=0 cellpadding=0
 style='border-collapse:collapse;border:none'>
 <tr>
  <td width=601 valign=top style='width:450.8pt;border:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p dir=LTR><span lang=en-IL>A PNG file consists of a PNG <em>signature</em>
  followed by a series of <em>chunks</em>. <br>
  </span><span lang=EN-US>…</span><span lang=EN-US> </span></p>
  <p dir=LTR><span lang=en-IL>The first eight bytes of a PNG file always
  contain the following (decimal) values: </span></p>
  <pre dir=LTR><span lang=en-IL>   137 80 78 71 13 10 26 10</span></pre>
  <p class=MsoNormal dir=RTL style='margin-bottom:0cm;margin-bottom:.0001pt;
  text-align:right;line-height:normal;direction:rtl;unicode-bidi:embed'><span
  lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
  </td>
 </tr>
</table>

</div>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span dir=RTL></span><span lang=en-IL style='font-family:"Arial",sans-serif'><span
dir=RTL></span> </span><span lang=HE style='font-family:"Arial",sans-serif'>נבדוק
את הקובץ שקיבלנו בעורך </span><span lang=EN-US dir=LTR>Hex</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=472 height=84
id="Picture 17"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image019.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>על מנת לקבל את
המפתח המקורי, נבצע </span><span lang=EN-US dir=LTR>XOR</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> שוב מול
הערך שאמור להיות שם לפי התקן:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=485
height=163 id="Picture 18"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image020.png"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נראה שהמפתח הוא </span><span
lang=EN-US dir=LTR>NLET</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> (</span><span
dir=LTR></span><span lang=EN-US dir=LTR><span dir=LTR></span>0x4e 0x4c 0x45
0x54</span><span dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>). אנחנו רואים גם שב-</span><span lang=EN-US dir=LTR>Chunk</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> הבא, המפתח הפך להיות </span><span dir=LTR></span><span
lang=EN-US dir=LTR><span dir=LTR></span>“0x4f 0x4d 0x46 0x55”</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, כלומר קידמנו כל ערך ב-1. </span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נבצע מספר שינויים
קלים בקוד ההצפנה על מנת לבצע פענוח:</span></p>

```python
# (Using original functions)

def transform(key):
    return "".join(map(lambda x: chr((ord(x)+1) % 256), key))

with open('encrypted.png', 'rb') as f:
    img = f.read()

key = "NLET"

dec_data = ''
for i in range(0, len(img), key_length):
    dec = xor(img[i:i+key_length], key)
    key = transform(key)
    dec_data += dec

with open('flag.png', 'wb') as f:
    f.write(dec_data)
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>והתוצאה:</span></p>

<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=513
height=351 id="Picture 19"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image022.png"></span></p>

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 7 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>Test
my Patience</span><span dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (קטגוריית </span><span lang=EN-US dir=LTR>Surprise</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span>, </span><span dir=LTR></span><span lang=EN-US dir=LTR><span
dir=LTR></span>50</span><span dir=RTL></span><span lang=HE style='font-family:
"Times New Roman",serif'><span dir=RTL></span> נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
Hi there,

We found This executable on the local watchmaker's computer.

It is rumored that somehow the watchmaker was the only person who succeeded to crack it.

Think you're as good as the watchmaker?

Note: This file is not malicious in any way
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>קודם כל, תמיד מרגיע
לראות הצהרה בסגנון &quot;קובץ זה אינו נוזקה&quot;. נשמע אמין. זה זמן טוב להזכיר
שבמסגרת אתגרים יוצא לא פעם להוריד קבצי הרצה, כלים, ספריות וכד' ומומלץ מאוד
להפעיל הכל בתוך מכונה וירטואלית, על כל צרה שלא תבוא.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נריץ את הקובץ ונראה:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=357
height=110 id="Picture 21"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image023.png"></span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מדובר במשחק
ניחושים, התוכנה חושבת על מספר כלשהו ואנחנו צריכים לנחש מהו. אחרי מספר ניחושים
(ארוכים, קצרים, שליליים, לא חוקיים וכד') אפשר לראות שלעיתים לוקח לתוכנה יחסית
הרבה זמן להחזיר תשובה. יחד עם השם של האתגר, נראה שמדובר ב-</span><span
lang=EN-US dir=LTR>Timing Attack</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הסבר קצר: כאשר
התוכנה בודקת את הניחוש, היא משווה אותו מול המספר הנבחר. אם הספרה הראשונה של
הניחוש שווה לספרה הראשונה של התשובה הנכונה, ההשוואה תקח קצת יותר זמן. כמובן
שבאתגרים מהסוג הזה, לעיתים מוסיפים השהייה מלאכותית כל מנת להקל על המדידה.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נכתוב סקריפט שינסה
את כל הספרות 0-9, יבדוק מתי התוצאה חזרה הכי לאט, וימשיך לספרה הבאה.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נריץ את הסקריפט
(הקוד המלא בדף הבא) ונקבל:</span></p>

<p class=MsoNormal align=right dir=RTL style='text-align:left;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=422
height=189 id="Picture 23"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/images/image024.jpg"></span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקוד:</span></p>

```python
from subprocess import Popen, PIPE
import time

p = Popen(['tmp.exe'], stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)
print p.stdout.readline()
print p.stdout.readline()

answer = ""

searching = True
while searching:
    time_arr = []
    for i in xrange(10):
        start = time.time()
        p.stdin.write(answer + str(i))
        p.stdin.write("\n")
        line = p.stdout.readline()
        end = time.time()
        print line.rstrip()
        if not "Wrong" in line:
            answer += str(i)
            searching = False
            break
        time_arr.append(end-start)
    print time_arr
    if searching:
        answer += str(time_arr.index(max(time_arr)))
        print "WIP answer: {}".format(answer)
print answer
```

<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>

<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 8 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span dir=LTR></span><span
lang=EN-US dir=LTR><span dir=LTR></span>0120343536</span><span dir=RTL></span><span
lang=HE style='font-family:"Times New Roman",serif'><span dir=RTL></span>
(קטגוריית </span><span lang=EN-US dir=LTR>Logic</span><span dir=RTL></span><span
lang=HE style='font-family:"Times New Roman",serif'><span dir=RTL></span>, </span><span
dir=LTR></span><span lang=EN-US dir=LTR><span dir=LTR></span>60</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> נקודות)</span></h2>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>

```
flag{IAAAA_$AYP_%CP_C_WIIX_BYWAOX}
Not so fast...
They say the only place where flags come before work is the dictionary, ours is no different

Note: flag letters are all capital
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>המילון מכיל רשימה
של כמעט 40,000 מילים. ננסה להשתמש במילון על מנת לפצח את הדגל.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ראשית נמיין את
המילים במילון לפי אורך (אפשר להתעלם ממילים באורך גדול מ-6 כי אין כאלה בדגל):</span></p>

```python
msg = "IAAAA_$AYP_%CP_C_WIIX_BYWAOX"

d = defaultdict(list)
with open("dictionary.txt") as f:
    for line in f:
        line = line.rstrip()
        l = len(line)
        if l <= 6:
            d[l].append(line)
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כעת נתחיל לחפש
מילים במילון שמתאימות לתבנית של הדגל.</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>המילה הראשונה שכדאי
לתקוף היא </span><span lang=EN-US dir=LTR>IAAAA</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>, מכיוון
שנדיר למצוא מילים עם 4 אותיות זהות רצופות.</span></p>

```python
for w in d[5]:
    if (w[1] == w[2] == w[3] == w[4]):
        print (w)
# CEEEE, OHHHH
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נהמר על </span><span
lang=EN-US dir=LTR>OHHHH</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>, כי נדיר לראות </span><span
lang=EN-US dir=LTR>CEEEE</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> בתחילת משפט.</span></p>

<div align=right>

<table class=MsoTableGrid dir=rtl border=1 cellspacing=0 cellpadding=0
 style='border-collapse:collapse;border:none'>
 <tr>
  <td width=601 valign=top style='width:450.8pt;border:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US style='font-family:"Courier New"'>IAAAA_$AYP_%CP_C_WIIX_BYWAOX</span></p>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US style='font-family:"Courier New"'>OHHHH ?H??
  ??? ? ?OO? ???H??</span></p>
  </td>
 </tr>
</table>

</div>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>המילה הבאה שכדאי
לתקוף היא </span><span lang=EN-US dir=LTR>WIIX</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>

```python
for w in d[4]:
    if (w[1] == w[2] and w[0] != w[3] and w[2] == 'O'):
        print (w)
# POOR
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מצאנו רק מילה אחת
שמתאימה:</span></p>

<p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
normal'><span lang=EN-US style='font-family:"Courier New"'>IAAAA_$AYP_%CP_C_WIIX_BYWAOX</span></p>

<p class=MsoNormal><span lang=EN-US style='font-family:"Courier New"'>OHHHH ?H??
??? ? POOR ??PH?R</span></p>

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נחפש את </span><span
lang=EN-US dir=LTR>BYWAOX</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>

```python
for w in d[6]:
    if (w[2] == 'P' and w[3] == 'H' and w[5] == 'R'):
        print (w)
# CIPHER
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>

---

*Truncated at 1200 lines. Full text: <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_CheckPoint_CSA/README.md>*

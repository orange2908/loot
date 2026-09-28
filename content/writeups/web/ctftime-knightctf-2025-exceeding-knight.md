---
title: "Exceeding Knight - KnightCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "informationleakage", "base64", "mysql", "laravel", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "The site appeared as follows:"
source:
  name: "CTFtime writeup #39829"
  url: "https://ctftime.org/writeup/39829"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Exceeding Knight"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Exceeding Knight
- **Author team:** QnQSec
- **CTFtime tags:** web, informationleakage
- **CTFtime:** <https://ctftime.org/writeup/39829>

---
### Challenge Description

![description](<https://i.imgur.com/NqClM8B.png>)

### Initial Analysis

The site appeared as follows:

![site](<https://i.imgur.com/lZnQt3v.png>)

There was nothing interesting here, so I began reading the attached files. The first thing I did was read the `web.php` file located in the `routes` folder. I found the following routes:

```php  
Route::get('/calculator', [CalculatorController::class, 'index']);  
Route::post('/calculator', [CalculatorController::class, 'calculate']); // Handle form submission

Route::get('/convert', [UnitConversionController::class, 'index']);  
Route::post('/convert', [UnitConversionController::class, 'convert']);

Route::get('/character-count', [StringManipulationController::class, 'characterCountIndex']);  
Route::post('/character-count', [StringManipulationController::class, 'characterCount']);

Route::get('/reverse-string', [StringManipulationController::class, 'reverseStringIndex']);  
Route::post('/reverse-string', [StringManipulationController::class, 'reverseString']);

Route::post('/profile', [ProfileController::class, 'index']);  
Route::get('/profile/error', [ProfileController::class, 'triggerError']); // Error-triggering route

Route::get('/', function () {  
return view('welcome');  
```

Next, I read the `.env` file and found something interesting:

```  
APP_NAME=Laravel  
APP_ENV=local  
APP_KEY=base64:KnrD53eO60BJBvCVGNlBuOqktUCAsTuod34OelLJjPQ=  
APP_DEBUG=true  
APP_URL=http://localhost  
MAX_CALC_LIMIT=100000000000000000

LOG_CHANNEL=stack  
LOG_DEPRECATIONS_CHANNEL=null  
LOG_LEVEL=debug

DB_CONNECTION=mysql  
DB_HOST=127.0.0.1  
DB_PORT=3306  
DB_DATABASE=laravel  
DB_USERNAME=root  
DB_PASSWORD=

BROADCAST_DRIVER=log  
CACHE_DRIVER=file  
FILESYSTEM_DISK=local  
QUEUE_CONNECTION=sync  
SESSION_DRIVER=file  
SESSION_LIFETIME=120  
FLAG=KCTF{i_am_not_flag}  
```

Aside from the `APP_KEY` and `FLAG`, as we can see, Laravel's debug mode is enabled. When debug mode is enabled in Laravel, any error that occurs will trigger a detailed error page. This page includes:

\- Error Message: A clear description of the error.  
\- Stack Trace: A full trace of the error, showing the file paths and lines of code where the issue occurred.  
\- Environment Details: Information about the environment, including variables, configurations, and request headers.  
\- Sensitive Data Exposure: Potential exposure of .env values, database credentials, API keys, and other sensitive information.

So, I thought about exploiting the enabled debug mode in Laravel to capture the flag. The only thing I needed was a way to trigger any kind of error. I found this method in the `/calculator` route, to be more precise, in the `CalculatorController.php` file under the `Http/Controllers` folder. As we can see, by entering a number greater than `MAX_CALC_LIMIT=100000000000000000` an exception is thrown:

```  
validate([  
'num1' => 'required|numeric',  
'num2' => 'required|numeric',  
'operation' => 'required|in:add,sub,mul,div',  
]);

$num1 = $request->input('num1');  
$num2 = $request->input('num2');  
$operation = $request->input('operation');  
$limit = env('MAX_CALC_LIMIT', 100000);

if ($num1 > $limit || $num2 > $limit) {  
throw new \Exception("You have hit the calculation limit set in the .env file.");  
}

$result = match ($operation) {  
'add' => $num1 + $num2,  
'sub' => $num1 - $num2,  
'mul' => $num1 * $num2,  
'div' => $num2 != 0 ? $num1 / $num2 : throw new \Exception("Division by zero is not allowed."),  
};

return view('calculator', ['result' => $result]);  
}  
}

```

### Exploit

So, all I had to do was enter `1000000000000000000` (just adding a simple zero) in the `num1` parameter to trigger the exception. This caused the detailed error page to return, which contained the flag inside it:

![flag](<https://i.imgur.com/bSnaJ5w.png>)

### Flag

```  
KCTF{_Y0U_sH0UlD_re4D_m0r3_Cod3_}  
```

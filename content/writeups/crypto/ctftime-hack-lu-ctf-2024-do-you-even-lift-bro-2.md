---
title: "Do you even lift bro? - Hack.lu CTF 2024"
category: "crypto"
subcategory: "image"
type: "writeup"
tags: ["crypto", "xor", "lsb", "even", "lift", "bro", "image", "hack-lu-ctf", "hack-lu-ctf-2024", "2024", "ctf-writeup"]
summary: "This challenge is the basic rev challenge of the CTF."
source:
  name: "CTFtime writeup #39582"
  url: "https://ctftime.org/writeup/39582"
original_source: "https://github.com/Gungilr/WriteUps/blob/main/Hacklu/Do%20You%20Even%20Lift.md"
ctf:
  name: "Hack.lu CTF 2024"
  year: 2024
  challenge: "Do you even lift bro?"
---

## Metadata

- **CTF:** Hack.lu CTF 2024
- **Task:** Do you even lift bro?
- **Author team:** Batman's Kitchen
- **CTFtime:** <https://ctftime.org/writeup/39582>
- **Original writeup:** <https://github.com/Gungilr/WriteUps/blob/main/Hacklu/Do%20You%20Even%20Lift.md>

---
![alt text](<https://github.com/Gungilr/WriteUps/blob/main/Hacklu/Pasted%20image%2020241023223734.png>)

This challenge is the basic rev challenge of the CTF. The downloaded file is a llvm file in the typically format of a encrypted key that you have to unencrypt by reversing engineering the algorithm.

Here's the full program for those of you curious:  
```llvm  
@do_you = dso_local global i16 -8531, align 2  
@__const.lift_bro.valid = private unnamed_addr constant [23 x i8] c"\D3\06\07\BBk\A2\FD<`\C99\1A\A8\16I2\A55\D2\AC@\D6)", align 16  
@__const.lift_bro.input = private unnamed_addr constant [24 x i8] c"flag{fakefakefakefake!}\00", align 16  
@.str = private unnamed_addr constant [22 x i8] c"Invalid input length\0A\00", align 1  
@.str.1 = private unnamed_addr constant [11 x i8] c"\0ACorrect!\0A\00", align 1  
@.str.2 = private unnamed_addr constant [13 x i8] c"\0AIncorrect!\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable  
define dso_local zeroext i8 @even() #0 {  
%1 = alloca i8, align 1; 8bit integer  
%2 = load i16, ptr @do_you, align 2  
%3 = zext i16 %2 to i32 ; extends 0s to %2 so that it becomes an 32 bit   
%4 = and i32 %3, 1 ;   
%5 = trunc i32 %4 to i8  
store i8 %5, ptr %1, align 1  
%6 = load i16, ptr @do_you, align 2  
%7 = zext i16 %6 to i32  
%8 = ashr i32 %7, 1  
%9 = sext i32 %8 to i64  
%10 = load i8, ptr %1, align 1  
%11 = zext i8 %10 to i64  
%12 = sub nsw i64 0, %11  
%13 = and i64 %12, 46080  
%14 = xor i64 %9, %13  
%15 = trunc i64 %14 to i16  
store i16 %15, ptr @do_you, align 2  
%16 = load i8, ptr %1, align 1  
ret i8 %16  
}

; Function Attrs: noinline nounwind optnone uwtable  
define dso_local i32 @lift_bro() #0 {  
%1 = alloca i32, align 4 ; allocates space for a 32 bit integer  
%2 = alloca [23 x i8], align 16  
%3 = alloca [24 x i8], align 16  
%4 = alloca i32, align 4  
%5 = alloca ptr, align 8  
%6 = alloca i64, align 8  
%7 = alloca i32, align 4  
%8 = alloca i8, align 1  
%9 = alloca i32, align 4  
%10 = alloca i8, align 1  
store i32 0, ptr %1, align 4  
call void @llvm.memcpy.p0.p0.i64(ptr align 16 %2, ptr align 16 @__const.lift_bro.valid, i64 23, i1 false)  
call void @llvm.memcpy.p0.p0.i64(ptr align 16 %3, ptr align 16 @__const.lift_bro.input, i64 24, i1 false)  
%11 = getelementptr inbounds [24 x i8], ptr %3, i64 0, i64 0 ; 24 for str len  
%12 = call i64 @strlen(ptr noundef %11) #5  
%13 = trunc i64 %12 to i32  
store i32 %13, ptr %4, align 4  
%14 = load i32, ptr %4, align 4  
%15 = sext i32 %14 to i64   
%16 = icmp ne i64 %15, 23  
br i1 %16, label %17, label %19 ; checks length of input as 23

17: ; preds = %0  
%18 = call i32 (ptr, ...) @printf(ptr noundef @.str)  
store i32 1, ptr %1, align 4  
br label %72

19: ; preds = %0  
%20 = load i32, ptr %4, align 4   
%21 = zext i32 %20 to i64 ; 23 extended   
%22 = call ptr @llvm.stacksave.p0() ; saves the state to the stack  
store ptr %22, ptr %5, align 8  
%23 = alloca i8, i64 %21, align 16 ; same value allocated to a 8 bit int  
store i64 %21, ptr %6, align 8  
store i32 0, ptr %7, align 4  
br label %24

24: ; preds = %57, %19  
%25 = load i32, ptr %7, align 4  
%26 = load i32, ptr %4, align 4  
%27 = icmp slt i32 %25, %26 ; compares len of input to 0  
br i1 %27, label %28, label %60

28: ; preds = %24  
store i8 0, ptr %8, align 1  
store i32 0, ptr %9, align 4  
br label %29

29: ; preds = %40, %28  
%30 = load i32, ptr %9, align 4  
%31 = icmp slt i32 %30, 8  
br i1 %31, label %32, label %43

32: ; preds = %29  
%33 = load i8, ptr %8, align 1  
%34 = zext i8 %33 to i32  
%35 = shl i32 %34, 1  
%36 = call zeroext i8 @even()  
%37 = zext i8 %36 to i32  
%38 = or i32 %35, %37  
%39 = trunc i32 %38 to i8  
store i8 %39, ptr %8, align 1  
br label %40

40: ; preds = %32  
%41 = load i32, ptr %9, align 4  
%42 = add nsw i32 %41, 1  
store i32 %42, ptr %9, align 4  
br label %29, !llvm.loop !6

43: ; preds = %29  
%44 = load i32, ptr %7, align 4  
%45 = sext i32 %44 to i64  
%46 = getelementptr inbounds [24 x i8], ptr %3, i64 0, i64 %45  
%47 = load i8, ptr %46, align 1  
%48 = sext i8 %47 to i32  
%49 = load i8, ptr %8, align 1  
%50 = zext i8 %49 to i32  
%51 = xor i32 %48, %50  
%52 = trunc i32 %51 to i8  
store i8 %52, ptr %10, align 1  
%53 = load i8, ptr %10, align 1  
%54 = load i32, ptr %7, align 4  
%55 = sext i32 %54 to i64  
%56 = getelementptr inbounds i8, ptr %23, i64 %55  
store i8 %53, ptr %56, align 1  
br label %57

57: ; preds = %43  
%58 = load i32, ptr %7, align 4  
%59 = add nsw i32 %58, 1  
store i32 %59, ptr %7, align 4  
br label %24, !llvm.loop !8

60: ; preds = %24  
%61 = getelementptr inbounds [23 x i8], ptr %2, i64 0, i64 0 ; get array point  
%62 = load i32, ptr %4, align 4  
%63 = sext i32 %62 to i64  
%64 = call i32 @memcmp(ptr noundef %23, ptr noundef %61, i64 noundef %63) #5 ; comparing ext  
%65 = icmp eq i32 %64, 0 ; if string length = string length ig  
br i1 %65, label %66, label %68

66: ; preds = %60  
%67 = call i32 (ptr, ...) @printf(ptr noundef @.str.1)  
br label %70

68: ; preds = %60  
%69 = call i32 (ptr, ...) @printf(ptr noundef @.str.2)  
br label %70

70: ; preds = %68, %66  
store i32 0, ptr %1, align 4  
%71 = load ptr, ptr %5, align 8  
call void @llvm.stackrestore.p0(ptr %71)  
br label %72

72: ; preds = %70, %17  
%73 = load i32, ptr %1, align 4  
ret i32 %73  
}  
```

Let's break down this program by it's own separated function starting with the `@lift_bro` function:

```  
%1 = alloca i32, align 4 ; allocates space for a 32 bit integer  
%2 = alloca [23 x i8], align 16  
%3 = alloca [24 x i8], align 16  
%4 = alloca i32, align 4  
%5 = alloca ptr, align 8  
%6 = alloca i64, align 8  
%7 = alloca i32, align 4  
%8 = alloca i8, align 1  
%9 = alloca i32, align 4  
%10 = alloca i8, align 1  
```

For the first section of code here there is space being allocated for variables. The notable ones being `%2`, and `%3` which are arrays that likely handle the user input, and encrypted flag.

```  
store i32 0, ptr %1, align 4  
call void @llvm.memcpy.p0.p0.i64(ptr align 16 %2, ptr align 16 @__const.lift_bro.valid, i64 23, i1 false)  
call void @llvm.memcpy.p0.p0.i64(ptr align 16 %3, ptr align 16 @__const.lift_bro.input, i64 24, i1 false)  
%11 = getelementptr inbounds [24 x i8], ptr %3, i64 0, i64 0 ; 24 for str len  
%12 = call i64 @strlen(ptr noundef %11) #5  
%13 = trunc i64 %12 to i32  
store i32 %13, ptr %4, align 4  
%14 = load i32, ptr %4, align 4  
%15 = sext i32 %14 to i64   
%16 = icmp ne i64 %15, 23  
br i1 %16, label %17, label %19 ; checks length of input as 23  
```

Here a couple things happen:  
1\. In the memcpy functions the encrypted flag and user input are copied into the storage at `%2` and `%3` respectively  
2\. `%11` and `%12` are then used to find the length of user input  
3\. Finally it compares the length against 23

If length isn't 23 the code sends us to an error message here:  
```  
17: ; preds = %0  
%18 = call i32 (ptr, ...) @printf(ptr noundef @.str)  
store i32 1, ptr %1, align 4  
br label %72  
```

Afterwards we enter a set of loops in 

```  
24: ; preds = %57, %19  
%25 = load i32, ptr %7, align 4  
%26 = load i32, ptr %4, align 4  
%27 = icmp slt i32 %25, %26 ; compares len of input to counter  
br i1 %27, label %28, label %60 ; condtional of the for loop

28: ; preds = %24  
store i8 0, ptr %8, align 1  
store i32 0, ptr %9, align 4  
br label %29

29: ; preds = %40, %28  
%30 = load i32, ptr %9, align 4  
%31 = icmp slt i32 %30, 8  
br i1 %31, label %32, label %43 ; condtional of the for loop  
  
.....

40: ; preds = %32  
%41 = load i32, ptr %9, align 4  
%42 = add nsw i32 %41, 1 ; increments the counter  
store i32 %42, ptr %9, align 4  
br label %29, !llvm.loop !6 ; loops the code  
  
.....  
57: ; preds = %43  
%58 = load i32, ptr %7, align 4  
%59 = add nsw i32 %58, 1 ; increments counter  
store i32 %59, ptr %7, align 4  
br label %24, !llvm.loop !8 ; loops the code

```

This common structure is used for for loops which ultimately looks something like this:

``` python  
for i in len(user_input):  
for i in range(8):  
do_stuff()   
```

The missing section i excluded that completes the loop is `%32` which really only calls the even function and does some bit manipulation:

```  
32: ; preds = %29  
%33 = load i8, ptr %8, align 1  
%34 = zext i8 %33 to i32  
%35 = shl i32 %34, 1  
%36 = call zeroext i8 @even()  
%37 = zext i8 %36 to i32  
%38 = or i32 %35, %37  
%39 = trunc i32 %38 to i8  
store i8 %39, ptr %8, align 1  
br label %40  
```

Combining with the previous section the encryption looks a bit like:

```python  
for i in range(len(input_str)):  
# Generate 8 bits for each character  
byte = 0  
for _ in range(8):  
byte = (byte << 1) | even()  
```

Section `%43` show how the byte that is created in the previous section is used to xor against each character of the input string

```  
43: ; preds = %29  
%44 = load i32, ptr %7, align 4  
%45 = sext i32 %44 to i64  
%46 = getelementptr inbounds [24 x i8], ptr %3, i64 0, i64 %45  
%47 = load i8, ptr %46, align 1  
%48 = sext i8 %47 to i32  
%49 = load i8, ptr %8, align 1  
%50 = zext i8 %49 to i32  
%51 = xor i32 %48, %50  
%52 = trunc i32 %51 to i8  
store i8 %52, ptr %10, align 1  
%53 = load i8, ptr %10, align 1  
%54 = load i32, ptr %7, align 4  
%55 = sext i32 %54 to i64  
%56 = getelementptr inbounds i8, ptr %23, i64 %55  
store i8 %53, ptr %56, align 1  
br label %57  
```

```python   
for i in range(len(input_str)):  
# Generate 8 bits for each character  
byte = 0  
for _ in range(8):  
byte = (byte << 1) | even()  
  
# XOR with input character  
processed = (ord(input_str[i]) ^ byte) & 0xFF  
result.append(processed)  
```

The last part we need to get the flag is the `@even` function at the top of script:  
```  
define dso_local zeroext i8 @even() #0 {  
%1 = alloca i8, align 1;   
%2 = load i16, ptr @do_you, align 2  
%3 = zext i16 %2 to i32 ;   
%4 = and i32 %3, 1 ;   
%5 = trunc i32 %4 to i8  
store i8 %5, ptr %1, align 1  
%6 = load i16, ptr @do_you, align 2  
%7 = zext i16 %6 to i32  
%8 = ashr i32 %7, 1  
%9 = sext i32 %8 to i64  
%10 = load i8, ptr %1, align 1  
%11 = zext i8 %10 to i64  
%12 = sub nsw i64 0, %11  
%13 = and i64 %12, 46080  
%14 = xor i64 %9, %13  
%15 = trunc i64 %14 to i16  
store i16 %15, ptr @do_you, align 2  
%16 = load i8, ptr %1, align 1  
ret i8 %16  
}  
```

Breaking this function down, it's performing some bitwise operations to check if the current number is even or odd and then generating a new number for next time and storing it globally.

``` python  
def even():  
global do_you  
result = do_you & 1 # Get least significant bit  
shifted = (do_you >> 1) # Shift right by 1  
mask = -(result) & 46080 # Create mask based on result  
do_you = (shifted ^ mask) & 0xFFFF # XOR and keep 16 bits  
return result & 0xFF # Return 8-bit value  
```

With this there enough information to reconstruct the original flag as the encrypted flag is just the XORed bytes of the original if we regenerate each byte and XOR it against the encrypted flag we'll get the original text.

``` python  
def even():  
global do_you  
result = do_you & 1 # Get least significant bit  
shifted = (do_you >> 1) # Shift right by 1  
mask = -(result) & 46080 # Create mask based on result  
do_you = (shifted ^ mask) & 0xFFFF # XOR and keep 16 bits  
return result & 0xFF # Return 8-bit value

def lift_bro():  
# The original valid bytes from the constant  
valid = [0xD3, 0x06, 0x07, 0xBB, 0x6B, 0xA2, 0xFD, 0x3C,  
0x60, 0xC9, 0x39, 0x1A, 0xA8, 0x16, 0x49, 0x32,  
0xA5, 0x35, 0xD2, 0xAC, 0x40, 0xD6, 0x29]  
  
# Process each character  
result = ""  
for i in range(23):  
# Generate 8 bits for each character  
byte = 0  
for _ in range(8):  
byte = (byte << 1) | even()  
  
# XOR with input character  
result += (chr(byte ^ valid[i]))  
processed = (ord(valid[i]) ^ byte) & 0xFF  
result.append(processed)  
print(result)  
return 0

# Initialize global variable  
do_you = -8531 & 0xFFFF # Keep as 16-bit value

if __name__ == "__main__":  
lift_bro()  
```

FLAG: flag{l1ftiN6_p41d_0ff!}

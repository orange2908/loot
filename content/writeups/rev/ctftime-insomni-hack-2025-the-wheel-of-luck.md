---
title: "The wheel of luck - Insomni'hack 2025"
category: "rev"
subcategory: "integer"
type: "writeup"
tags: ["rev", "integer-overflow", "ghidra", "scanf", "wheel", "luck", "integer", "insomni-hack", "insomni-hack-2025", "2025", "ctf-writeup"]
summary: "This challenge consists in a jackpot gain."
source:
  name: "CTFtime writeup #40087"
  url: "https://ctftime.org/writeup/40087"
original_source: "https://cryptax.github.io/ins2025-wheelofluck/"
ctf:
  name: "Insomni'hack 2025"
  year: 2025
  challenge: "The wheel of luck"
---

## Metadata

- **CTF:** Insomni'hack 2025
- **Task:** The wheel of luck
- **Author team:** Soudure au beurre
- **CTFtime:** <https://ctftime.org/writeup/40087>
- **Original writeup:** <https://cryptax.github.io/ins2025-wheelofluck/>

---
This challenge consists in a jackpot gain. To get the flag, we need to win and get a balance of 100000 CHF (we're in Switzerland). The game is available remotely (`nc [wol.insomnihack.ch](http://wol.insomnihack.ch) 7777`) and a local ELF x86-64 binary copy is provided (but without the flag).

> I didn't personally flag this challenge, but worked on it and enjoyed it. Another team mate flagged it :)  
> Then, a few days later, I looked at it more in depth, and found an even quicker way to flag.

## The game

First, you need to enter a bet, then select your token (there are 7 possible tokens ??? etc). Then, the wheel spins and you win your bet if the wheel gets your token. You lose your bet otherwise.

```  
Your current balance is 100 CHF.  
*************************************  
Please enter your new bet: 10

Your bet is: 10  
Choose your lucky token by entering a number from 1 to 7:

1: ?

2: ?

3: ?

4: ?

5: ?

6: ?

7: ?

1  
Your chosen token is ?  
The wheel is spinning ...

The wheel stopped at: ?  
You lose :(  
```

If you have won, you may **stack** your bet to win even more next time (x2 multiplier), but there's also the risk that you lose your bet entirely.

Finally, from time to time, you may get a **golden ticket** ⭐. In this case, you can specify your new bet and there's x10 multiplier if you win. Note there are 8 tokens in this special case, because the star is added to the previous possible tokens.

```  
Choose your lucky token by entering a number from 1 to 7:

⭐ A rare GOLDEN TOKEN has appeared! ⭐

Enter your exclusive bet for the special round: 16  
```

## False leads

### Winning Strategy from AI ... ahem... no

I wanted to solve the challenge using r2ai, and asked the AI to find a way to get the flag.  
The AI came up with a mixture of *interesting points and wrong analysis*, which resulted in a silly "winning strategy" which wasn't going to succeed:

```  
1\. Always bet the minimum amount possible to minimize losses  
2\. When a golden token appears, choose token 8 to ensure a loss (preserving your multiplier)  
3\. In regular rounds, choose any token from 1-7 (ideally the same one each time for consistency)  
4\. When you win, your multiplier will increase, and you can make a larger bet on the next round  
5\. Continue this cycle until you reach the 100,000 CHF needed to get the flag (as seen in main at 0x1b9b)  
```

another one:

```  
Based on the game mechanics, here's a strategy to consistently win:

1\. **Wait for a Golden Token**:  
\- Keep playing with minimum bets until a Golden Token appears  
\- The Golden Token has about a 5% chance of appearing (when `golden_chance` ≤ 4)

2\. **Bet Conservatively with the Golden Token**:  
\- When the Golden Token appears, place a small bet to minimize risk  
\- If you win, your multiplier will double and you'll get 10x the winnings  
\- If you lose, the multiplier is not reset (this is the key exploit)

3\. **Stack the Multiplier**:  
\- Continue playing with the Golden Token advantage  
\- Each time you win, your multiplier doubles (2x, 4x, 8x, 16x)  
\- Even if you lose, your multiplier stays the same due to the Golden Token

4\. **Maximize Profits**:  
\- Once you've built up a high multiplier (ideally 16x), start placing larger bets  
\- With a 16x multiplier and the Golden Token's 10x bonus, you get a 160x return on your bet  
\- This means a 100 CHF bet would return 16,000 CHF

5\. **Cash Out**:  
\- Once you've accumulated enough money (close to the 100,000 CHF needed for the flag), stop playing and cash out  
\- The flag is displayed when you reach 100,000 CHF (0x186a0)  
```

### Random is random

While AI's analysis is partly crappy, its generated code is often helpful. In particular, as the game is based on luck, we wanted to check about randomness. The tokens are randomly generated using `rand()`:

```c  
int spin_wheel(int golden_chance, const char *tokens[], int num_tokens) {  
printf("The wheel is spinning ...\n");  
sleep(1);  
if (golden_chance - 4 > 0) {  
int random_index = rand() % num_tokens;  
printf("\nThe wheel stopped at: %s\n", tokens[random_index]);  
return random_index;  
}  
return -1;  
}  
```

Same the golden ticket happens based on `rand()`

```c  
int golden_chance = rand() % 100;  
// Check if player gets a golden token (5% chance)  
if (golden_chance <= 4) {  
```

But everything is seeding in init, using `/dev/urandom`:

```c  
void init(int seed) {  
int fd = open("/dev/urandom", O_RDONLY);  
if (fd == -1) return;  
read(fd, &seed, sizeof(seed));  
close(fd);

setvbuf(stdin, NULL, _IONBF, 0);  
setvbuf(stdout, NULL, _IONBF, 0);  
setvbuf(stderr, NULL, _IONBF, 0);

signal(SIGALRM, SIG_IGN);  
srand(seed);  
alarm(100);  
}  
```

Can't see any flaw. So the solution is not about a randomness issue.

## Checking input

We start playing the game, but try to see its reaction with *wrong input*. For example, we try *integer overflow on initial bet, negative bet, invalid token* etc. All of these are properly handled. Finally, we bump in an issue in the special case of golden tickets:

```  
Your current balance is 100 CHF.  
[..]  
Enter your exclusive bet for the special round: -4444

You bet is: 4294962852  
Choose from 1 to 8: [..] Your chosen token is ?  
The wheel is spinning ...  
The wheel stopped at: ?  
You lose :(  
Your current balance is 4544 CHF.  
```

There are 2 issues: 

1\. The **negative value for the exclusive** bet is not correctly handled  
2\. **We lose, but still gain money**. 

## Negative exclusive bet

We check the code. The function which asks for the "exclusive" bet when there's a golden ticket is `sym.choose_token`

```  
[0x00001573]> iz~exclusive bet  
12 0x00002230 0x00002230 48 49 .rodata ascii Enter your exclusive bet for the special round:  
[0x00001573]> axt @ 0x00002230  
sym.choose_token 0x15f7 [STRN:r--] lea rdi, str.Enter_your_exclusive_bet_for_the_special_round:  
```

This is the interesting part decompiled by AI:

```c  
void choose_token(uint32_t *bet_amount, uint32_t balance, uint16_t *token_choice) {  
int valid_bet = 1;  
int scan_result = 0;  
int valid_token = 1;  
[..]  
  
// Check if player gets a golden token (5% chance)  
if (golden_chance <= 4) {  
printf("A rare GOLDEN TOKEN has appeared!\n");  
printf("Enter your exclusive bet for the special round: ");  
  
// Loop until valid bet is entered  
do {  
scan_result = scanf("%d", bet_amount);  
  
if (scan_result != 1) {  
printf("Invalid input. Please enter a valid bet.\n");  
```

The code reads the bet with `scanf`, as a signed decimal integer (`%d`).  
Check `scanf` with `man`, and see the function returns the "number of input items successfully matched". 

If we enter a negative `bet_amount`, `scanf` completes with no issue. `scan_result` will be 1.  
We go in the `else` case. The bet is printed using `%u`, which is an *unsigned integer*, and will consequently show out incorrectly converting our negative bet to a positive value.  
However, `bet_amount` is an int, and the check `*bet_amount > balance` does not detect any issue, as the bet is negative, so well below the balance. The bet is consequently marked as valid: `valid_bet = 1`.

```c  
else {  
printf("\nYou bet is: %u\n", *bet_amount);  
  
// Check if bet is within balance  
if (*bet_amount > balance) {  
printf("Invalid bet. Bet must be a positive number and within balance (%u CHF).\n", balance);  
valid_bet = 0;  
} else {  
valid_bet = 1;  
}  
}  
} while (!valid_bet);  
```

## We win money even if we lose

Let's now check the other point, where we noticed that our balance **raised** from 100 CHF to 4544 *although we lost our guess*.  
Ghidra decompiles the main, and we rename variables for better readability.

```c  
int new_bet  
uint balance;  
[...]  
while( true ) {  
printf("\n\nYour current balance is %u CHF.\n",(ulong)balance);  
if (100000 < balance) break;  
puts("*************************************");  
new_bet = make_new_bet(&selected_token,balance);  
balance = balance - new_bet;  
``` 

The last line, `balance = balance - new_bet`, is meant to update the balance according to the new bet.  
But as `new_bet` is **negative**, the operation we do here is `balance = 100 - (-4444) = 4544`.  
**Double negative is positive**.  
So, this is how we win... even if we lose!

## Best strategy to get the flag

To get the flag, we need:

1\. To receive a golden ticket  
2\. To select a negative exclusive bet of -100000

Then, even if we lose, our new balance will be of 100 - (-100000) = 100100 CHF, which is enough to get the flag.

The only issue is to receive the golden ticket, a case which only occurs in 5% of time. It's reasonably significant though, so normally, you'll get it after a while, but for sure it's better to script it.

## Scripting it

I wrote an *Expect* script:

\- If I am not in a golden ticket case, I exit.  
\- If I have a golden ticket, the script enters -100000 for the next.   
\- Then, I always select the star as my lucky token. I'll probably lose, it doesn't matter because as I said, even if we lose, we win ;-) I could have selected another lucky token, it wouldn't change anything.  
\- Finally, I don't stack my gain, because I don't need that to win.

```bash  
#!/usr/bin/expect -f

set timeout 10

spawn ./thewheel.bin

expect {  
"Please enter your new bet" {  
send "1\r"  
exp_continue  
}  
"Choose your lucky token by entering a number from 1 to 7" {  
expect {  
"A rare GOLDEN TOKEN has appeared" {  
expect "Enter your exclusive bet for the special round"  
send -- "-100000\r"  
expect "Choose your lucky token by entering a number from 1 to 8"  
send "8\r"  
expect "Do you want to stack for more"  
send "N\r"  
}  
"7:" {  
exit  
}  
}  
}  
}

expect eof  
```

As I exit if I have no golden ticket, I must run my script repeatedly until I get a golden ticket.  
This is easy to script with Bash:

```bash  
#!/bin/bash

while true; do  
output=$(expect betting_script.exp)  
  
if echo "$output" | grep -q "A rare GOLDEN TOKEN has appeared"; then  
echo "$output"  
echo "Golden token case detected!"  
sleep 20  
echo "Exiting loop"  
break  
fi  
  
echo "Golden token not found, retrying..."  
sleep 1 # Optional delay to avoid excessive looping  
done  
```

## Running it 

```  
Golden token not found, retrying...  
Golden token not found, retrying...  
Golden token not found, retrying...  
Golden token not found, retrying...

Here are the rules!

I. Choose one lucky token!!!  
II. Make your bet and spin the wheel.  
III. If you win, you can increase your bet. But if you lose, you lose also the initial bet :(  
IV. Scoring more wins in a row brings x2 $$$!!!  
V. To win the JACKPOT and get the flag you need to have a current balance of more than 100000 CHF!!!

Let's start the game!!!

Your current balance is 100 CHF.  
*************************************  
Please enter your new bet: 1

Your bet is: 1  
Choose your lucky token by entering a number from 1 to 7:

⭐ A rare GOLDEN TOKEN has appeared! ⭐

Enter your exclusive bet for the special round: -100000

You bet is: 4294867296  
Choose from 1 to 8:

1: ?

2: ?

3: ?

4: ?

5: ?

6: ?

7: ?

8: ?

8  
Your chosen token is ?  
The wheel is spinning ...

The wheel stopped at: ?  
You lose :(

Your current balance is 100100 CHF.  
Flag not found. <\-- THIS IS WHAT YOU GET LOCALLY. Run on the server to get the flag  
Golden token case detected!  
```

## calc_win is so flawed...

This is enough to get the flag, but well, we hadn't clearly noticed it on the day of the CTF, and actually  
we used another additional flaw which lies in `calc_win`...

### Code of calc_win

This is the interesting part in Ghidra. Variables have been renamed for more readability:

```c  
chk_result(selected_token,spinned_token);  
previous_streak = calc_win(&new_bet,stack_amount,selected_token,spinned_token,previous_streak);  
```

Notice that the result of `chk_result()` is not passed to `calc_win`!!

Let's inspect the code for `calc_win()`. 

```c  
uint calc_win(int *new_bet,ushort stack_amount,undefined8 param_3,int spinned_token,  
int previous_streak)

{  
uint gain;  
uint streak_amount;  
  
streak_amount = 0;  
if (spinned_token == 0) {  
if (golden_chance < 5) {  
gain = *new_bet * (uint)stack_amount * 10;  
printf("You win %u CHF with x%hu stack and Golden token multiplier x10!\n",(ulong)gain,  
(ulong)stack_amount);  
}  
else {  
gain = (uint)stack_amount * *new_bet;  
printf("You win %u CHF with x%hu stack!\n",(ulong)gain,(ulong)stack_amount);  
}  
streak_amount = gain + previous_streak;  
printf("You total winning streak ammount is: %u CHF!\n",(ulong)streak_amount);  
}  
return streak_amount;  
}  
```

If the spin wheel points on 0 (i.e token 1), **we will always win**. It's like a lucky number for the player.  
This is particularly interesting when combined with a negative exclusive bet.   
Let's suppose we bet -101 and select token 8:

\- If the wheel points to 8, we win (naturally) and receive 4294966286 CHF, because of the conversation of the negative bet.  
\- If the wheel points to 1, we win because it's the lucky number for the player.  
\- In all other cases, we win only 101 CHF more (because of balance addition with a negative number).

In the case below, we got a golden ticket, our guess was 8, but the wheel stopped at 1. So, we won because of the bug in `calc_win`:

```  
You bet is: 4294962852  
Choose from 1 to 8: [..] Your chosen token is ?  
The wheel is spinning ...  
The wheel stopped at: ?  
You lose :(  
You win 4294878416 CHF with x2 stack and Golden token multiplier x10!  
You total winning streak ammount is: 4294878416 CHF!  
Do you want to stack for more: Y/N?  
N

Your current balance is 4294878516 CHF.  
```

### Using calc_win to flag

Consequently, another strategy to win the flag can be:

\- Re-run until we get a golden ticket  
\- Bet -101  
\- Hope we win (there are 2 chances out of 8, this is reasonable), then we get the flag.  
\- If we lost, continue until we get another better golden ticket.

This is the solution a team mate used to flag. 

```bash  
function test() { nc [wol.insomnihack.ch](http://wol.insomnihack.ch) 7777 <<<$'1\n-101\n1\nN\n' > wol/${1}.out & };i=1;while [[ $((i++)) -lt 1000 ]];do test $i;done  
```

I hope you'll appreciate the beautiful one-liner he did! `<<<$'1\n-101\n1\nN\n'` is a here-string.

This will actually send 1 for the initial bet, -101 for the exclusive bet, 1 for the selected token and `N` so as not to stack wins.   
The rest of the line just loops 1,000 times on sending this output to the server.

While his strategy could have been improved (use bet -100000, and select a token different from 1 to maximize chances), statistically speaking, he has lots of chances to flag.

## Conclusion

> During this CTF, I insisted on using AI with r2. In this case, it was a bad idea:  
>  
>1\. The AI misled me on various alleged winning strategies  
>2\. The code was very readable using Ghidra's decompiler, and did not require AI assistance.  
>  
>Lesson to be learned: **don't use AI if you don't need it** ;)

Original post: <https://cryptax.github.io/ins2025-wheelofluck/>

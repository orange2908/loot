---
title: "Random - n00bzCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "random", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "We are given parts of the cpp source of the challenge."
source:
  name: "CTFtime writeup #39375"
  url: "https://ctftime.org/writeup/39375"
original_source: "https://moormaster.github.io/CtfWriteups/random.html"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Random"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Random
- **Author team:** zwiebel
- **CTFtime:** <https://ctftime.org/writeup/39375>
- **Original writeup:** <https://moormaster.github.io/CtfWriteups/random.html>

---
We are given parts of the cpp source of the challenge. The main functions reads in a line and is doing some checks in the input

```
        map<char, int> counts;
        for (char c : s) {
            if (counts[c]) {
                cout << "no repeating letters allowed passed this machine" << endl;
                return 1;
            }
            counts[c]++;
        }
    
        if (s.size() < 10) {
            cout << "this machine will only process worthy strings" << endl;
            return 1;
        }
    
        if (s.size() == 69) {
            cout << "a very worthy string" << endl;
            cout << "i'll give you a clue'" << endl;
            cout << "just because something says it's random mean it actually is" << endl;
            return 69;
        }
```

after that the line input gets shuffled

```
        random_shuffle(s.begin(), s.end());
```

... and a sorting algorithm is asked to sort the characters of the line

```
        if (amazingcustomsortingalgorithm(s)) {
            ifstream fin("flag.txt");
            string flag;
            fin >> flag;
            cout << flag << endl;
        }
        else {
            cout << "UNWORTHY USER DETECTED" << endl;
        }
```

A quick look at the sort algorithm tells us that it is not really sorting but instead it checks if the input is already sorted and repeatedly (uo to 69 times) calls the `random_shuffle` method if the input is not sorted yet.

```
    bool amazingcustomsortingalgorithm(string s) {
        int n = s.size();
        for (int i = 0; i < 69; i++) {
            cout << s << endl;
            bool good = true;
            for (int i = 0; i < n - 1; i++)
                good &= s[i] <= s[i + 1];
    
            if (good)
                return true;
    
            random_shuffle(s.begin(), s.end());
    
            this_thread::sleep_for(chrono::milliseconds(500));
        }
    
        return false;
    }
```

The source code for the `random_shuffle` method is not known but there is a hint in of the input checks ...

```
        if (s.size() == 69) {
            cout << "a very worthy string" << endl;
            cout << "i'll give you a clue'" << endl;
            cout << "just because something says it's random mean it actually is" << endl;
            return 69;
        }
```

If we reconnect to the challenge and give it the same sample input like `0123456789` we'll see that the first shuffled version of that string is always producing the same output:

```
    $ echo "0123456789" | nc challs.n00bzunit3d.xyz 10385
    4378052169
    0578439216
```

So our task here is to undo the fixed permutation above on the sorted value `0123456789` so that the first call of `random_suffle` will apply the permutation again and produce sorted string - leading the `amazingcustomsortingalgorithm` method to return true immediately and causing the flag to be printed:

The first output line tells us how to invert the permuation:

```
    4   - character at index 4 -> 0
    3   - character at index 3 -> 1
    7   - character at index 7 -> 2
    8   ...
    0
    5
    2
    1
    6
    9
```

... resulting in the input value `4761058239`:

```
    $ echo "4761058239" | nc challs.n00bzunit3d.xyz 10385
    0123456789
    n00bz{FAKE_FLAG}
```

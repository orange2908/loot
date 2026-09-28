---
title: "web codenames-1 - ImaginaryCTF 2025"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["imaginary-ctf", "web", "python", "2025", "path-traversal", "flask", "werkzeug", "wordlists", "lfi", "imaginaryctf", "imaginaryctf-2025", "ctf-writeup"]
summary: "The full source code for the application was provided (see the challenge directory), allowing for in-depth analysis and understanding of its functionality and security."
source:
  name: "CTFtime writeup #40416"
  url: "https://ctftime.org/writeup/40416"
original_source: "https://github.com/S450R1/imaginary-ctf-writeups/tree/main/web/codenames-1"
ctf:
  name: "ImaginaryCTF 2025"
  year: 2025
  challenge: "web codenames-1"
---

## Metadata

- **CTF:** ImaginaryCTF 2025
- **Task:** web codenames-1
- **Author team:** WhiteDukesDZ
- **CTFtime tags:** imaginary-ctf, web, python, 2025, path-traversal
- **CTFtime:** <https://ctftime.org/writeup/40416>
- **Original writeup:** <https://github.com/S450R1/imaginary-ctf-writeups/tree/main/web/codenames-1>

---
# WhiteDukesDZ - Imaginary CTF 2025 Writeup: codenames-1

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/imaginary-ctf-writeups/main/web/codenames-1/challenge/web-codenames-1-challenge.png>)

The full source code for the application was provided (see the `challenge` directory), allowing for in-depth analysis and understanding of its functionality and security.

\---

## Challenge Summary

This challenge presents a Python web application built with Flask and Flask-SocketIO, featuring real-time multiplayer gameplay. Users can register, log in, and play Codenames with others or bots. The app manages user profiles, game state, and supports multiple languages.

## Application Analysis

Upon reviewing the deployment configuration (Dockerfile), we notice that there are two flags present in the application:  
\- One flag is stored in the file `/flag.txt`.  
\- The second flag is set as an environment variable (`FLAG_2`).  
These flags may be revealed through different exploitation paths in the challenge.

Additionally, the `words` folder contains `.txt` files for each supported language (e.g., `en.txt` for English), which are used as wordlists for the Codenames game.

The `[app.py](http://app.py)` file is the main backend for the challenge and implements a real-time multiplayer Codenames game using Flask and Flask-SocketIO. Here are its key components and logic:

\- **Imports & Setup:**  
\- Uses Flask for web routing and session management, Flask-SocketIO for real-time communication, and Werkzeug for password hashing.  
\- Initializes the app, sets a secret key, and prepares directories for profiles and wordlists.

\- **User Profiles:**  
\- Profiles are stored as JSON files in the `profiles` directory, containing username, hashed password, win count, and bot status.  
\- Functions `load_profile` and `save_profile` handle reading and writing these profiles.

\- **Routes:**  
\- `/` (index): Redirects logged-in users to the lobby, otherwise shows the homepage.  
\- `/register`: Handles user registration, enforces password length, checks for existing usernames, and supports bot detection via a secret prefix in the password.  
\- `/login`: Authenticates users, supports bot detection, and sets session variables.  
\- `/logout`: Logs out the user and clears the session.  
\- `/lobby`: Shows the lobby with win count and available languages.  
\- `/create_game`: Creates a new game with a random code, selects a language, loads words, assigns teams, and sets up the game board.  
\- `/join_game`: Allows a second player to join an existing game and assigns them as the clue giver.  
\- `/game/``: Renders the game view for a specific game code, with the choosen language.  
- `/add_bot`: Spawns a bot process to join a game, passing the secret prefix via environment variable.`

\- **SocketIO Events:**  
\- `join`: Handles players joining a game room, tracks socket IDs, and starts the game when both players are connected.  
\- `give_clue`: Allows the clue giver to send a clue and number of guesses to the game.  
\- `make_guess`: Allows the guesser to make guesses, updates the board, checks win/lose conditions, and awards wins. If hard mode is enabled and a bot is present, the flag from the environment variable may be revealed.

\- **Game Logic:**  
\- Supports multiple languages via wordlist files in the `words` directory.  
\- Assigns teams, clue givers, and manages game state (board, colors, revealed words, scores).  
\- Implements hard mode for double win points and special lose conditions.  
\- Handles bot participation and flag reveal logic.

\- **Main Entry:**  
\- Runs the app using SocketIO for real-time features.

This structure enables secure user management, flexible game setup, and interactive gameplay, with special logic for bots and flag retrieval as part of the challenge.

### Security Observations

And after carefully analyzing `[app.py](http://app.py)`, we notice that when creating or joining a game, the application loads the language wordlist based on user input from the form (the `language` parameter). This input is used to select the corresponding `.txt` file from the `words` directory (e.g., `language=en` => `words/en.txt`). While there is a basic check to prevent directory traversal (rejecting language values containing a dot), the application still trusts the user-provided language value to determine which wordlist to load.

The `.` check can easily be bypassed. Using an absolute path. You can try this on your terminal:

```sh  
└─$ python3  
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux  
Type "help", "copyright", "credits" or "license" for more information.  
>>> import os  
>>> os.path.join("words", "/flag.txt")  
'/flag.txt'  
```

\---

## Solution

We already know that the flag is on `/flag.txt`, to get the flag we need to:

\- Create a new account.

\- Create a game with `language=/flag` which will result in the game loaded with `os.path.join(WORDS_DIR, "/flag.txt")` => `/flag.txt`.

\- Add a bot to the newly created game so the game starts.

\- See the flag in all the board cases.

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/imaginary-ctf-writeups/main/web/codenames-1/solution/web-codenames-1-flag.png>)

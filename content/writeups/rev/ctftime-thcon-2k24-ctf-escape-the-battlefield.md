---
title: "Escape the battlefield - THCon 2k24 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "godot", "reverse", "escape", "battlefield", "thcon-2k24-ctf", "ctf-writeup"]
summary: "By opening the game from a terminal, it can be seen that the game has been developed with Godot Engine, an open source game engine:"
source:
  name: "CTFtime writeup #39048"
  url: "https://ctftime.org/writeup/39048"
ctf:
  name: "THCon 2k24 CTF"
  challenge: "Escape the battlefield"
---

## Metadata

- **CTF:** THCon 2k24 CTF
- **Task:** Escape the battlefield
- **Author team:** r00ster
- **CTFtime tags:** godot, reverse
- **CTFtime:** <https://ctftime.org/writeup/39048>

---
By opening the game from a terminal, it can be seen that the game has been developed with [Godot Engine](<https://godotengine.org/>), an open source game engine:

```  
Godot Engine v4.2.1.stable.custom_build - <https://godotengine.org>  
OpenGL API 3.3.0 NVIDIA 517.48 - Compatibility - Using Device: NVIDIA - NVIDIA GeForce MX250  
```

[gdsdecomp ](<https://github.com/bruvzg/gdsdecomp)is> a reverse engineering tools for games written with Godot Engine. It is able to recover a full project from the executable. Executables produced by Godot embed a "PCK" (packed) archive. gdsdecomp is able to locate that archive, extract it, and even decompile its embedded GDScripts.

Opening game.exe with gdsdecomp gives the following error message:

> Error opening encrypted PCK file: C:/Users/xx/Downloads/game.exe  
> Set correct encryption key and try again.

The PCK archive is encrypted. Its encryption key must be retrieved. As Godot Engine has to extract this archive to run the game, the encryption key must be present somewhere in the binary. By quickly looking at the project source code, I found a location where thus key is manipulated and easy to retrieve with a debugger:

```c  
bool PackedSourcePCK::try_open_pack(const String &p_path, bool p_replace_files, uint64_t p_offset) {  
Ref<FileAccess> f = FileAccess::open(p_path, FileAccess::READ);  
if (f.is_null()) {  
return false;  
}

bool pck_header_found = false;

// Search for the header at the start offset - standalone PCK file.  
f->seek(p_offset);  
// ...  
if (enc_directory) {  
Ref<FileAccessEncrypted> fae;  
fae.instantiate();  
ERR_FAIL_COND_V_MSG(fae.is_null(), false, "Can't open encrypted pack directory.");

Vector<uint8_t> key;  
key.resize(32);  
for (int i = 0; i < key.size(); i++) {  
key.write[i] = script_encryption_key[i];  
}  
```

Godot Engine has a verbose logging system. Error strings can be easily located in the binary. Breaking just after the reference to the "Can't open encrypted pack directory." message allows to directly dump the value of `script_encryption_key`.

Key value is DFE5729E1243D4F7778F546C0E1EE8CC532104963FF73604FFB3234CE5052B27.

Enter key in "RE Tools" --> "Set encryption key", then extract project.

Project contains 6 GD files: [Beach.gd](http://Beach.gd), [Bullet.gd](http://Bullet.gd), [Enemy.gd](http://Enemy.gd), [EnemySpawner.gd](http://EnemySpawner.gd), [Main.gd](http://Main.gd) and [Player.gd](http://Player.gd). They are small and can be quickly analyzed. The interesting function for the challenge is `_unhandled_input`, located in [Main.gd](http://Main.gd):

```python  
func teleport():  
get_tree().change_scene_to_file("res://Beach.tscn")

func _unhandled_input(event):  
if event is InputEventKey:  
if event.pressed and event.keycode == KEY_ESCAPE:  
get_tree().quit()  
if event.pressed and event.keycode == KEY_G and power == 0:  
power += 1  
elif event.pressed and event.keycode == KEY_M and power == 1:  
power += 1  
elif event.pressed and event.keycode == KEY_T and power == 2:  
power += 1  
elif event.pressed and event.keycode == KEY_F and power == 3:  
power += 1  
elif event.pressed and event.keycode == KEY_L and power == 4:  
power += 1  
elif event.pressed and event.keycode == KEY_A and power == 5:  
power += 1  
elif event.pressed and event.keycode == KEY_G and power == 6:  
teleport()  
elif event.pressed:  
power = 0  
```

It checks for keyboard input events. If the good combination is entered, the main scene is replaced with the "Beach" scene thanks to the `teleport` function. The `_ready` function prints with a timer each char of the flag. As each char is put in a specific location, difficult to identify by just reading the source code, it is preferable to get the flag directly from the game, rather than by reading the code.

Open game, enter "gmtflag" and a new screen displays the flag.

Flag is THCON{60d07_D3cryp7}

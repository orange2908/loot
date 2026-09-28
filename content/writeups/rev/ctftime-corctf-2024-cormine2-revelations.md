---
title: "corMine2: Revelations - corCTF 2024"
category: "rev"
subcategory: "rust"
type: "writeup"
tags: ["rev", "bevy", "rust", "reversing", "game-hacking", "ghidra", "binaryninja", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "#Reverse Engineering #Game Hacking #Rust #Bevy #ECS"
source:
  name: "CTFtime writeup #39394"
  url: "https://ctftime.org/writeup/39394"
original_source: "https://nnub.es/blog/en/ctf/corctf/2024/cormine/"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "corMine2: Revelations"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** corMine2: Revelations
- **Author team:** ICAI Cyber Team
- **CTFtime tags:** bevy, rust, reversing, game-hacking
- **CTFtime:** <https://ctftime.org/writeup/39394>
- **Original writeup:** <https://nnub.es/blog/en/ctf/corctf/2024/cormine/>

---
# corMine 1 and 2

tags
     [#Reverse Engineering](https://nnub.es/blog/en/tags/reverse-engineering/) [#Game Hacking](https://nnub.es/blog/en/tags/game-hacking/) [#Rust](https://nnub.es/blog/en/tags/rust/) [#Bevy](https://nnub.es/blog/en/tags/bevy/) [#ECS](https://nnub.es/blog/en/tags/ecs/)
published
    August 17, 2024
series
    corCTF 2024
reading time
    ~59 minutes

…in which a reverse engineer having a Not Good day is given a Rust binary with a Bevy game, and then proceeds to descend into madness about it. Then after corCTF, tries to make a write-up and descends into madness about it _again_.

# corMine 1 - The Beginning

> Crusaders of Rust Gaming Division is proud to present our first totally original title: corMine! Please enjoy exclusive access to this alpha test! […]

On this challenge, we are provided with a compressed archive containing two files:

  * `cormine`, a Linux AMD64 binary.
  * `cormine1.cms`, a data file.


## Exploring the game

Upon running the executable, and after a few seconds of initialization, we are presented with **corMine** , a voxel-based sandbox game reminiscent of early versions of Minecraft.

![The corMine game running on a window, showing a beautiful voxel landscape.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_1.png)

The game allows the player to move (`W``A``S``D`) and jump (`Space`) around within a delimited voxel-based 3D world. The player can also break and place (left/right mouse click) blocks, of which a palette of five different types of blocks is available to the player (`1``2``3``4``5`).

![A showcase of the 5 blocks the player has available to place: stone, grass, water, ice and dirt.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_2.png)

By default, the game generates a random world on startup; however, saves can also be loaded. The current world state can be saved onto a `game.cms` file by pressing `F9`. The instructions for the first challenge hint us at the means to load such a save by running the game from the terminal:

```
    $ ./cormine load game.cms
```

The challenge provides one such save file to try: `cormine1.cms`. Upon loading it, the player spawns on top of a large box. Its outer lining seems to be made of a 6th block type which cannot be broken by the player. The objective seems clear: break or otherwise reveal the contents of the box.

![The top of a mysterious monolith, lined with black blocks that were not part of the showcase, nor seem available to the player.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_3.png) ![A far-off view of the mysterious monolith, emphasizing its massive size in contrast to the landscape around it.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_4.png)

Sometimes, the game seems to crash or “panic” benignly upon closing it using the window controls.

![Console output shows the game crashing or panicking due to a lack of entities, whatever that means.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_5.png)

While this crash is certainly not intended, it cannot be denied that the way the crash information is presented, along with hints that can be gleaned from the logging output, quickly reveals three key facts to the reverse-engineer:

  1. The program has been developed using the **Rust** programming language, which uses the term “panic” to designate fatal program errors, as is hinted by the format of the crash message.
  2. Some **debug information** is provided with the executable, as full source location information for the resulting stack trace can be requested at the moment of the crash with an environment variable (`RUST_BACKTRACE=1`).
  3. This very stack trace hints the use of a few Rust packages, notably **`bevy`** ; a quick search on Rust’s package repository eventually leads to **Bevy** , a popular game engine for Rust.


## The Plan

Now, before we go any further, let me spoil you the whole thing and tell you about the various easy ways you can solve this challenge:

  * Hacking the player’s position through memory editing with tools like [GameConqueror](https://github.com/scanmem/scanmem).
  * Hooking into the game with [RenderDoc](https://renderdoc.org/).
  * Finding and editing the shaders corresponding to the rendered blocks.


This write-up is not about any of those.

You see, dear reader, at the time of corCTF 2024… I was not at my best :’). I was not reasonable, much less someone that could come up with simple solutions. So, sure, I could tell you how to do any of the above… or I could tell you about the _terrifyingly_ overkill way I did it at corCTF 2024.

The way to solve the first challenge that I came up with stems from the following thought process:

  * We have previously established that the player can break blocks.
  * The map provided by the challenge, `cormine1.cms`, has unbreakable blocks.
  * This implies there has to be a distinction between breakable and unbreakable blocks.
  * This distinction is, very likely, enforced by **conditional branches** within the logic that handles block breaking.
  * These checks can be **subverted** somehow.


So, here’s the game plan:

  1. Identify the logic that handles left-mouse clicks.
  2. Run the game under a debugger while loading `cormine1.cms`, and set a breakpoint on this function.
  3. Try to break both unbreakable and breakable blocks, triggering the breakpoint.
  4. Through the differences in how the game’s code handles both cases, identify the conditional jump/-s that makes some blocks unbreakable, and patch them out, thereby making all blocks breakable.
  5. …
  6. Flag!?


## Navigating an ocean of Systems

We can open up the executable in our reverse-engineering tool of choice to take a look at it; I chose the free version of Binary Ninja in this particular case. Despite the sheer size of the binary, the initial analysis is able to complete; however, an initial exploration seems for naught at first, as I quickly got lost in an ocean of functions without much of a direction.

Let’s not panic, though. When in doubt, we can do string searches for keywords found in console logs, as those will often end up close to the application logic. Problem is, there don’t seem to be that many useful logs here. With some playing around, though, we can find that whenever we save the map with `F9`, the string `Saved to game.cms` is printed to the console; this should be close enough to the application logic for our purposes.

![Console output showing the aforementioned string being printed.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev1.png) ![Examining the game executable with the program Binary Ninja, the string can be found packed alongside many other strings.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev2.png)

Ok, so we have a packed string. Let’s follow the trail by looking at the cross-references:

![Binary Ninja shows dozens of references to this particular string from other locations in the executable.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev3.png)

There is a lot of data references pointing to this packed string. If we start examining them individually, we’ll find that each one is a pointer located in the `.data.rel.ro` section referencing an individual string within the larger pack. By inspecting the individual pointers one by one, we can easily find the one that points directly to our string of interest:

![One of the references points to the specific string we are looking for.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev4.png)

Examining the cross-references for this pointer, we can then land on the function that prints this string:

![A view of the cross-references for this reference, showing two references on a function.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev5.png) ![An excerpt of the decompilation of the function in question shows the string being used here.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev6.png)

The debug information shows this function as:

```
    _$LT$bevy_ecs..system..function_system..FunctionSystem$LT$Marker$C$F$GT$$u20$as$u20$bevy_ecs..system..system..System$GT$::run_unsafe::hf653820ccd9abe7c
```

Which through some choice substitutions (`$LT$` becomes `<`, `$GT$` becomes `>`… you can take hints from this [this Ghidra script](https://gist.github.com/str4d/e541f4c28e2bca80d222434ac1a204f4)) can be cleaned up into:

```
    <bevy_ecs::system::function_system::FunctionSystem<Marker, F> as bevy_ecs::system::system::System>::run_unsafe::hf653820ccd9abe7c
```

If we translate this type signature into plain English, we can _almost_ describe it as “the function run_unsafe, from a [`FunctionSystem`](https://docs.rs/bevy/0.14.1/bevy/ecs/system/struct.FunctionSystem.html) casted into a [`System`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.System.html)”. _Almost_ , what is the random string of letters at the end (`hf653820ccd9abe7c`)? We’ll get to that a bit later.

But, strange huh? It does seems this function from Bevy itself entirely implements the game’s very own save logic in question. Does that even make sense? Not really, but there’s an explanation why this function shows up when searching for this string.

## Interlude: Ornithology, and surprising Rust optimizations

Let’s dig into Bevy itself, starting from the documentation of [`FunctionSystem`](https://docs.rs/bevy/0.14.1/bevy/ecs/system/struct.FunctionSystem.html):

> ### **Struct** `bevy::ecs::system::FunctionSystem`
> 
> The [`System`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.System.html) counter part of an ordinary function.
> 
> You get this by calling [`IntoSystem::into_system`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.IntoSystem.html#tymethod.into_system) on a function that only accepts [`SystemParam`](https://docs.rs/bevy/0.14.1/bevy/ecs/system/trait.SystemParam.html)s. The output of the system becomes the functions return type, while the input becomes the functions _(sic)_ [`In`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/struct.In.html) tagged parameter or `()` if no such parameter exists.
> 
> […]

So `FunctionSystem` is a type that wraps a standard Rust function and allows it to become a Bevy [`System`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.System.html). The type we got does in fact make a reference to [`System`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.System.html), which according to the documentation is…

> ### **Trait** `bevy::ecs::prelude::System`
> 
> An ECS system that can be added to a [`Schedule`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/struct.Schedule.html).

“ECS”? Some internet searches, and now this starts to make a bit of sense in context. A core feature of Bevy is its **ECS** (Entity Component System) architecture. From a cursory reading, I cannot quite conclude whether ECS is a programming paradigm or a software architecture, but concisely, ECS comprises three key concepts interacting together:

  * **Entities** , which represent an instance of _something_ ; let it be a player, an NPC, a camera or even the world geometry itself. Entities, as is, do not contain data or logic; they merely serve as an identity for that _something_ ’s self, generally an unique identifier.

  * **Components** , data structures which can be arbitrarily attached to entities in a piece-meal basis, thus donning the entities with state.

  * **Systems** , as processes or units of logic which operate on entities that match a condition, often expressed as a query for the existence or absence of certain components, and are responsible for actually operating on these components.


For example, within the context of an role-playing game, the player character may be represented as an **entity** with `Position`, `Health` and `Player` **components** (the last one possibly being empty, instead serving as a marker for identifying what entity represents the player character). An applicable **system** may be one that reads the player’s inputs every frame and updates the `Position` of any entity that is also a `Player` accordingly.

With this knowledge in mind, we can deduce that _the_ game logic of corMine is, very likely, implemented as **systems**. So we may very well be on the right path! But then, _why_ is the logic hiding inside an opaque `FunctionSystem<Marker, F>`?

Let’s keep digging: `System` does indeed have a [`run_unsafe`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.System.html#tymethod.run_unsafe) method you can override. And, `FunctionSystem` does implement `System`, so it [does implement `run_unsafe` too](https://docs.rs/bevy_ecs/0.14.1/src/bevy_ecs/system/function_system.rs.html#515-537)!

```
        #[inline]
        unsafe fn run_unsafe(&mut self, input: Self::In, world: UnsafeWorldCell) -> Self::Out {
            // ... some initialization happens before ...
            let out = self.func.run(input, params); // oh, this looks interesting!
            self.system_meta.last_run = change_tick;
            out
        }
```

Where `self.func` is the instance of `F` stored by `FunctionSystem<Marker, F>`, which it seems to “run”. What is `F`, even?

```
    pub struct FunctionSystem<Marker, F> // (1)
    where
        F: SystemParamFunction<Marker> // (2)
```

We’ll ignore `Marker` for now, but both `Marker` and `F` are **generic type parameters** (1). So as to make this more comfortable for beginner reverse-engineers: if you know C++, think templates; otherwise, try to think about how you can pass parameters to functions in most programming languages, but now instead of thinking of code, think of that concept being applied to _types_ as handled by a type system (say, classes in Java). Maybe that makes more sense? Well, dunno, for now just consider `Marker` and `F` “placeholders for other types”.

We’ll ignore `Marker` for now and focus on `F`. It seems that whatever type ends up being `F`, it must implement `SystemParamFunction` (2), which according to the documentation is:

> ### **Trait** `bevy::ecs::prelude::SystemParamFunction`
> 
> A trait implemented for all functions that can be used as Systems.

**Recommendation:** don’t scroll too far down on the [`SystemParamFunction`](https://docs.rs/bevy/0.14.1/bevy/ecs/prelude/trait.SystemParamFunction.html) documentation, you will likely blank out midway and end up waking up 19 hours later with a hangover and a [turbofish](https://turbo.fish/) scribbled onto your forehead by mysterious extra-dimensional crab gods. Instead, look at the source for the [`impl_system_function`](https://docs.rs/bevy_ecs/0.14.1/src/bevy_ecs/system/function_system.rs.html#688-715) macro that automates all of that mess, and deep within its confines you will see the light:

```
    // ...
    fn run(&mut self, _input: (), param_value: SystemParamItem< ($($param,)*)>) -> Out {
        // Yes, this is strange, but `rustc` fails to compile this impl
        // without using this function. It fails to recognize that `func`
        // is a function, potentially because of the multiple impls of `FnMut`
        #[allow(clippy::too_many_arguments)]
        fn call_inner<Out, $($param,)*>(
            mut f: impl FnMut($($param,)*)->Out,
            $($param: $param,)*
        )->Out{
            f($($param,)*)
        }
        let ($($param,)*) = param_value;
        call_inner(self, $($param),*)
    }
    // ...
```

Is this even real Rust? It is, the macro syntax just makes it look like someone reinvented Lisp inside Rust. Let’s clean this up into pseudocode:

```
    fn run(&mut self, _input: (), param_value: SystemParamItem<(Param1, Param2...)>) -> Out {
        fn call_inner<Out, Param1, Param2...>(
            mut f: impl FnMut(Param1, Param2...) -> Out,
            param1: Param1,
            param2: Param2,
            ...
        ) -> Out{
            f(param1, param2...) // f == self == <F as SystemParamFunction> !!!
        }
        let (param1, param2...) = param_value;
        call_inner(self, param1, param2...)
    }
```

So it _is_ calling _itself_ , as a `FnMut`! Which means `F` is, in fact, _**the**_ ordinary function [`FunctionSystem`](https://docs.rs/bevy/0.14.1/bevy/ecs/system/struct.FunctionSystem.html) was talking about!

Ok, let’s take a few steps back and **recap** what we know so far:

  1. The function we are analyzing is `<FunctionSystem<Marker, F> as System>::run_unsafe`. That is, the trait `System` has a method `run_unsafe` which `FunctionSystem` implements, and the function we are analyzing _is_ that implementation.
  2. A “system” on Bevy terminology is a process or piece of logic that operates on application data.
  3. `FunctionSystem<Marker, F>` stores an `F`, which is a plain old Rust function.
  4. `FunctionSystem<Marker, F>`’s implementation of `run_unsafe` calls the stored `F`.


So, _what_ is a `FunctionSystem`?

Well, it is in fact, one of Bevy’s **selling points** : its ECS engine allows the developer to fully define systems using plain old Rust functions! Here’s a function system I just came up with:

```
    #[derive(Component)]
    struct Position {
        x: f32,
        y: f32,
    }
    
    #[derive(Component)]
    struct Velocity {
        x: f32,
        y: f32,
    }
    
    fn update_frog_position(mut query: Query<(&mut Position, &Velocity)>) {
        for (mut position, velocity) in &mut query {
            position.x += velocity.x;
            position.y += velocity.y;
        }
    }
```

It takes entities that have `Position` and `Velocity` components, then reads the velocity of each entity and uses it to update its position. Pretty sick, huh?

Now let’s see what happens behind the scenes:

  * Upon registering this system onto our hypothetical Bevy game, some Rust type magic allows this function to get wrapped onto a `FunctionSystem`, becoming its `F`, such that here you’d get an instance of `FunctionSystem<Marker, update_frog_position>`.
  * Due to the way generic type parameters work on Rust, the compiler considers `FunctionSystem<Marker, F>` **unique for every** `F`, meaning `FunctionSystem<Marker, update_frog_position>` and `FunctionSystem<Marker, print_frogs>` are in fact **different types** , each with its own unique in-memory structure.
  * And, because of the fact `F` can be of different types, each with a different size, the memory layout of the entire `FunctionSystem<Marker, F>` can change too as a result, which suddenly makes generating assembly that has to access a field at a certain offset of this structure particularly difficult, to say the least.
  * The solution the Rust compiler provides is to make **one copy** of the same function (in this case, `run_unsafe`) for **every combination** of `Marker` and `F` that is used to call it, so that the instructions that do memory accesses to this structure are generated correctly to read on the correct offsets for each field. The compilation process under which these functions are duplicated is known as **monomorphization**.


Because of this, there is, in fact, **multiple copies** of `run_unsafe` on the program! So _**many**_ of them!

![A search for symbols containing the string run_unsafe shows that there are a lot of them named very similarly.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev7.png)

Thus, the random string at the end of the function’s signature (`hf653820ccd9abe7c`) is a means of distinguishing each individual copy of `run_unsafe` for debugging purposes.

By now, you may start to see what is happening here:

  * If the compiler knows exactly what system function `F` each instance of `FunctionSystem<Marker, F>` has at compile time…
  * …and the compiler is near-guaranteed to keep a `FunctionSystem<Marker, A>` separate from a `FunctionSystem<Marker, B>` due to differences in structure offsets requiring changes in the assembly…


…well, an **optimizing** compiler might as well decide take your `FunctionSystem<Marker, update_frog_position>` and **inline** `update_frog_position`’s code into that `FunctionSystem`’s `run_unsafe`, mainly in order to reduce the call stack depth and make it easier to apply optimizations to the whole bunch at once. Which is **exactly** what is happening here, we are seeing a mix of Bevy and corMine code within the same compiled function!

Cool, so we _are_ on the right track!

…except, why is it still called `F` on the type signature, and not `some_cormine_function`?

## Singling out birds from the flock

Alright, let’s fan out further and see where this function is used:

![The cross-references view shows a data reference and a code reference for this function.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev8.png)

In particular, the data reference here is very interesting, because it reveals the [_vtable_](https://stackoverflow.com/a/3555290) for this particular instance of `FunctionSystem`:

![A view of the v-table for the instance of FunctionSystem, containing many pointers to many functions.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev9.png)

While there doesn’t seem to be an authoritative source on how Rust _vtables_ are laid out (and the layout [isn’t even stable](https://www.reddit.com/r/rust/comments/11okz75/comment/jbt969m/)), most sources I’ve seen on the topic (see for example [this design discussion](https://rust-lang.github.io/dyn-upcasting-coercion-initiative/design-discussions/vtable-layout.html) for the _Dyn upcasting coercion initiative_ , [cheats.rs](https://cheats.rs/#pointer-meta) and Raph Levien’s [Rust container cheat sheet](https://docs.google.com/presentation/d/1q-c7UAyrUlM-eZyTo1pd8SZ0qwA_wYxmPZVOQkoDmH4/edit#slide=id.p)) agree that a typical Rust _vtable_ , as of time of writing, is roughly ordered as follows:

  1. Pointer to the `drop` (destructor) function.
  2. Size and alignment of the structure.
  3. Pointers to method implementations.


Now, most method signatures on here don’t seem to really reveal us much else. But, what about the destructor?

Let’s see its name in full:

```
    core::ptr::drop_in_place$LT$bevy_ecs..system..function_system..FunctionSystem$LT$fn$LP$bevy_ecs..system..query..Query$LT$$RF$cormine..chunk..Chunk$GT$$C$bevy_ecs..change_detection..Res$LT$cormine..world..World$GT$$C$bevy_ecs..event..EventReader$LT$cormine..input..SaveEvent$GT$$RP$$C$cormine..world..process_save_events$GT$$GT$::h64e9704cb477196a
```

Wow, that sure is a function name! Let’s first clean this bad boy up:

```
    core::ptr::drop_in_place<bevy_ecs::system::function_system::FunctionSystem<fn(bevy_ecs::system::query::Query<&cormine::chunk::Chunk>, bevy_ecs::change_detection::Res<cormine::world::World>, bevy_ecs::event::EventReader<cormine::input::SaveEvent>), cormine::world::process_save_events>>::h64e9704cb477196a
```

That helps… but only a little. Here, let’s put some indentation:

```
    core::ptr::drop_in_place<
        bevy_ecs::system::function_system::FunctionSystem<
            fn(
                bevy_ecs::system::query::Query<&cormine::chunk::Chunk>,
                bevy_ecs::change_detection::Res<cormine::world::World>,
                bevy_ecs::event::EventReader<cormine::input::SaveEvent>
            ),
            cormine::world::process_save_events
        >
    >::h64e9704cb477196a
```

…yep! This in fact, not only contains the original name and module path of the Bevy system’s function (`cormine::world::process_save_events`), but also the fully self-contained query specification with which it was declared (the parameters of the `fn(...)`). This is **huge** , as it allows us to start looking for interesting systems to reverse-engineer. As a bonus, it also hints us that at main application crate being `cormine`.

…not that it wasn’t trivially guessable1. But hey, you never know when the project ends up being first named after a crazy cool secret codename or something and the executable itself being renamed after the fact.

## To survey a Bevy

Now that we know where to look, let’s do some recon! Now, because I have a free version of Binary Ninja, I cannot quite script a full find/replace, but despite this we can still do quite a lot. We want to search for all destructors for `FunctionSystem` because, as we previously discovered, they give us a _lot_ of information about the Bevy systems the program has; we’ll thus search for:

```
    core::ptr::drop_in_place$LT$bevy_ecs..system..function_system..FunctionSystem
```

![The many search results for the aforementioned search query, filling the search window.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_rev10.png)

Tip

Escape the `$` as `\$` when searching.

Now we can select all the coincidences, then copy and paste them into a text document. A bit of scripting takes care of cleanup and extraction:

```
    import re
    
    ESCAPE_MAP = {
        "SP": "@",
        "BP": "*",
        "RF": "&",
        "LT": "<",
        "GT": ">",
        "LP": "(",
        "RP": ")",
        "C": ", ",
        "u20": " ",
    }
    
    # Regular expression groups:
    # 1. System parameters
    # 2. Return value
    # 3. System name 
    system_regex = r"core::ptr::drop_in_place<bevy_ecs::system::function_system::FunctionSystem<fn\((.+)\)( -> .+)?, (.+)>>::h[a-f0-9]+"
    
    with open("symbols.txt", "r") as f:
        symbols = f.read()
    
    for symbol in symbols.split():
        for escape, replacement in ESCAPE_MAP.items():
            symbol = symbol.replace(f"${escape}$", replacement)
        symbol = symbol.replace("..", "::").replace(".", "-")
        match = re.match(system_regex, symbol)
        system_name = match.group(3) # output the system name only
        print(system_name)
```

And _presto_ : system names!

```
    bevy_asset::assets::Assets<bevy_animation::AnimationClip>::asset_events_condition
    bevy_animation::transition::expire_completed_transitions
    bevy_asset::assets::Assets<bevy_animation::AnimationClip>::track_assets
    bevy_animation::transition::advance_transitions
    bevy_animation::advance_animations
    bevy_animation::animate_targets
    bevy_ecs::event::event_update_condition
    bevy_asset::assets::Assets<()>::asset_events_condition
    bevy_asset::assets::Assets<()>::track_assets
    ...
```

And, knowing the main crate’s name is `cormine`, simple filtering gets us with a near-full list of corMine-specific systems:

```
    cormine::input::handle_special_keys
    cormine::make_camera
    cormine::debug::should_display_perf_stats
    cormine::ui::draw_ui
    cormine::handle_mesh_tasks
    cormine::debug::display_perf_stats
    cormine::input::hook_cursor
    cormine::terrain::load_chunks
    cormine::world::process_save_events
    cormine::debug::display_player_info
    cormine::material::process_block_texture
    cormine::debug::toggle_debug_ui_displays
    cormine::input::handle_lmb
    cormine::input::player_look
    cormine::input::handle_rmb
    cormine::input::handle_movement_keys
    cormine::queue_chunk_meshes
    cormine::highlight::update_selected_voxel
    cormine::player::player_move
```

(_Near_ -full, namely because this list doesn’t cover [exclusive systems](https://bevy-cheatbook.github.io/programming/exclusive.html), but this is way more than enough for what we need)

Look at that! So many interesting functions, and we didn’t even have to touch GDB yet! And on the output above, we can finally see the light: `cormine::input::handle_lmb`. We can then figure out that, it being part of the `input` module, `lmb` must stand for **l** eft **m** ouse **b** utton; seems like it’s what we are looking for!

A search for `handle_lmb` leads to the destructor of this system at `0x01ded22b`. Through the cross-references to it, we can quickly pivot to the _vtable_ for `cormine::input::handle_lmb` at `0x02690570` and, shortly after, find its `run_unsafe(...)` implementation at `0x01db7420`.

## A cheesy solution

Now that we have a ledge to hang onto within application code, we can finally pull out the debugger. Due to the large size of the binary, until now I was using an ARM64 Mac with plenty of RAM in order to run the initial analysis; however, we cannot really debug the provided x86_64 binary here. Fortunately, at the time I also had with me a Steam Deck with [Bazzite](https://github.com/ublue-os/bazzite) installed, which allowed me to quickly set up a reverse-engineering environment using the built-in Distrobox with the Kali Linux Docker image.

At corCTF, I used GDB with [GEF](https://github.com/hugsy/gef) locally on my Steam Deck to do this challenge; however, while writing this writeup I wanted to try Binary Ninja’s debugger instead. At first I tried to export the Binary Ninja analysis database to my Steam Deck, then use Binary Ninja’s built-in debugger locally; however, enabling the debugger seems to trigger a rebasing of the binary (i.e. the base address of the binary being different at runtime) and a complete re-analysis of the (huge) executable; this quickly makes my Steam Deck become unstable due to memory pressure.

I was ready to give up… until I found out Binary Ninja has [remote debugging](https://docs.binary.ninja/guide/remote-debugging.html) capabilities. This would allow me to have analysis run on my more powerful Mac while the actual binary runs on my Steam Deck.

Now, it took me a while to set up, and there were a few pitfalls I had to deal with (debug server mode didn’t work for me, some disassembly was really slow for some reason…), but what ended up working for me was to download the latest [Linux debug server](https://github.com/Vector35/debugger/releases/), then run the provided `lldb-server` in _gdbserver_ mode:

```
    $ debugger-linux/plugins/lldb/bin/lldb-server g 0.0.0.0:31337 -- cormine load cormine1.cms
```

Then, we can connect to it from the Binary Ninja menu: **Debugger** -> **Connect to Remote Process**. Since this is technically a _gdbserver_ , make sure to set the plugin to `gdb-remote` (I got stuck on this for quite a bit before I actually decided to read the `lldb-server` documentation… RTFM, I guess), then set connection parameters accordingly:

![A small window to configure the connection parameters to connect to a remote debugger. The connection plugin, alongside IP address and port to connect, can be specified.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal1.png)

And presto, we are connected.

Let’s get to business; we’ll first set a breakpoint at `0x01db7420`:

![A view of the Binary Ninja debugger, showing the code decompilation output front and center, and the current values of the CPU registers at one side. A breakpoint is placed on the function being targeted.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal2.png)

Then we continue execution…aaaaand the program triggers the breakpoint **every frame** , even if I don’t press the left click button. Why?

Let’s dig a bit further. We can retool our previous script a little bit to print more information about this Bevy system:

```
    # ...
    
    for symbol in symbols.split():
        for escape, replacement in ESCAPE_MAP.items():
            symbol = symbol.replace(f"${escape}$", replacement)
        symbol = symbol.replace("..", "::").replace(".", "-")
        match = re.match(system_regex, symbol)
        system_params = match.group(1).replace(",", ",\n    ")
        system_return_value = match.group(2)
        system_name = match.group(3)
        if system_name == "cormine::input::handle_lmb":
            print(f"fn {system_name}({system_params}) -> {system_return_value}")
```

Here’s the full signature for `cormine::input::handle_lmb`:

```
    fn cormine::input::handle_lmb(
         bevy_ecs::system::commands::Commands,
         bevy_ecs::change_detection::Res<bevy_input::button_input::ButtonInput<bevy_input::mouse::MouseButton>>,
         bevy_ecs::change_detection::Res<cormine::highlight::SelectedVoxel>,
         bevy_ecs::change_detection::Res<cormine::world::World>,
         bevy_ecs::system::query::Query<&mut cormine::chunk::Chunk>
    ) -> None
```

The key here is to understand how user input is collected through the use of `Res<ButtonInput<...>>`. As we can see from [this Bevy example](https://github.com/bevyengine/bevy/blob/7f658cabf7abd98d52bd94db8bd7fc788f49856a/examples/input/keyboard_input.rs), detection of whether a key is pressed or not is handled _within_ the application logic, not as part of the query. Barring that, the system runs every frame so that those checks are kept updated accordingly.

Therefore, we’ll have to dig a bit deeper within the function in order to find a suitable breakpoint location. After some trial and error, a sanity check at `0x01db7b13` is found to be a reliable breakpoint location to stop whenever the **left mouse button** is pressed.

![The Binary Ninja debugger again, showing a breakpoint being placed at the aforementioned address. The code is checking if the RSI register equals 0; if so, the program seems to panic with a Selected voxel is not in chunk error.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal3.png)

Now, time to count conditional jumps.

As I spawn on top of the mysterious monolith of unbreakable blocks, I first try to place and break a (breakable) block; my thinking is that by doing so and then stepping through the function one instruction at a time, I would able to establish a “behavioral baseline” of what the function does based on which conditional branches (`jz`/`jnz`/…) are taken and which ones aren’t. After a while, execution quickly devolves a labyrinth of function calls as the game starts processing the removal of the block, at which point I decide to fold and hand control over back to the program.

Then, I repeat the process trying to break one of the unbreakable blocks forming the monolith. I quickly notice that, on this particular case, the function swiftly returns control to the caller instead. Once again I trace the behavior of the conditional branches, and I find that execution starts to diverge at the 10th branch instruction, located at `0x01db767c`.

![The Binary Ninja debugger again, highlighting the decompiled code around a conditional branch.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal4.png)

After doing a few more tests, I confirm this check to be tied to whether or not a block is unbreakable; when a block is unbreakable, the jump is not taken and a function return shortly follows.

![The same code as in the previous image, but in disassembly form. The check is implemented as a JNE \(Jump if Not Equal\) instruction, and it is shown that, were the jump not taken, the execution would quickly return control to the caller.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal5.png)

We can examine the memory pointed at by the `rbp` register before the jump happens to see how blocks are laid out in memory at this stage. For example, here’s me trying to break an unbreakable block:

![Memory view of the memory pointed at by the RBP register when checking the bedrock block, showing a small cluster of twelve fives surrounded by bytes with the value 255.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal6.png)

Meanwhile, stone and grass blocks have this instead:

![Memory view of the memory pointed at by the RBP register when checking the stone block, a single byte with value 0 followed by bytes with the value 255.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal7.png) ![Memory view of the memory pointed at by the RBP register when checking the grass block, a single byte with value 1 followed by bytes with the value 255.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal8.png)

The condition is indeed checking that the value obtained is not 5, so it seems that unbreakable blocks have an type ID of 5, whereas stone and grass blocks have IDs of 0 and 1 respectively; eventually, I figured out the five blocks the player has available on the hotbar have type IDs 0 to 4, and unbreakable blocks use the otherwise unused ID 5; thus:

  * Stone: 0
  * Grass: 1
  * Water: 2
  * Ice: 3
  * Dirt: 4
  * Bedrock (unbreakable): 5


We can try to patch this conditional jump into an unconditional jump; Binary Ninja provides quick actions to do so.

![Right-clicking on the instruction to patch on Binary Ninja, we can go to the Patch dropdown menu and select various quick actions to patch the instruction such as Always branch and Invert branch.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal9.png)

Then, we can export the resulting patched binary. Upon executing it with the loaded save, it indeed seems that **we can now break** unbreakable blocks, and so…

There should have been a video here but your browser does not seem to support it. 

(Don’t mind the video quality, just trick your brain into thinking you’re watching a 2010 Minecraft YouTube video by a small-time content creator providing you with the sickest tutorial on how to break bedrock [no clickbait])

![A screenshot of the game where the player stands inside of the broken-into box, where the flag string hides. It is constructed from stone blocks, and is also shown backwards.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine_chal10.png)

…now we just gotta read the flag backwards.

Flag

`corctf{w4llh4cks}`

# corMine 2 - Revelations

Note

I wasn’t able to solve this one within corCTF’s time limit (although I was pretty close!). Instead, this part of the writeup tries to detail a couple of creative ways _one_ could go about solving this challenge that I managed to fully flesh out after the fact. By discussing these techniques, I hope someone else can find an use for them elsewhere for fun and _epic pwn_ :)

…and yes, I did way too much overthinking. My recommendation if you wanna try this challenge yourself is that you take a deep breath and _actually_ stare at the decompiler output of a bit; it simplifies a lot of the process I’m about to explain.

> We’ve hidden a flag within this save file, but decided that you’re not ready for it: it’s been permanently removed - don’t try to find it!!

For the next challenge, we are given another save: `cormine2.cms`. Opening this save with the game executable reveals us yet another mysterious monolith, this time made of stone.

![The top of a mysterious monolith, this time lined with plain stone blocks.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_1.png) ![A far-off view of the mysterious stone monolith, emphasizing its massive size in contrast to the landscape around it. It seems to somewhat overlap with the mountain next to it.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_2.png)

After some manual work done breaking down the monolith, it became clear the flag wasn’t within it. But if it isn’t within the box, where is it?

Let’s try to analyze the save format and see where this leads us.

## Breaking into the DWARF Fortress

Before diving into the hard and cold reverse-engineering, I first did some forensics on the provided save. `strings` lead to nothing, nor did `binwalk` or `foremost`, so we might as well be dealing with either encrypted data and/or a bespoke custom save format. Or both!

If we open up the `cormine2.cms` save file in a hex editor we can see there’s certainly some kind of pattern in how bytes that use the most-significant bit are distributed; however, there doesn’t seem to be anything else we can conclude just from a look at the file.

![A colored hexadecimal view of the bytes within the cormine2.cms save file, highlighting bytes in different ranges with different colors. Through this view, it becomes clear that bytes of value lower than 128 seem strangely clustered around three soft vertical lines in the file.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_dwarf1.png)

Is it then time to start staring into the code? Not yet! We happen to be able to write our own saves using the game’s save functionality (`F9`). We can use this to write some “test saves” and try to analyze them to make educated guesses about how the save format works.

First, I tried to generate a new world a few times, then save it without changing anything. Invariably, all files came up at about 6 bytes, and the only information that changed was the first 4 bytes.

```
    $ xxd gamea.cms
    00000000: e62e 59cb 1010                           ..Y...
    $ xxd gameb.cms
    00000000: d66d 16af 1010                           .m....
    $ xxd gamec.cms
    00000000: 4b06 e4e8 1010                           K.....
```

Since 6 bytes is by no means enough to store all of the individual blocks that are generated, and considering that the landscape doesn’t change every time we load up a given save, I found it safe to make a few educated guesses:

>   1. **The automatically-generated landscape of every world is generated with an algorithm that uses a seed.**
>   2. **That seed is stored onto the save, in order to generate the same world every time the save is loaded.**
> 


Let’s keep going. Now, we’ll generate a new world, and place a **single block** anywhere before saving. What’s the result?

```
    00000000: 6ac3 be08 1010 e0f4 8bee 7d99 ecd8 8278  j.........}....x
    00000010: 97f0 9cfa 7dbd                           ....}.
```

Alright, so now the file has grown to 22 bytes. Breaking a single block also seems to have the same effect; this makes sense if you think of breaking a block as “changing it to the block type corresponding to air/nothing”.

If we repeat this with more blocks, we can also see the file size keeps growing linearly…

Blocks placed | File size (bytes) | Breakdown  
---|---|---  
0 | 6 | 6 + 0  
1 | 22 | 6 + (1 block * 16 bytes)  
2 | 38 | 6 + (2 blocks * 16 bytes)  
3 | 54 | 6 + (3 blocks * 16 bytes)  
4 | **69?** | 6 + (3 blocks * 16 bytes) **\- 1 byte ???**  
  
…but only somewhat. For some reason, the sizes don’t seem to align at times. Some blocks add more data to the file, some add less data. We can also see this if we try the 1 block experiment multiple times:

```
    $ xxd gamed.cms 
    00000000: 6ac3 be08 1010 e0f4 8bee 7d99 ecd8 8278  j.........}....x
    00000010: 97f0 9cfa 7dbd                           ....}.
    $ xxd gamee.cms 
    00000000: 3d31 292c 1010 88d1 b6ae 04e1 a0f6 bb05  =1),............
    00000010: a9b1 e55c 38                             ...\8
    $ xxd gamef.cms 
    00000000: 3475 1b84 1010 f1ad cde9 78e6 b5e0 c500  4u........x.....
    00000010: 88c6 dadf 0021                           .....!
```

Hm, there may be some compression going on, then. Also, we cannot quite see any obvious place where, say, the block type would be stored; we’d know because we previously established when solving the previous challenge that the type of a solid block would be somewhere between 0 and 5. There’s could be some obfuscation or encryption going on, but we cannot say for sure quite yet.

But we can be sure of this:

>   3. **Every changed block is stored individually.**
> 


This gives me one theory about where the flag could hide: it could be encoded as yet another block pattern, as was the first flag, only for it to be overwritten by the massive stone monolith later on the file. One way to attack this problem could be to truncate the file into only having, say, the first N blocks; however, the fact that each block’s individual size seems to somewhat change leaves me uneasy on whether that is even possible.

Ok, let’s start looking at program code. The Bevy system `cormine::terrain::load_chunks` seems like a good candidate to start looking, so we search for `cormine..terrain..load_chunks`, find the Drop implementation, pivot into the vtable and look at the `run_unsafe` function, easy peasy!

…except for some reason there are 3 vtables associated with the exact same Drop implementation. Wait, what?

![A view into the cross-references of this function on Binary Ninja shows three data references, each corresponding to a different v-table.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_dwarf2.png)

Furthermore, looking at the vtables themselves, it seems that they also reference very similar functions, but the implementations of some functions such as `run_unsafe` differ! We can tell from the hash at the end of the function changing between each implementation:

```
    ...bevy_ecs..system..system..System$GT$::is_exclusive::h0ac4e8febec8c31d
    ...bevy_ecs..system..system..System$GT$::has_deferred::h241368ad6d9f3e63
    ...bevy_ecs..system..system..System$GT$::run_unsafe::h4e4d5b51f40928bc
    bevy_ecs::system::system::System::run::hf750d1afdc6910e2
    ...bevy_ecs..system..system..System$GT$::apply_deferred::h0d8bf0fab0d4f725
```

```
    ...bevy_ecs..system..system..System$GT$::is_exclusive::h0ac4e8febec8c31d
    ...bevy_ecs..system..system..System$GT$::has_deferred::h241368ad6d9f3e63
    ...bevy_ecs..system..system..System$GT$::run_unsafe::h06b810d262677ad4
    ...bevy_ecs::system::system::System::run::h7f18147a497281cd
    ...bevy_ecs..system..system..System$GT$::apply_deferred::h0d8bf0fab0d4f725
```

```
    ...bevy_ecs..system..system..System$GT$::is_exclusive::h0ac4e8febec8c31d
    ...bevy_ecs..system..system..System$GT$::has_deferred::hd802949ae17c8efd
    ...bevy_ecs..system..system..System$GT$::run_unsafe::h4ac9ac52b106cb49
    ...bevy_ecs::system::system::System::run::h5285f6a4bde10b28
    ...bevy_ecs..system..system..System$GT$::apply_deferred::hbfa5f4ab118b45aa
```

A truly strange and fascinating compiler behavior. But now we have to reverse-engineer more code, I suppose. Well, shucks.

…ok, but I am a bit too lazy. Let’s use one of the oldest tricks in the book: tracing the use of `libc` imports such as `open` and `read`. Let’s look into the latter now:

![A view into the cross-references for the libc read function shows several functions using it.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_dwarf3.png)

Hey, wait a second, that is a Bevy system that directly uses this call! Looking at it’s vtable, it’s one of the implementations of `cormine::terrain::load_chunks`, so it was indeed somewhere in there.

But also, just below it, there’s a completely different Rust crate: `cormine_shared`… with a `save` module! Seems like we hit jackpot. Now, the full symbol name (with demangling applied as previously explained) is:

```
    cormine_shared::save::Serializer<Cursor>::read_leb128_signed::he32d2bd5e2a4a56b
```

Huh, “`leb128`”? That almost sounds like an cryptography algorithm. Yet another quick search aaaand… not quite; [according to Wikipedia](https://en.wikipedia.org/wiki/LEB128):

> LEB128 or Little Endian Base 128 is a variable-length code compression used to store arbitrarily large integers in a small number of bytes. LEB128 is used in the DWARF debug file format and the WebAssembly binary encoding for all integer literals.

Ok, so it’s a way to encode integers, cool! The fact that it’s variable-length may explain why the save’s size doesn’t grown perfectly linearly as we keep changing blocks. If we read a little closer, we can also notice that the most significant bit of each byte that forms a LEB128 number is used to tell the decoder when to stop reading (the decoder keeps reading bytes until it finds one where the MSB is 0), which can explain the somewhat non-random distribution of bytes lower than `0x7F` in the save file.

And, if we look at the callers for this function, it so happens that its only user is the `cormine::terrain::load_chunks` Bevy system we just uncovered, calling `read_leb128_signed` multiple times across its logic. So, here we can start speculating on some points:

  * The `cormine::terrain::load_chunks` Bevy system (or some other function that got inlined within it) seems to handle save reading logic, due to its connection to `read_leb128_signed`, which itself seems in turn clearly associated with save logic thanks to debug information.
  * The save format likely uses LEB128 numbers in an **unencrypted** form, as it seems to directly read from the file (as we found from it using `read` directly on a file descriptor) and nothing on the decompiler output for `read_leb128_signed` suggests to me there’s any weird encryption going on.
  * `read_leb128_signed`’s purpose is likely to read a single LEB128-encoded number at a time; it would be odd otherwise for the function to be called at multiple places.


This gets us somewhat closer to understanding the file format… but not close enough. And the implementation of `cormine::terrain::load_chunks` looks way too large. Don’t wanna reverse that just yet, too lazy. Can we still figure out how the save format works?

Well, yes! A cursory look at both functions seems to suggest `read` is called multiple times across this Bevy system’s implementation, with different static sizes.

![A search for read syscalls within the decompilation output of this Bevy system shows 6 results.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_dwarf4.png)

This suggests the save is not read all at once into memory, but instead is gradually deserialized, with each call site for `read` corresponding to a different kind of data being read. And given `read` happens to be a Linux syscall, a fairly powerful way to make sense of the format becomes possible.

## Tracing our way into the save format

`strace` is a wonderful, if sometimes flawed tool. It mainly allows its user to hook into a program and log any usage of a Linux syscall, optionally printing out the arguments it was called with, the return values (including values returned by reference), and even call stack traces. Together, all these capabilities make it almost a breeze to profile a program’s usage of OS resources.

Now, why is this useful? Well, I could explain it now, but instead I’ll let `strace` do the talking here. We’ll ask it to run the game as it loads the `cormine2.cms` file from the previous challenge; while the game runs, `strace` will log any calls to the `open*`, `read` and `close` syscalls (`-e openat,open,close,read`) and to print the arguments (`-v -s 2048`) along with corresponding stack traces for each call (`-k`), while also following process forks (`-f`). Having `strace` fetch the backtraces comes with a large performance hit 2, but that won’t be a problem, we just need the program to load the save once, and this doesn’t require any interaction with the program itself. The output will also be massive, so we’ll save it to a file for later analysis.

```
    $ strace -f -v -k -s 2048 -e openat,open,close,read ./cormine load cormine2.cms 2> out.log
```

The program now seems to take ages to start. At this point I left it running and had some dinner, and when I came back I just `Ctrl`+`C` the process.

Ok, let’s take a look at the `strace` output-

```
    $ ls -lah out.log
    -rw-r--r--. 1 deck deck 106M Jul 28 22:00 out.log
```

…ok, well, its _quite large_ size may make casual examination somewhat difficult.

Tip

Here’s a nifty Linux sysadmin trick if you ever find yourself in a similar situation: if you use the `less` command to page your output, you can press `/`, then type in a search string, then press `Enter`. The `less` command is fairly efficient when it comes to reading large files, so this is an easy way to sift through large files such as logs. [Depending on your system](https://unix.stackexchange.com/a/453238) this may or may not support regular expressions. Also try `:` for jumping to a specific line number!

So, we can still search for `cormine2.cms` on this file, and we should land directly on the corresponding `open`-whatever syscall:

![An extract of the output of the strace tool being applied to the game executable, showing how the game reads the save file by interacting with the Linux operating system through syscalls.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_strace1.png)

There are some spurious errors from the audio system while the program is debugged3, but if we squint hard enough… look at that, the file structure is practically revealing itself to us! Just within the first few bytes of `cormine2.cms`:

  1. The file is opened at instruction address `0x1d98269`.
[code] [pid 125685] openat(AT_FDCWD, "cormine2.cms", O_RDONLY|O_CLOEXEC) = 22
          > /usr/lib/x86_64-linux-gnu/libc.so.6(__open64+0xc8) [0xfe198]
          > /var/home/deck/Downloads/cormine-1/cormine(std::sys::pal::unix::fs::File::open_c+0xf9) [0x228d719]
          > /var/home/deck/Downloads/cormine-1/cormine(<bevy_ecs::system::function_system::FunctionSystem<Marker,F> as bevy_ecs::system::system::System>::run_unsafe+0x309) [0x1d98269]
```

  2. Once opened, 4 bytes are first read at `0x1d9816a`.
[code] [pid 125685] read(22, ")\6\341\203", 4) = 4
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(<bevy_ecs::system::function_system::FunctionSystem<Marker,F> as bevy_ecs::system::system::System>::run_unsafe+0x20a) [0x1d9816a]
```

  3. Then, 2 bytes are read individually at `0x1d981f8` and `0x1d982d8`.
[code] [pid 125685] read(22, "\22", 1)         = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(<bevy_ecs::system::function_system::FunctionSystem<Marker,F> as bevy_ecs::system::system::System>::run_unsafe+0x298) [0x1d981f8]
         [pid 125685] read(22, "\n", 1)          = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(<bevy_ecs::system::function_system::FunctionSystem<Marker,F> as bevy_ecs::system::system::System>::run_unsafe+0x378) [0x1d982d8]
```

  4. Next up, 15 **bytes** worth of LEB128 data are read.
[code] [pid 125685] read(22, "\325", 1)        = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(cormine_shared::save::Serializer<Cursor>::read_leb128_signed+0x96) [0x1dcd746]
         [pid 125685] read(22, "\345", 1)        = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(cormine_shared::save::Serializer<Cursor>::read_leb128_signed+0x96) [0x1dcd746]
          > unexpected_backtracing_error [0x700]
         [pid 125685] read(22, "\350", 1)        = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(cormine_shared::save::Serializer<Cursor>::read_leb128_signed+0x96) [0x1dcd746]
          > unexpected_backtracing_error [0xe00]
         ...
```

Unfortunately, the call stack collected by `strace` doesn’t seem to extend enough here to identify how many LEB128 **numbers** are being read. But this will not be a problem, as we’ll soon see.

  5. Then, back into the Bevy system’s main logic, 1 byte is read at `0x1d9891a`.
[code] [pid 125685] read(22, "o", 1)           = 1
          > /usr/lib/x86_64-linux-gnu/libc.so.6(read+0x4c) [0xfea5c]
          > /var/home/deck/Downloads/cormine-1/cormine(<bevy_ecs::system::function_system::FunctionSystem<Marker,F> as bevy_ecs::system::system::System>::run_unsafe+0x9ba) [0x1d9891a]
```

  6. Steps **4** and **5** then seem to repeat indefinitely.


This information is **really** good to have, since we can now make reasonably informed guesses about how the data format works; namely, it’s clear steps **2** and **3** seek to read a header of some kind, whereas we can safely guess steps **4** and **5** are done to read each block from the file.

Furthermore, we can start to make educated guesses about what each piece of data could be. For example, the seed could very well be part of the first 4 bytes, as many popular random number generators such as the [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) and [xorshift32](https://en.wikipedia.org/wiki/Xorshift) use a 32-bit seed. Additionally, we do know the block type is encoded as a small number, so the last byte in the block data may encode the block type.

So here’s a mental model of the format so far:

  * Header 
    * 4 bytes: seed?
    * 1 byte: ???
    * 1 byte: ???
  * Block data: list of blocks 
    * A bunch of LEB128 data
    * 1 byte: block type?


This might be enough to start writing a basic **parser**! So let’s get to it.

## The beginnings of a parser

We’ll write the parser using Python, employing [`pwntools`](https://github.com/Gallopsled/pwntools) for quickly parsing byte sequences into integers and the [`leb128`](https://pypi.org/project/leb128/) library for parsing LEB128 numbers.

First off, let’s tackle the header:

```
    import leb128
    import sys
    from pwn import *
    
    with open(sys.argv[1], "rb") as f:
        seed = u32(f.read(4), endian="big")
        print(f"seed?: {seed}")
        unk1 = u8(f.read(1), endian="big")
        unk2 = u8(f.read(1), endian="big")
        print(f"unk1: {unk1}")
        print(f"unk2: {unk2}")
```

The only unknown we have to solve before we begin parsing is how many LEB128 numbers are actually in a single block. Now, since LEB128 integers have a variable length, the library we are using for parsing them returns the number of bytes read alongside the parsed number. Since we know that the game read 15 bytes worth of LEB128 to read what we presume is the first block on `cormine2.cms`, we can try to read LEB128 numbers on this file with our parser until we match this number.

So here’s one number:

```
    with open(sys.argv[1], "rb") as f:
        # ...
        d1, n1 = leb128.i.decode_reader(f)
        print(f"Read {d1} using {n1} bytes")
```

```
    seed?: 688316803
    unk1: 18
    unk2: 10
    Read 750400213 using 5 bytes
```

Ok, not quite enough. How about 2?

```
    Read 750400213 using 5 bytes
    Read 509639610 using 5 bytes
```

Almost. How about 3?

```
    Read 750400213 using 5 bytes
    Read 509639610 using 5 bytes
    Read 210383163 using 5 bytes
```

15 bytes in total, so spot on! Now, let’s read a single byte for what’s probably the block type.

```
    with open(sys.argv[1], "rb") as f:
        # ...
        block_type = u8(f.read(1), endian="big")
        print(f"block_type?: {block_type}")
```

```
    block_type?: 111
```

And tie everything off with a loop:

```
    import leb128
    import sys
    from pwn import *
    
    with open(sys.argv[1], "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)
        seed = u32(f.read(4), endian="big")
        print(f"seed?: {seed}")
        unk1 = u8(f.read(1), endian="big")
        unk2 = u8(f.read(1), endian="big")
        print(f"unk1: {unk1}")
        print(f"unk2: {unk2}")
        i = 1
        while f.tell() < file_size:
            print(f"Block #{i}")
            d1, n1 = leb128.i.decode_reader(f)
            print(f" Read {d1} using {n1} bytes")
            d2, n2 = leb128.i.decode_reader(f)
            print(f" Read {d2} using {n2} bytes")
            d3, n3 = leb128.i.decode_reader(f)
            print(f" Read {d3} using {n3} bytes")
            block_type = u8(f.read(1), endian="big")
            print(f" block_type?: {block_type}")
            i += 1
```

We run it on `cormine2.cms`, aaaand…

```
    seed?: 688316803
    unk1: 18
    unk2: 10
    Block #1
     Read 750400213 using 5 bytes
     Read 509639610 using 5 bytes
     Read 210383163 using 5 bytes
     block_type?: 111
    Block #2
     Read 1367663539 using 5 bytes
     Read 1154360776 using 5 bytes
     Read 762612651 using 5 bytes
     block_type?: 168
    Block #3
     Read -224813911 using 5 bytes
     Read -1492939015 using 5 bytes
     Read -1515736888 using 5 bytes
     block_type?: 180
    Block #4
     Read 828603333 using 5 bytes
     Read -1207076910 using 5 bytes
     Read 1984705747 using 5 bytes
     block_type?: 158
    ...
```

Ok, so everything seems to be reading fairly evenly. Comparing the LEB128 read sizes with those on the `strace` output, they do seem to match. I was able to verify this with blocks `#22` and `#23`, where there are **14 bytes** worth of LEB128 numbers instead of 15:

```
    ...
    Block #22
     Read 1389809728 using 5 bytes
     Read -6950871 using 4 bytes
     Read 1080931495 using 5 bytes
     block_type?: 109
    Block #23
     Read -136368784 using 5 bytes
     Read 22042346 using 4 bytes
     Read 658741446 using 5 bytes
     block_type?: 211
    ...
```

So it definitely seems right that each block uses 3 LEB128 numbers. Furthermore, this would make sense; this being a 3D game, using 3 numbers would definitely make sense to encode the position of each block in a 3-dimensional coordinate system.

…except there’s a problem, which you may have noticed already: the output we get is still complete garbage.

At this point, since all the numbers looked pretty random, I suspected there was some additional encryption going on _after_ this step, but looking at the decompilation output for `cormine::terrain::load_chunks` still gave me migraines. But then, how can we even do anything here? Is all hope lost?

Well, no, because now we _know_ where the blocks are stored. The real question is, _is the game going to miss them?_

## Time-traveling by save truncation

First off, let’s count how many blocks the `cormine2.cms` save has:

```
    import leb128
    import sys
    from pwn import *
    
    with open(sys.argv[1], "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)
        seed = u32(f.read(4), endian="big")
        unk1 = u8(f.read(1), endian="big")
        unk2 = u8(f.read(1), endian="big")
        i = 1
        while f.tell() < file_size:
            d1, n1 = leb128.i.decode_reader(f)
            d2, n2 = leb128.i.decode_reader(f)
            d3, n3 = leb128.i.decode_reader(f)
            block_type = u8(f.read(1), endian="big")
            i += 1
    
    print(f"File has {i - 1} blocks")
```

```
    File has 68594 blocks.
```

So, let’s have a look once again at the huge floating stone monolith:

![A screenshot of the game shows a far-off view of the mysterious stone monolith, emphasizing its massive size in contrast to the landscape around it. It seems to somewhat overlap with the mountain next to it.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_2.png)

Ok, here’s the pitch: what happens if we read the file, and then write it back, but **only with the first 30000 blocks**? We can parse everything into a bunch of variables, then rewrite everything back in order onto a separate file:

```
    import leb128
    import sys
    from pwn import *
    
    blocks_to_keep = 30000
    seed = 0
    unk1 = 0
    unk2 = 0
    blocks = []
    with open(sys.argv[1], "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)
        seed = u32(f.read(4), endian="big")
        unk1 = u8(f.read(1), endian="big")
        unk2 = u8(f.read(1), endian="big")
        while len(blocks) < blocks_to_keep:
            d1, n1 = leb128.i.decode_reader(f)
            d2, n2 = leb128.i.decode_reader(f)
            d3, n3 = leb128.i.decode_reader(f)
            block_type = u8(f.read(1), endian="big")
            blocks.append((d1, d2, d3, block_type))
    
    with open(f"trunc_{blocks_to_keep}_{sys.argv[1]}", "wb") as f:
        f.write(p32(seed, endian="big"))
        f.write(p8(unk1, endian="big"))
        f.write(p8(unk2, endian="big"))
        for d1, d2, d3, block_type in blocks:
            f.write(leb128.i.encode(d1))
            f.write(leb128.i.encode(d2))
            f.write(leb128.i.encode(d3))
            f.write(p8(block_type, endian="big"))
```

Ok, now we load this save onto the game aaaand…

![The large stone monolith from the previous screenshot now appears with less than half of its original size; as a result, it no longer overlaps with the mountain.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_truncation1.png)

Woah! The monolith became smaller, and the game didn’t even complain! Ok, so this attack against corMine save files seems very practical. I’ll just make some adjustments to that number, the monolith will disappear, and the flag shall appear magically!

So here’s the file truncated to only 300 blocks:

![The large stone monolith has completely disappeared, leaving nothing but a clear view of the sky in its wake.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_truncation2.png)

200 blocks, same thing. So is 100 blocks. I still don’t see the flag.

Uh oh. This is not good.

It definitely must be hidden in there, though; as the whole file reads correctly, we don’t have a reason yet to think it’s somewhere else other than the blocks. So let’s not panic; we can do a _bit_ of bruteforce and, starting from the `cormine2.cms` save having no blocks, make a bunch of new saves where we slowly start adding its blocks back.

```
    # ...
    from itertools import islice
    
    # ...
    
    for i in range(1, 12):
        file_name = f"trunc_{i}_{sys.argv[1]}"
        with open(file_name, "wb") as f:
            f.write(p32(seed, endian="big"))
            f.write(p8(unk1, endian="big"))
            f.write(p8(unk2, endian="big"))
            for d1, d2, d3, block_type in islice(blocks, i):
                f.write(leb128.i.encode(d1))
                f.write(leb128.i.encode(d2))
                f.write(leb128.i.encode(d3))
                f.write(p8(block_type, endian="big"))
        print(f"Written {i} blocks to {file_name}")
```

```
    Written 1 blocks to trunc_1_cormine2.cms
    Written 2 blocks to trunc_2_cormine2.cms
    Written 3 blocks to trunc_3_cormine2.cms
    Written 4 blocks to trunc_4_cormine2.cms
    Written 5 blocks to trunc_5_cormine2.cms
    Written 6 blocks to trunc_6_cormine2.cms
    Written 7 blocks to trunc_7_cormine2.cms
    Written 8 blocks to trunc_8_cormine2.cms
    Written 9 blocks to trunc_9_cormine2.cms
    Written 10 blocks to trunc_10_cormine2.cms
    Written 11 blocks to trunc_11_cormine2.cms
```

…aaaalright, guess we gotta check out all of those saves. Could be worse.

However, on this particular case, there’s… something. On `trunc_1_cormine2.cms`, we can suddenly find a lonely **ice** block floating in mid-air:

![A lonely ice block is contrasted against the clear skies.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_truncation3.png)

But on `trunc_2_cormine2.cms`, the block disappears…

Then, on `trunc_3_cormine2.cms`, a block appears again, only for it to disappear on `trunc_4_cormine2.cms`. I suspected they weren’t quite the same blocks, so I did some in-game measurements. Here’s the difference between `cormine2.cms` truncated to 1 block, and truncated to 11 blocks:

![A man-made construction meant to show the height of the single white block that appears with the save file truncated to one block.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_truncation4.png) ![A man-made construction meant to show the height of the single white block that appears with the save file truncated to eleven blocks. In comparison to the former, it appears two blocks lower.](https://nnub.es/blog/en/ctf/corctf/2024/cormine/assets/corctf2024_cormine2_truncation5.png)

So they are indeed different blocks; at the very least, they’re at different heights. This seems to be a good candidate to be the flag, given the blocks that appear are colored differently from other blocks. After examining all of the generated saves, we can start figuring out what’s going on: a block that encodes the flag is encoded, then another block is placed that “deletes” the previous block. Thus, blocks #1, #3, #5, … contain the flag, but blocks #2, #4, #6… keep deleting the previous block that was placed. Given it seems to be encoded as a block itself, that means a block “delete” must be encoded as “set a block to something that looks empty”. It is not uncommon for voxel-based games to encode the existence of nothing as a block type in and of itself; for example, Minecraft [has the block type `air`](https://minecraft.wiki/w/Air) for this purpose.

In order to read the flag, it seems we’ll need to figure out a way to otherwise “negate” the instruction that deletes the block. Let’s try skipping the “delete” block in the middle while reading `cormine2.cms`:

```
    # ...
    with open(sys.argv[1], "rb") as f:
        # ... read header ...
        i = 0   # new!
        while len(blocks) < blocks_to_keep:
            d1, n1 = leb128.i.decode_reader(f)
            d2, n2 = leb128.i.decode_reader(f)
            d3, n3 = leb128.i.decode_reader(f)
            block_type = u8(f.read(1), endian="big")
            if i % 2 == 0:   # skip every other block
                blocks.append((d1, d2, d3, block_type))
            i += 1
```

Then we’ll take the resulting `trunc_3_cormine2.cms`, which will contain the first, third and fifth block, and load it into the game. Hopefully flag?

```
    $ cormine load trunc_3_cormine2.cms
    ...
    thread 'Compute Task Pool (3)' panicked at src/terrain.rs:170:51:
    called `Result::unwrap()` on an `Err` value: invalid voxel kind `227`
    note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
    Aborted (core dumped)
```

Well, no, the game now just crashes because the voxel data got corrupted. That can mean whatever is reading the file expects blocks to be in a specific position. Well shucks, so it seems we cannot do much other than stare at the file reading logic until something comes to mind.

## If nobody got me, I know the oracle got me

…

…wait a second.

```
    called `Result::unwrap()` on an `Err` value: invalid voxel kind `227`
```

This is an… interesting error. It not only tells us that the save file had a block with an invalid block type, it also tells us what block it tried to read before crashing. Is it anywhere on the file? Well, 227 is `0xE3` in hexadecimal, so a quick byte search should turn up the value, right?

…except that value doesn’t even appear anywhere on the file we created, `trunc_3_cormine2.cms`. Do you see it? Because I sure don’t:

```
    00000000: 2906 e183 120a d5e5 e8e5 02ba f781 f301  )...............
    00000010: bbe2 a8e4 006f a9b9 e694 7ff9 9d8e b87a  .....o.........z
    00000020: c8e1 9ead 7ab4 aab6 bb8b 7cde 92d5 b805  ....z.....|.....
    00000030: a9ba f28e 7dd3                           ....}.
```

Can we figure out what byte in the file triggers it? Sure, we can do yet another `strace` and figure out at which point it stops reading. Doing this shows the panic triggers as soon as it finishes reading the **last byte** of the **second block**. I think we can reasonably say now that lonely last byte of every block does in fact encode the **block type** … somehow. However, if we examine `trunc_3_cormine2.cms` with our save reader, we get this:

```
    seed?: 688316803
    unk1: 18
    unk2: 10
    Block #1
     Read 750400213 using 5 bytes
     Read 509639610 using 5 bytes
     Read 210383163 using 5 bytes
     block_type?: 111
    Block #2
     Read -224813911 using 5 bytes
     Read -1492939015 using 5 bytes
     Read -1515736888 using 5 bytes
     block_type?: 180
    Block #3
     Read -1049699542 using 5 bytes
     Read 1461012830 using 5 bytes
     Read -774070999 using 5 bytes
     block_type?: 211
```

And 180 (`0xB4`) sure isn’t 227 (`0xE3`). So we are definitely dealing with some transformation applied to the save before it is processed, but after the basic structure is read, probably some sort of **encryption**. Can we figure it out?

Sure, let’s try to figure this mysterious transformation in a _black-box_ way. We can do this by **corrupting** the values on the save file ourselves a few times, then by using the previous error as an **oracle** we can record what the **result** of the transformation is, then see if we can guess any algorithm behind it. Let’s call the mysterious transformation `y = f(x)` where `x` is the data from the file and `y` is the data the game reads (and shows on the error).

Tip

What is an **oracle** , in this context? Well, I was about to write an explanation here, but I don’t think I can be as funny and concise as Thomas Pornin is on [this Security StackExchange answer](https://security.stackexchange.com/a/10621) to the same question:

> An oracle is an individual who knows the personal cell phone number of a god. This enables him (or her) to obtain some information which is usually considered as out of reach of mere mortals, such as glimpses of the future. In cryptography, that’s the same, except that no deity is involved: an oracle is any system which can give some extra information on a system, which otherwise would not be available.

Why do I think this is an oracle? Well, it gives us the value of the block type that the game tried to read **after** potentially applying any strange transformations to it. So if we were dealing with encryption, the game just gave us a bunch of (corrupted) **plaintext** , which is not really something we are supposed to see… but we can use, as we’ll soon see :)

We’ll need all the information we can get, so this time we’ll corrupt the information of the **first block** ; this is because we know that this block, being solid white, is an **ice** block, which has an type ID of 3 as we previously figured out when solving the first challenge. Therefore, `f(111) = 3`.

Ok, let’s try to set it to 0:

```
        while len(blocks) < blocks_to_keep:
            d1, n1 = leb128.i.decode_reader(f)
            d2, n2 = leb128.i.decode_reader(f)
            d3, n3 = leb128.i.decode_reader(f)
            block_type = u8(f.read(1), endian="big")
            if i == 0:
                block_type = 0  # boo, the devilish corruptor strikes!
            blocks.append((d1, d2, d3, block_type))
            i += 1
```

This gives us:

```
    called `Result::unwrap()` on an `Err` value: invalid voxel kind `108`
```

So `f(0) = 108`. If we try a few additional values for `block_type`, we end up with something like this:

```
    f(0) = 108
    f(1) = 109
    f(2) = 110
    f(3) = 111
    f(4) = 104
    f(5) = 105
    f(111) = 3
```

…that looks very suspiciously linear. Not only the numbers seem to be always together in bunches of two, but it also seems that our mystery function is its own inverse.

Let’s look at this in binary:

```
    f(00000000) = 01101100

---

*Truncated at 1200 lines. Full text: <https://nnub.es/blog/en/ctf/corctf/2024/cormine/>*

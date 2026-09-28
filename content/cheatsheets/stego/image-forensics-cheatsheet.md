---
title: "Image Forensics - ImageMagick and FFmpeg Recipes"
category: stego
subcategory: image-forensics
type: cheatsheet
tags: [imagemagick, convert, magick, ffmpeg, channel-split, bit-plane, difference, contrast-stretch, colormap, palette, auto-level, fx, montage, compare, stego, cheatsheet]
summary: "Copy-paste ImageMagick and ffmpeg commands for channel splitting, bit planes, image differencing, contrast stretching and palette tricks."
tools: [imagemagick, ffmpeg, python3, pillow, numpy, gimp]
related: [image-triage, lsb-extraction, png-structure-attacks, other-image-formats, video-stego, stego-cheatsheet, lsb-extractor]
---

## Notes on syntax

```bash
# ImageMagick 6 uses `convert`; ImageMagick 7 uses `magick`. Both are shown as `convert`.
# If you are on IM7, either alias it or prefix: magick convert ...
convert -version
# -fx is a per-pixel expression evaluator: u = current channel value in [0,1], 0<=u<=1
# -evaluate / -function operate on channel values numerically
# ALWAYS write to PNG/PPM/TIFF. Writing to JPEG destroys whatever you just isolated.
```

## Channel splitting

```bash
# split into per-channel greyscale images (writes rgb-0.png, rgb-1.png, rgb-2.png)
convert chal.png -separate rgb-%d.png
# one specific channel
convert chal.png -channel R -separate r.png
convert chal.png -channel G -separate g.png
convert chal.png -channel B -separate b.png
convert chal.png -alpha extract alpha.png
# alternate colour spaces - a payload invisible in RGB often pops in one of these
convert chal.png -colorspace HSL -separate hsl-%d.png
convert chal.png -colorspace CMYK -separate cmyk-%d.png
convert chal.png -colorspace YCbCr -separate ycc-%d.png
convert chal.png -colorspace Lab -separate lab-%d.png
convert chal.png -colorspace Gray gray.png
# recombine channels from separate files
convert r.png g.png b.png -combine out.png
# swap channels (payload written into the wrong channel order)
convert chal.png -channel RGB -separate -swap 0,2 -combine swapped.png
```

## Bit planes

```bash
# bit 0 (LSB) of each channel, stretched to full range
convert chal.png -channel R -separate -depth 8 -fx '(floor(u*255)%2)' -normalize r_b0.png
convert chal.png -channel G -separate -depth 8 -fx '(floor(u*255)%2)' -normalize g_b0.png
convert chal.png -channel B -separate -depth 8 -fx '(floor(u*255)%2)' -normalize b_b0.png
# bit n (change the divisor: 1,2,4,8,16,32,64,128)
convert chal.png -channel R -separate -depth 8 -fx '(floor(u*255/4)%2)' -normalize r_b2.png
# all eight planes of the green channel in one loop
for i in 0 1 2 3 4 5 6 7; do
  d=$((1<<i))
  convert chal.png -channel G -separate -depth 8 -fx "(floor(u*255/$d)%2)" -normalize "g_b$i.png"
done
# keep only the low 3 bits and amplify (reveals gradient-style embedding)
convert chal.png -evaluate And 7 -evaluate Multiply 36 low3.png
# zero the low bits to see what the cover looked like
convert chal.png -evaluate And 254 cover_hi.png
# XOR the image with itself shifted - exposes periodic embedding
convert chal.png \( +clone -roll +1+0 \) -compose difference -composite -auto-level rollx.png
```

## Difference of two images

```bash
# absolute pixel difference, auto-levelled so any non-zero delta is visible
convert a.png b.png -compose difference -composite -auto-level diff.png
# binary mask of every differing pixel
convert a.png b.png -compose difference -composite -threshold 0 mask.png
# count differing pixels (AE = absolute error)
compare -metric AE a.png b.png null: 2>&1
compare -metric RMSE a.png b.png null: 2>&1
# visual highlight of the differences (red overlay)
compare a.png b.png -compose src diffmap.png
# crop to just the region that differs
convert a.png b.png -compose difference -composite -trim +repage trimmed.png
# side-by-side / stacked comparison
convert a.png b.png +append side.png
convert a.png b.png -append stacked.png
# difference amplified 20x
convert a.png b.png -compose difference -composite -evaluate Multiply 20 diff20.png
```

## Contrast stretching and levels

```bash
# stretch whatever range exists to full black-white
convert chal.png -auto-level out.png
convert chal.png -normalize out.png
# aggressive: clip 0.1% at each end
convert chal.png -contrast-stretch 0.1%x0.1% out.png
# equalise the histogram (finds text hidden a few levels from the background)
convert chal.png -equalize out.png
# gamma adjustment to pull out shadows or highlights
convert chal.png -gamma 0.3 shadows.png
convert chal.png -gamma 3.0 highlights.png
# isolate an exact colour value range (e.g. only pixels equal to 0xFE)
convert chal.png -fx '(floor(u*255)==254)?1:0' only254.png
# posterise: collapse to N levels per channel
convert chal.png -posterize 4 post.png
# per-channel level stretch with explicit black/white points
convert chal.png -level 40%,60% levels.png
# threshold and invert
convert chal.png -threshold 50% bw.png
convert chal.png -negate inv.png
```

## Colour map and palette tricks

```bash
# how many distinct colours, and what are they
identify -format '%k unique colours\n' chal.png
convert chal.png -unique-colors -scale 1600% palette.png
convert chal.png txt:- | head -20            # x,y: (r,g,b) #HEX per pixel
convert chal.png -colors 16 -unique-colors txt:-
# palette-index image: map each index to a maximally distinct colour
convert chal.png -depth 8 -colorspace Gray -random-threshold 50x50% rt.png
# apply a false-colour LUT so near-identical colours separate visually
convert chal.png -colorspace Gray -clut rainbow_lut.png false.png
convert chal.png -separate -evaluate-sequence max maxchan.png
# quantise down then back up - near-duplicate palette entries collapse
convert chal.png -colors 8 q8.png
# remap one exact colour to another
convert chal.png -fuzz 0% -fill white -opaque '#010101' remapped.png
# extract the palette of a GIF/indexed PNG
identify -verbose chal.gif | sed -n '/Colormap:/,/^  [A-Z]/p' | head -40
```

## Geometry and repair

```bash
# nearest-neighbour upscale (never blur a QR or a bit plane)
convert chal.png -filter point -resize 800% big.png
# add a quiet zone / border
convert chal.png -bordercolor white -border 40 pad.png
# rotate, flip, mirror
convert chal.png -rotate 90 r90.png
convert chal.png -flip vflip.png
convert chal.png -flop hflip.png
# crop a region: WxH+X+Y
convert chal.png -crop 200x100+50+30 +repage crop.png
# extend the canvas downward to reveal content cut off by a wrong height
convert chal.png -background magenta -extent 512x1024 extended.png
# deskew a scanned/rotated image
convert chal.png -deskew 40% deskewed.png
# strip all metadata (to compare byte sizes: a big drop means the payload was in metadata)
convert chal.png -strip stripped.png && ls -l chal.png stripped.png
```

## Tiling, montage and frames

```bash
# montage a directory of frames into a contact sheet
montage frames/*.png -tile 10x -geometry +2+2 sheet.png
# reassemble jigsaw pieces in a known order
montage p1.png p2.png p3.png p4.png -tile 2x2 -geometry +0+0 joined.png
# split an image into a grid of tiles
convert chal.png -crop 3x3@ +repage tile_%d.png
# animated GIF -> frames and back
convert chal.gif -coalesce frames/%03d.png
convert -delay 10 -loop 0 frames/*.png out.gif
# append every frame vertically to see them all at once
convert chal.gif -coalesce -append allframes.png
```

## FFmpeg equivalents and video-only recipes

```bash
# frames without frame-rate resampling, lossless
ffmpeg -i chal.mp4 -vsync 0 frames/%06d.png
# only keyframes
ffmpeg -i chal.mp4 -vf "select=eq(pict_type\,I)" -vsync 0 key/%04d.png
# contact sheet directly from the video
ffmpeg -i chal.mp4 -vf "select=not(mod(n\,30)),scale=320:-1,tile=10x10" -vsync 0 sheet.png
# per-frame difference, amplified
ffmpeg -i chal.mp4 -vf "tblend=all_mode=difference,eq=contrast=10" -vsync 0 d/%06d.png
# split channels of a video into three greyscale videos
ffmpeg -i chal.mp4 -vf "extractplanes=y+u+v" -map 0:v out_y.mp4
# histogram overlay
ffmpeg -i chal.mp4 -vf "histogram" -vsync 0 hist/%04d.png
# amplify the low bits of every frame
ffmpeg -i chal.mp4 -vf "lutrgb=r='val&7':g='val&7':b='val&7',eq=contrast=30" -vsync 0 low/%06d.png
# negate / levels on a still through ffmpeg
ffmpeg -i chal.png -vf negate inv.png
ffmpeg -i chal.png -vf "eq=contrast=5:brightness=0.1" stretch.png
# audio spectrogram from a video's audio track, in one command
ffmpeg -i chal.mp4 -lavfi "showspectrumpic=s=1920x1080:mode=separate:scale=log" spec.png
```

## Python one-liners (Pillow / numpy)

```bash
# image mode, size, bands
python3 -c "from PIL import Image;i=Image.open('chal.png');print(i.mode,i.size,i.getbands())"
# does the alpha channel vary at all?
python3 -c "from PIL import Image;print(Image.open('chal.png').convert('RGBA').getchannel('A').getextrema())"
# per-channel extrema (a channel with extrema (0,1) is a bitmask, not an image)
python3 -c "from PIL import Image;i=Image.open('chal.png');print([c.getextrema() for c in i.split()])"
# count unique colours
python3 -c "from PIL import Image;print(len(set(Image.open('chal.png').convert('RGB').getdata())))"
# palette of an indexed PNG/GIF
python3 -c "from PIL import Image;p=Image.open('chal.png').getpalette();print([tuple(p[i:i+3]) for i in range(0,48,3)])"
# save bit plane N of channel C
python3 -c "
from PIL import Image
import numpy as np
a=np.array(Image.open('chal.png').convert('RGB'))
bit,ch=0,2
Image.fromarray(((a[:,:,ch]>>bit)&1)*255).save('plane.png')"
# difference of two images, bounding box of the change
python3 -c "
from PIL import Image, ImageChops
a=Image.open('a.png').convert('RGB'); b=Image.open('b.png').convert('RGB')
d=ImageChops.difference(a,b); print(d.getbbox()); d.point(lambda v:255 if v else 0).save('diff.png')"
# dump raw pixels for offline analysis
python3 -c "
from PIL import Image
import numpy as np
np.array(Image.open('chal.png')).tofile('pixels.raw')"
# stack every GIF frame's difference from frame 0
python3 -c "
from PIL import Image, ImageSequence, ImageChops
im=Image.open('chal.gif'); frames=[f.convert('RGB').copy() for f in ImageSequence.Iterator(im)]
for i,f in enumerate(frames[1:],1):
    d=ImageChops.difference(frames[0],f)
    if d.getbbox(): print(i, d.getbbox())"
```

## Diagnostics that tell you where to look

```bash
# file size vs expected raw size - a big excess means embedded data
python3 -c "
from PIL import Image; import os
i=Image.open('chal.png'); w,h=i.size; n=len(i.getbands())
print('pixels', w*h*n, 'file', os.path.getsize('chal.png'))"
# entropy per 1 KB block (flat high entropy = compressed payload)
python3 -c "
import math,collections,sys
d=open('chal.png','rb').read()
for off in range(0,len(d),1024):
    b=d[off:off+1024]
    if not b: break
    c=collections.Counter(b); e=-sum(v/len(b)*math.log2(v/len(b)) for v in c.values())
    if e>7.8: print(hex(off), round(e,2))"
# is the LSB plane spatially correlated (natural) or random (embedded)?
python3 -c "
from PIL import Image
import numpy as np
a=np.array(Image.open('chal.png').convert('L'))&1
print('mean', a.mean(), 'horiz-corr', float(np.mean(a[:,:-1]==a[:,1:])))
# ~0.5 mean and ~0.5 correlation across a whole channel is a strong embedding signal"
```

## Gotchas

```bash
# 1. never save intermediate results as JPEG
# 2. -auto-level after any -fx, otherwise a 0/1 image renders as all black
# 3. IM has a resource limit; huge images need: convert -limit memory 2GB -limit map 4GB ...
# 4. `convert a.png b.png -compose difference -composite` requires identical dimensions:
convert a.png -resize $(identify -format '%wx%h' b.png)\! a_resized.png
# 5. ImageMagick's PNG delegate may drop ancillary chunks - do structure work with pngcheck,
#    not with convert
# 6. check the security policy if PDF/PS conversions are refused:
cat /etc/ImageMagick-6/policy.xml
```

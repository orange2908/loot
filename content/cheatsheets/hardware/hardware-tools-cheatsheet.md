---
title: "Hardware Tools Cheatsheet - binwalk, flashrom, openocd, sigrok, esptool"
category: hardware
subcategory: tooling
type: cheatsheet
tags: [binwalk, unblob, sasquatch, jefferson, ubi-reader, flashrom, openocd, minicom, picocom, screen, sigrok, sigrok-cli, esptool, avrdude, qemu, ghidra, can-utils]
summary: "Dense command reference for firmware extraction, flash programming, debug ports, serial terminals, logic decoding and MCU tooling."
tools: [binwalk, flashrom, openocd, sigrok-cli, esptool, avrdude, picocom, qemu]
related: [firmware-extraction, spi-i2c-flash-dump, jtag-swd, logic-analyzer-decoding, mcu-reversing]
---

## Firmware extraction

```bash
# identify
file firmware.bin
xxd -l 64 firmware.bin
binwalk firmware.bin                         # signature scan
binwalk -B firmware.bin                      # force a full signature scan
binwalk -E firmware.bin                      # entropy (flat 1.0 = compressed/encrypted)
binwalk -E -J firmware.bin                   # save the entropy plot as png
binwalk -A firmware.bin                      # scan for cpu opcodes / function prologues
binwalk -Y firmware.bin                      # capstone-based architecture guess
binwalk -% firmware.bin                      # entropy-based arch heuristic

# extract
binwalk -e firmware.bin                      # auto extract
binwalk -e -M firmware.bin                   # recurse into extracted files
binwalk -e -M -d 2 firmware.bin              # bound the recursion depth
binwalk -e --run-as=root firmware.bin        # newer binwalk refuses root by default
binwalk --dd='.*' firmware.bin               # carve every signature match
binwalk -D 'squashfs:sqfs' firmware.bin      # carve only squashfs
unblob -e out/ firmware.bin                  # better nesting, more handlers
unblob --show-external-dependencies

# carve by hand from a binwalk offset
dd if=firmware.bin of=rootfs.sqfs bs=1 skip=1572864 count=5242880 status=progress
dd if=firmware.bin of=part.bin bs=4096 skip=384 count=1280      # faster with a big bs

# filesystems
unsquashfs -s rootfs.sqfs                    # superblock info first
unsquashfs -d rootfs rootfs.sqfs
unsquashfs -ll rootfs.sqfs                   # list without extracting
sasquatch -d rootfs rootfs.sqfs              # vendor LZMA variants
sasquatch -b -d rootfs rootfs.sqfs           # big endian
jefferson -d jffs2-out rootfs.jffs2
jefferson -v -d jffs2-out rootfs.jffs2
ubireader_display_info firmware.bin
ubireader_extract_images -o ubi-img firmware.bin
ubireader_extract_files -o ubi-files firmware.bin
cramfsck -x cram-out rootfs.cramfs
cpio -idmv < initramfs.cpio
zcat initramfs.cpio.gz | cpio -idmv
7z x rootfs.ext -oext-out
debugfs -R 'ls -l /' rootfs.ext

# containers
mkimage -l kernel.uimage                     # u-boot header: load addr, entry, type
dd if=kernel.uimage of=kernel.lzma bs=1 skip=64
dtc -I dtb -O dts -o board.dts board.dtb     # device tree -> readable
fdtdump board.dtb | head -60

# decompression
xz -d -c blob.xz > blob
unlzma -c blob.lzma > blob
lz4 -d blob.lz4 blob
zstd -d blob.zst -o blob
gzip -d -c blob.gz > blob
```

## Loot a root filesystem

```bash
cat etc/passwd etc/shadow etc/version
grep -rIn -iE 'password|passwd|admin|secret|key=' etc/ | head -30
find . \( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name 'id_rsa*' \) -ls
cat etc/init.d/rcS etc/inittab
ls -la www/ usr/www/ htdocs/
find . -name '*.cgi' -o -name '*.php' | head -30
grep -rIn 'system(\|popen(\|exec(' www/ | head -20
file bin/busybox                             # arch + endianness + libc
find . -type f -exec file {} + | grep ELF | cut -d: -f1 |
  xargs strings -n 8 | grep -iE 'password|token|key=' | sort -u | head -40
```

## SPI / I2C flash

```bash
flashrom --list-supported | head -40
flashrom -L | grep -i w25q64                 # exact chip model strings
flashrom -p ch341a_spi                       # probe
flashrom -p ch341a_spi -c W25Q64.V -r dump1.bin
flashrom -p ch341a_spi -c W25Q64.V -r dump2.bin && sha256sum dump1.bin dump2.bin
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r dump.bin
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=30k -r dump.bin   # slow = reliable
flashrom -p ft2232_spi:type=2232H,port=A,divisor=4 -r dump.bin
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r dump.bin
flashrom -p serprog:dev=/dev/ttyACM0:115200 -r dump.bin
flashrom -p ch341a_spi -c W25Q64.V -w patched.bin
flashrom -p ch341a_spi -c W25Q64.V -v patched.bin
flashrom -p ch341a_spi -c W25Q64.V -E                        # chip erase
flashrom -p ch341a_spi --layout layout.txt --image rootfs -w new.bin
flashrom -p ch341a_spi --progress -r dump.bin

# i2c eeprom
sudo modprobe i2c-dev
i2cdetect -l
i2cdetect -y 1                               # 0x50-0x57 = eeprom addresses
i2cdump -y 1 0x50
i2cget -y 1 0x50 0x00
i2cset -y 1 0x50 0x00 0x41
eeprog -f -x -r 0:0x8000 /dev/i2c-1 0x50 > eeprom.bin
echo 24c256 0x50 | sudo tee /sys/bus/i2c/devices/i2c-1/new_device
sudo cat /sys/bus/i2c/devices/1-0050/eeprom > eeprom.bin

# sanity check a dump
xxd -l 64 dump.bin
python3 -c "d=open('dump.bin','rb').read(); print('unique bytes', len(set(d)))"
binwalk dump.bin && strings -n 8 dump.bin | head -20
```

## JTAG / SWD with OpenOCD

```bash
ls /usr/share/openocd/scripts/interface/     # adapter configs
ls /usr/share/openocd/scripts/target/        # chip configs
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg
openocd -f interface/jlink.cfg -c "transport select swd" -f target/nrf52.cfg
openocd -f interface/ftdi/ft2232h-module-swd.cfg -f target/stm32f4x.cfg
openocd -f interface/cmsis-dap.cfg -f target/rp2040.cfg
openocd -f interface/raspberrypi2-native.cfg -f target/stm32f1x.cfg
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg -c "adapter speed 100"

# scan an unknown chain
openocd -f interface/jlink.cfg -c "transport select jtag" \
  -c "adapter speed 100" -c "init; scan_chain; exit"

# one-shot dump
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; dump_image flash.bin 0x08000000 0x20000; shutdown"
```

```text
# openocd telnet console (port 4444)
init | reset init | reset halt | halt | resume | step | poll | targets
mdw 0x08000000 16 | mdh 0x20000000 8 | mdb 0x20000000 32
mww 0x20000000 0xdeadbeef
dump_image fw.bin 0x08000000 0x20000
load_image patched.bin 0x08000000
verify_image fw.bin 0x08000000
reg | reg pc | reg pc 0x08001234
flash banks | flash info 0 | flash probe 0
flash read_bank 0 fw.bin 0 0x20000
flash write_image erase unlock new.bin 0x08000000
stm32f1x unlock 0        # MASS ERASES the chip
nrf5 mass_erase          # clears APPROTECT, erases flash
```

```bash
# gdb over openocd (port 3333)
gdb-multiarch -batch -ex 'target extended-remote localhost:3333' \
  -ex 'monitor reset halt' -ex 'dump binary memory fw.bin 0x08000000 0x08020000'

# other st tools
st-info --probe
st-flash read flash.bin 0x08000000 0x10000
stm32flash -r flash.bin -S 0x08000000:65536 /dev/ttyUSB0
stm32flash -k /dev/ttyUSB0                   # readout protection status
pyocd list
pyocd commander -t stm32f103rc
```

## Serial terminals

```bash
ls -l /dev/serial/by-id/ ; ls /dev/ttyUSB* /dev/ttyACM* /dev/cu.usbserial-*
dmesg | tail -20
lsusb | grep -iE 'ftdi|cp210|ch34|prolific'

picocom -b 115200 /dev/ttyUSB0                    # ctrl-a ctrl-x to exit
picocom -b 115200 --imap lfcrlf --omap crlf /dev/ttyUSB0
picocom -b 115200 -f n -p n -d 8 -y n /dev/ttyUSB0
picocom -b 115200 --logfile boot.log /dev/ttyUSB0

screen /dev/ttyUSB0 115200                        # ctrl-a k to kill
screen -L -Logfile boot.log /dev/ttyUSB0 115200

minicom -D /dev/ttyUSB0 -b 115200                 # ctrl-a z help, ctrl-a x exit
minicom -s                                         # setup menu

tio /dev/ttyUSB0 -b 115200                        # ctrl-t q to quit
python3 -m serial.tools.miniterm /dev/ttyUSB0 115200
python3 -m serial.tools.list_ports -v

stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb raw -echo
cat /dev/ttyUSB0 | tee boot.log
printf 'help\r' > /dev/ttyUSB0
```

## Logic analysis with sigrok

```bash
sigrok-cli --scan
sigrok-cli -L | head -40                          # drivers, formats, decoders
sigrok-cli --protocol-decoders | grep -iE 'spi|i2c|uart'
sigrok-cli -P spi --show                          # a decoder's options

# capture
sigrok-cli -d fx2lafw -c samplerate=8m --samples 8M -o cap.sr
sigrok-cli -d fx2lafw -c samplerate=24m --time 5s -o cap.sr
sigrok-cli -d fx2lafw -c samplerate=4m --triggers D3=f --samples 4M -o cap.sr

# inspect
sigrok-cli -i cap.sr --show
unzip -p cap.sr metadata
sigrok-cli -i cap.sr -O ascii | head -40
sigrok-cli -i cap.sr -O bits --samples 2000
sigrok-cli -i cap.sr -O csv -o samples.csv
sigrok-cli -i cap.sr -O vcd -o cap.vcd

# decode
sigrok-cli -i cap.sr -P uart:rx=D0:baudrate=115200:format=ascii -A uart=rx-data
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3:cpol=0:cpha=0 -A spi
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3,spiflash -A spiflash
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1 -A i2c
sigrok-cli -i cap.sr -P i2c:scl=D0:sda=D1,eeprom24xx -A eeprom24xx
sigrok-cli -i cap.sr -P onewire_link:owr=D0 -A onewire_link
sigrok-cli -i cap.sr -P can:can_rx=D0:bitrate=500000 -A can
sigrok-cli -i cap.sr -P jtag:tck=D0:tms=D1:tdi=D2:tdo=D3 -A jtag
sigrok-cli -i cap.sr -P swd:swclk=D0:swdio=D1 -A swd

# bytes out of a decode
sigrok-cli -i cap.sr -P spi:clk=D0:mosi=D1:miso=D2:cs=D3 -A spi=miso-data |
  grep -oE '0x[0-9A-Fa-f]{2}' | sed 's/0x//' | tr -d '\n' | xxd -r -p > payload.bin
```

## MCU programming

```bash
# --- esp8266 / esp32 ---
esptool.py --port /dev/ttyUSB0 chip_id
esptool.py --port /dev/ttyUSB0 flash_id
esptool.py --port /dev/ttyUSB0 read_mac
espefuse.py --port /dev/ttyUSB0 summary                # encryption / secure boot state
esptool.py --port /dev/ttyUSB0 --baud 921600 read_flash 0 0x400000 dump.bin
esptool.py --port /dev/ttyUSB0 read_flash 0x8000 0x1000 partitions.bin
esptool.py image_info dump.bin                          # segments + load addresses
gen_esp32part.py partitions.bin
esptool.py --port /dev/ttyUSB0 write_flash 0x10000 app.bin
esptool.py --port /dev/ttyUSB0 erase_flash

# --- avr ---
avrdude -c usbasp -p m328p -v
avrdude -c usbasp -p m328p -U lfuse:r:-:h -U hfuse:r:-:h -U efuse:r:-:h -U lock:r:-:h
avrdude -c usbasp -p m328p -U flash:r:flash.bin:r
avrdude -c usbasp -p m328p -U eeprom:r:eeprom.bin:r
avrdude -c usbasp -p m328p -B 10 -U flash:r:flash.bin:r  # slower bit clock
avrdude -c arduino -P /dev/ttyUSB0 -b 115200 -p m328p -U flash:r:flash.bin:r
avrdude -c jtag2updi -P /dev/ttyUSB0 -p t1614 -U flash:r:flash.bin:r
avrdude -c usbasp -p m328p -U flash:w:patched.hex:i
avr-objdump -D -m avr5 -b binary flash.bin | head -60

# --- pic / msp430 / rp2040 ---
minipro -l | grep -i pic16f8
minipro -p PIC16F877A -r dump.hex
pk2cmd -P PIC16F877A -GF dump.hex
mspdebug rf2500 "read 0x8000 0x8000"
picotool info -a
picotool save -r 0x10000000 0x10200000 dump.bin

# hex conversions
srec_cat flash.hex -intel -o flash.bin -binary
srec_cat flash.bin -binary -o flash.hex -intel
srec_info flash.hex                                      # populated address ranges
avr-objcopy -I ihex -O binary flash.hex flash.bin
```

## Emulation

```bash
file rootfs/bin/busybox                                  # arch + endianness
cp $(which qemu-mipsel-static) rootfs/
sudo mount --bind /proc rootfs/proc && sudo mount --bind /dev rootfs/dev
sudo chroot rootfs /qemu-mipsel-static /bin/sh
sudo chroot rootfs /qemu-mipsel-static /usr/sbin/httpd
qemu-mipsel-static -L ./rootfs ./rootfs/usr/sbin/httpd
qemu-mipsel-static -strace -L ./rootfs ./rootfs/usr/sbin/httpd 2>&1 | tail -40
qemu-arm-static -L ./rootfs -E LD_PRELOAD=/libnvram.so ./rootfs/usr/sbin/httpd
qemu-mipsel-static -g 1234 -L ./rootfs ./rootfs/usr/sbin/httpd &
gdb-multiarch ./rootfs/usr/sbin/httpd -ex 'target remote :1234'

qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.ext2 \
  -append "root=/dev/sda console=ttyS0" -nographic \
  -net nic -net user,hostfwd=tcp::8080-:80
qemu-system-arm -M versatilepb -kernel vmlinuz -initrd initrd.img \
  -hda rootfs.qcow2 -append "root=/dev/sda1 console=ttyAMA0" -nographic

python3 fat.py firmware.bin                              # firmware analysis toolkit
```

## Disassembly and analysis

```bash
analyzeHeadless /tmp/proj fw -import firmware.bin \
  -processor 'ARM:LE:32:Cortex' -loader BinaryLoader -loader-baseAddr 0x08000000
analyzeHeadless /tmp/proj fw -import firmware.bin \
  -processor 'MIPS:BE:32:default' -loader BinaryLoader -loader-baseAddr 0x80000000
analyzeHeadless /tmp/proj fw -import lib.so -analysisTimeoutPerFile 600

r2 -a arm -b 16 -e asm.cpu=cortex -m 0x08000000 firmware.bin
r2 -a mips -b 32 -e cfg.bigendian=true -m 0x80000000 firmware.bin
r2 -a avr -b 8 -m 0 flash.bin
# inside r2: aaa ; afl ; pd 40 ; izz ; /a mov r0 ; s 0x1234

arm-none-eabi-objdump -D -b binary -m arm -M force-thumb firmware.bin | head -60
mips-linux-gnu-objdump -D -b binary -m mips -EB firmware.bin | head -60
readelf -h -d -S lib.so
nm -D --defined-only lib.so
strings -n 8 -a firmware.bin | sort -u > strings.txt

cpu_rec.py firmware.bin                                  # architecture guess
binbloom -f firmware.bin -e l                            # base address recovery
```

## CAN bus

```bash
sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
sudo slcand -o -c -s6 /dev/ttyUSB0 can0 && sudo ip link set up can0
sudo ip link set can0 type can bitrate 500000 && sudo ip link set up can0
candump can0 | candump -t d can0 | candump -c -c can0
candump -l can0                                          # log to candump-<date>.log
cansniffer -c can0                                       # group by id, highlight changes
cansend can0 123#DEADBEEF
cangen can0 -g 4 -I 123 -L 8 -D r -v
canplayer -I capture.log vcan0=can0
canbusload can0@500000 -r -t -b -c
isotpsend -s 7E0 -d 7E8 can0 <<< "22 F1 90"
cantools dump --database vehicle.dbc capture.log
```

## Quick reference: file magics

```text
27 05 19 56   uImage (big endian)      68 73 71 73  squashfs LE ("hsqs")
73 71 73 68   squashfs BE ("sqsh")     85 19        JFFS2 node LE
55 42 49 23   UBI# erase counter       28 CD 3D 45  CramFS
FD 37 7A 58   XZ                       1F 8B 08     gzip
5D 00 00      LZMA alone               04 22 4D 18  LZ4
28 B5 2F FD   zstd                     D0 0D FE ED  device tree blob
30 37 30 37   cpio ("0707")            7F 45 4C 46  ELF
E9            ESP8266/ESP32 image      50 4B 03 04  zip / apk / jar / sr
```

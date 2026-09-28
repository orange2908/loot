---
title: "RF and SDR Cheatsheet - rtl-sdr, HackRF, URH, rtl_433 and ISM Bands"
category: hardware
subcategory: sdr
type: cheatsheet
tags: [rtl-sdr, hackrf, airspy, gqrx, urh, inspectrum, rtl-433, gnuradio, ism-bands, frequency-table, modulation, ook, fsk, iq, waterfall, proxmark]
summary: "Commands for every common SDR tool, a frequency table for the ISM bands, and a modulation identification guide."
tools: [rtl_sdr, hackrf, gqrx, urh, inspectrum, rtl_433, gnuradio, sox]
related: [rf-sdr-analysis, rf-protocols-rfid-ble, hardware-tools-cheatsheet, logic-analyzer-decoding]
---

## Device check

```bash
rtl_test                                    # confirm the dongle works, report PPM drift
rtl_test -p                                 # PPM error estimation (needs a strong signal)
rtl_test -s 2400000                         # test at a specific sample rate
rtl_eeprom                                  # read/write the dongle's eeprom
hackrf_info                                 # firmware, serial, part id
airspy_info
SoapySDRUtil --find
SoapySDRUtil --probe="driver=rtlsdr"
lsusb | grep -iE 'rtl|realtek|hackrf|airspy|great scott'
dmesg | tail -10
```

## Spectrum survey

```bash
# power sweep to csv (then plot with heatmap.py from the rtl-sdr tools)
rtl_power -f 400M:500M:100k -g 40 -i 10 -e 60 sweep.csv
rtl_power -f 24M:1700M:1M -i 30 -e 300 wide.csv
python3 heatmap.py sweep.csv sweep.png

# hackrf full sweep (1 MHz bins, 0-6 GHz capable)
hackrf_sweep -f 300:1000 -w 1000000 > sweep.txt
hackrf_sweep -f 2400:2500 -w 100000 -l 32 -g 40 > wifi.txt

# interactive waterfalls
gqrx
SDRPlusPlus
CubicSDR
qspectrumanalyzer
```

## Capturing IQ

```bash
# rtl-sdr: cu8 (unsigned 8-bit interleaved I,Q) - the default everywhere
rtl_sdr -f 433920000 -s 2048000 -g 40 -n 20480000 capture.cu8   # ~10 s
rtl_sdr -f 433920000 -s 2400000 -g 49.6 capture.cu8             # until ctrl-c
rtl_sdr -f 868300000 -s 1024000 -g 40 -p 25 capture.cu8         # -p = ppm correction
rtl_sdr -f 433920000 -s 250000 -g 30 - | head -c 20000000 > short.cu8

# hackrf: cs8 (signed 8-bit interleaved)
hackrf_transfer -r capture.cs8 -f 433920000 -s 8000000 -l 24 -g 32 -a 1
hackrf_transfer -r capture.cs8 -f 868300000 -s 2000000 -l 16 -g 20
hackrf_transfer -r capture.cs8 -f 2450000000 -s 20000000 -l 32 -g 40 -a 1
#   -l = LNA gain (0-40, step 8), -g = VGA gain (0-62, step 2), -a = antenna power

# airspy
airspy_rx -r capture.iq -f 433.92 -a 3000000 -t 0
# -t 0 = 32-bit float IQ, -t 1 = 16-bit int IQ, -t 2 = 8-bit int IQ

# transmit (hackrf / plutosdr only; rtl-sdr is receive-only)
hackrf_transfer -t capture.cs8 -f 433920000 -s 8000000 -x 20 -a 1
sudo rpitx -m IQFLOAT -i capture.cf32 -s 250000 -f 433920      # raspberry pi gpio

# demodulated audio
rtl_fm -f 433.92M -M am -s 24k - | aplay -r 24000 -f S16_LE
rtl_fm -f 100.1M -M wbfm -s 200k -r 48k - | aplay -r 48000 -f S16_LE
rtl_fm -M raw -f 433.92M -s 250k capture.raw
sox -r 250000 -e signed -b 16 -c 2 capture.raw capture.wav      # raw -> wav (I/Q)
sox -t raw -r 2048000 -e unsigned -b 8 -c 2 capture.cu8 capture.wav
```

## Known protocols first

```bash
rtl_433 -f 433.92M                          # decode everything it knows
rtl_433 -f 433.92M -A                       # analyse mode: pulse timings + a suggested -X
rtl_433 -f 868.3M -s 1024k
rtl_433 -F json -M level -M time:iso        # structured output with rssi
rtl_433 -r capture.cu8 -A                   # offline, on a saved capture
rtl_433 -R 0 -X 'n=custom,m=OOK_PWM,s=350,l=1050,r=10000,g=500,t=50,y=0' -r capture.cu8
rtl_433 -R 0 -X 'n=fsk,m=FSK_PCM,s=100,l=100,r=2000' -r capture.cu8
rtl_433 -G 4                                # enable ALL decoders (noisy)
rtl_433 -w capture.cu8 -f 433.92M           # record while decoding
rtl_433 -S all -f 433.92M                   # auto-save every detected signal
rtl_433 -R                                  # list every built-in decoder
```

## Analysis tools

```bash
# inspectrum: visual IQ with a symbol-extraction overlay
inspectrum -r 2048000 capture.cu8
inspectrum -r 8000000 capture.cs8
#   drag a selection over a burst -> add "Amplitude Demod" (OOK) or "Frequency Demod" (FSK)
#   set the symbol period from the shortest pulse, then right-click > Copy bits

# universal radio hacker
urh
urh_cli -d RTL-SDR -f 433.92e6 -s 2e6 -rx -file capture.complex
urh_cli -d HackRF -f 433.92e6 -s 2e6 -tx -file modified.complex
#   Interpretation: autodetect modulation, tune samples/symbol and the centre value
#   Analysis     : choose a decoding (Manchester I/II, Differential, NRZ-I), label fields
#   Generator    : edit a field and rebuild the frame
#   Simulator    : replay and fuzz

# gnuradio
gnuradio-companion
#   File Source -> Throttle -> Complex to Mag^2 -> Threshold -> File Sink   (OOK)
#   File Source -> Quadrature Demod -> Binary Slicer -> File Sink           (FSK)

# baudline / audacity for audio-rate signals
audacity capture.wav

# crc identification once you have several frames (hex, no spaces)
reveng -w 8 -s 01020304AA 01020305AB
reveng -w 16 -l -s 0102030405AABB 0102030406AACC 0102030407AADD
```

## ISM and common frequency table

```text
 13.56  MHz    NFC / RFID HF (MIFARE, NTAG, iCLASS)
125-134 kHz    RFID LF (EM410x, HID Prox, T5577, Hitag)
 27.12  MHz    ISM, RC toys
 40.68  MHz    ISM
 315    MHz    ISM (north america): garage doors, TPMS, car fobs
 390    MHz    north american garage doors (some)
 418    MHz    UK legacy remotes
 433.05-434.79 MHz  ISM region 1: remotes, sensors, weather stations, LoRa
 433.92 MHz    the single most common sub-GHz CTF frequency
 447-450 MHz   LPD433/PMR adjacent
 868.0-868.6   MHz  ISM region 1: LoRa, Z-Wave (868.42 EU), Wireless M-Bus
 902-928 MHz   ISM region 2: LoRa US, Z-Wave (908.42 US), ZigBee 900
 915    MHz    ISM region 2 centre
2400-2483.5 MHz ISM: WiFi, BLE, ZigBee, classic Bluetooth, many proprietary
2402/2426/2480 MHz  BLE advertising channels 37 / 38 / 39
5150-5875 MHz  WiFi 5 GHz / U-NII
 169    MHz    wireless M-Bus (EU)
1090   MHz     ADS-B (aircraft)
 978   MHz     UAT / ADS-B (US)
 162   MHz     AIS (ships): 161.975 and 162.025
 137   MHz     NOAA APT weather satellites
 145/435 MHz   amateur satellite bands
1575.42 MHz    GPS L1
```

## Modulation identification guide

```text
LOOK AT THE WATERFALL
  single vertical line, blinking on and off          -> OOK (on-off keying)
  single line, amplitude varies but never zero       -> ASK
  two parallel lines, both constant amplitude        -> 2-FSK
  four parallel lines                                -> 4-FSK / GFSK variants
  one smeared line, constant amplitude               -> PSK (look at phase)
  a wide constant-envelope blob                      -> spread spectrum / DSSS
  a line that jumps between channels                 -> FHSS (BLE, Bluetooth)
  a slanted line (chirp)                             -> LoRa (CSS)

LOOK AT THE TIME DOMAIN (|IQ| magnitude)
  square on/off envelope                             -> OOK, threshold it
  constant envelope                                  -> frequency or phase modulation
  envelope with two non-zero levels                  -> ASK

LOOK AT THE INSTANTANEOUS FREQUENCY (d/dt of phase)
  two stable levels                                  -> 2-FSK; threshold at the midpoint
  smooth transitions between levels                  -> GFSK / MSK
  flat                                               -> not frequency modulated

LINE CODING (after you have raw symbols)
  lots of 01 / 10 pairs, never 00 or 11 runs > 2     -> Manchester
  long high + short low vs short high + long low     -> PWM (EV1527, PT2262)
  fixed-width symbols, arbitrary runs                -> NRZ
  transitions mean 1, no transition means 0          -> differential / NRZ-I

SYMBOL RATE
  symbol_rate = sample_rate / samples_in_shortest_pulse
  then round to a plausible value (1000, 2000, 4800, 9600, 38400, 100000 ...)
```

## Common sub-GHz chips

```text
EV1527 / PT2262 / HT12E   24 bit, OOK PWM, FIXED code  -> replayable
PT2240 / SC2262           same family
KeeLoq                    66 bit, rolling               -> not replayable
Somfy RTS, Nice Flor-S    rolling
Princeton PT2264          fixed
CC1101 based devices       configurable OOK/FSK, 300-928 MHz
Si4432 / RFM69 / SX1276    FSK / LoRa
Weather sensors            Oregon, LaCrosse, Acurite, Ambient  -> rtl_433 knows them
TPMS                       FSK, 315/433 MHz -> rtl_433 -R for the decoder list
```

## RFID / NFC quick commands

```text
# proxmark3
hw tune | hw status
lf search | lf read | lf em 410x reader
lf em 410x clone --id 1234567890
lf t55xx detect | lf t55xx dump
lf hid reader | lf hid clone -r 2004263f88
hf search | hf 14a info | hf 14a reader
hf mf autopwn                       # chk -> nested -> hardnested -> dump
hf mf chk --1k -f mfc_default_keys.dic
hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF
hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta
hf mf dump | hf mf restore --1k
hf mf cload -f dump.eml | hf mf csetuid --uid 11223344
hf mfu info | hf mfu dump -k FFFFFFFF
hf mfdes info | hf 15 info | hf iclass info
hf 14a sniff | hf list 14a
```

```bash
# libnfc / mfoc
nfc-list ; nfc-poll
nfc-mfclassic r a dump.mfd keys.mfd
nfc-mfclassic w a new.mfd dump.mfd
mfoc -O dump.mfd
mfoc -k FFFFFFFFFFFF -k A0A1A2A3A4A5 -O dump.mfd
mfcuk -C -R 0:A -v 2
xxd -g 1 -c 16 dump.mfd | awk 'NR%4==0'      # sector trailers: KeyA|access|KeyB
```

## Bluetooth LE quick commands

```bash
sudo hciconfig hci0 up && sudo hcitool lescan --duplicates
bluetoothctl                               # scan on / devices / connect / menu gatt
sudo gatttool -b AA:BB:CC:DD:EE:FF --primary
sudo gatttool -b AA:BB:CC:DD:EE:FF --characteristics
sudo gatttool -b AA:BB:CC:DD:EE:FF --char-read --handle=0x0025
sudo gatttool -b AA:BB:CC:DD:EE:FF --char-write-req --handle=0x0025 --value=deadbeef
sudo gatttool -b AA:BB:CC:DD:EE:FF --listen --char-read --handle=0x0025
sudo bettercap -eval "ble.recon on"
ubertooth-btle -f -c capture.pcap
tshark -r capture.pcap -Y 'btatt' -T fields -e btatt.handle -e btatt.value
crackle -i capture.pcap -o decrypted.pcap
```

## Useful conversions

```bash
# cu8 (rtl_sdr) -> cf32 (gnuradio / urh)
python3 -c "
import numpy as np,sys
a=np.fromfile(sys.argv[1],dtype=np.uint8).astype(np.float32)
a=(a-127.5)/127.5
a.astype(np.float32).tofile(sys.argv[2])
" capture.cu8 capture.cf32

# cs8 (hackrf) -> cf32
python3 -c "
import numpy as np,sys
a=np.fromfile(sys.argv[1],dtype=np.int8).astype(np.float32)/128.0
a.tofile(sys.argv[2])
" capture.cs8 capture.cf32

# how long is my capture?
python3 -c "
import os,sys
size=os.path.getsize(sys.argv[1]); rate=int(sys.argv[2]); bps=int(sys.argv[3])
print(f'{size/(2*bps*rate):.3f} seconds')
" capture.cu8 2048000 1

# wavelength (antenna length): quarter wave in cm = 7500 / f_MHz
python3 -c "f=433.92; print(f'quarter wave: {7500/f:.1f} cm, half wave: {15000/f:.1f} cm')"
```

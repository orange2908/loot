---
title: "Image Geolocation"
category: osint
subcategory: geolocation
type: technique
tags: [geolocation, geoguessing, osint, exif, gps, shadows, solar-position, signage, license-plates, road-markings, vegetation, reverse-image-search, street-view, openstreetmap, suncalc]
difficulty: medium
summary: "Read the metadata first, then the photo: script, traffic side, plates, infrastructure, vegetation and shadows narrow the world to a street."
when_to_use:
  - "The challenge asks where a photo was taken, or for the name of a nearby business"
  - "You need to estimate when a photo was taken from the shadows"
  - "An image has no EXIF and you must work from content alone"
  - "You must confirm a candidate location against the photo"
tools: [exiftool, python3, openstreetmap, google-earth, suncalc, tineye, yandex]
related: [osint-methodology, metadata-hiding, osint-social-and-archives, osint-tools-cheatsheet, osint-people-pivoting]
---

## TL;DR

Order: **metadata -> reverse image search -> systematic visual read -> candidate area ->
street-level confirmation**. Each visual clue is a filter; apply the cheap, high-information
ones first (script/language, side of the road, plate shape) before the expensive ones
(architecture, vegetation).

## Recognise it

- "Where was this taken?", "What is the name of the cafe?", "Which airport is this?"
- A photo with no obvious text, or with text deliberately cropped.
- A photo that is clearly a screenshot of a photo (so EXIF is gone by design).
- A series of photos - they are probably all from one trip, so one solved photo locates the rest.

## Step 1 - metadata (30 seconds, sometimes the whole answer)

```bash
# everything, including GPS and maker notes
exiftool -a -u -g1 photo.jpg

# GPS as signed decimals, ready for a map URL
exiftool -n -GPSLatitude -GPSLongitude -GPSAltitude photo.jpg
exiftool -c '%.8f' -GPSPosition photo.jpg

# camera, software and timestamps - a phone model narrows the region and the era
exiftool -Make -Model -Software -DateTimeOriginal -OffsetTimeOriginal photo.jpg

# the embedded thumbnail may be the UNCROPPED original
exiftool -b -ThumbnailImage photo.jpg > thumb.jpg

# the timezone offset alone gives you a longitude band
exiftool -OffsetTime -OffsetTimeOriginal -GPSDateStamp -GPSTimeStamp photo.jpg
```

Open coordinates with `https://www.openstreetmap.org/?mlat=LAT&mlon=LON#map=18/LAT/LON`.

## Step 2 - reverse image search

Run the image through **several** engines; they index completely different things.

| Engine | Best at |
| --- | --- |
| Google Lens / Images | landmarks, products, text in the image |
| Yandex Images | by far the strongest for faces and for buildings, especially outside the US |
| Bing Visual Search | sometimes finds what Google misses |
| TinEye | exact-copy and crop detection, plus the oldest known appearance |

Techniques that improve the hit rate:

- **Crop to the distinctive element** (the sign, the building, the logo) and search that alone.
- **Search the uncropped thumbnail** from EXIF, which may contain more than the visible image.
- **Rotate/flip** if the image may have been mirrored.
- Search **text in the image** as a normal web query, not as an image.

## Step 3 - the systematic visual read

Work down this list. Each line is a filter; write down what it eliminates.

### Writing and language

- **Script** is the single strongest filter: Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari,
  Thai, Han, Kana, Hangul, Georgian, Armenian, Ethiopic.
- Within Latin, **diacritics** narrow hard: `ă â î ș ț` (Romanian), `ő ű` (Hungarian),
  `ą ć ę ł ń ś ź ż` (Polish), `å ä ö` (Swedish), `ø æ` (Danish/Norwegian), `ğ ı ş` (Turkish),
  `ñ` (Spanish), `ç ã õ` (Portuguese).
- **Phone number format** on shop signs gives the country code and often the city.
- **Domain suffix** on an advert (`.co.uk`, `.com.br`, `.pl`) is decisive.
- **Address format**: number-before-street vs street-before-number; postcode shape.

### Traffic and roads

- **Which side do they drive on?** Left: UK, Ireland, India, Japan, Australia, New Zealand,
  South Africa, Thailand, Indonesia, Malaysia, Kenya, and more. Right: most of the rest.
  Check parked cars, the driver's seat position, and which way vehicles face on each side.
- **Line colours**: white centre lines (most of Europe, Asia), yellow centre lines (North
  America, Japan for no-overtaking, and others). Yellow edge lines on the left in the US.
- **Road sign shapes**: octagonal STOP is near-universal but the wording changes
  (`ALTO`, `ARRET`, `STOP`); European warning signs are triangles with red borders, US ones are
  yellow diamonds.
- **Bollards, guardrails, chevrons** are strongly country-specific and are a classic
  geoguessing tell.
- **Kilometre vs mile markers**, speed limits in km/h vs mph.

### Vehicles

- **Licence plate shape and colour**: EU plates have a blue strip on the left; North American
  plates are wider relative to their height; Japanese plates are distinctive; many countries
  use yellow rear plates (UK, Netherlands, Luxembourg).
- **Vehicle models** sold only in certain markets; tuk-tuks, jeepneys, matatus, auto-rickshaws.
- **Taxi livery** is often city-specific.

### Infrastructure

- **Utility poles**: material (wood, concrete, metal), shape, insulator style, and the way
  cables are strung are strongly regional.
- **Street light design**, **manhole covers** (often stamped with the city name), **fire
  hydrants**, **post boxes**, **bus stop design**, **kerb paint**.
- **Building materials and roof pitch**: steep roofs where it snows, flat roofs where it does
  not; terracotta tiles in the Mediterranean; corrugated metal in the tropics.
- **Window shutters, balconies, air-conditioner placement** - all regional.
- **Power socket** type if any interior is visible.

### Nature and sky

- **Vegetation**: palms (which kind), eucalyptus (Australia and planted elsewhere), birch
  (northern), olive (Mediterranean), tropical broadleaf.
- **Soil colour**: red laterite (tropics, parts of Australia and Brazil), pale sand, dark loam.
- **Terrain and horizon**: mountain profiles are identifiable, and a distinctive ridge line can
  be matched against elevation data.
- **Sun position**: at noon the sun is due **south** in the northern hemisphere and due
  **north** in the southern. A shadow pointing "up-screen" in a north-oriented photo is a
  hemisphere clue.
- **Season** from foliage, combined with a timestamp, cross-checks the hemisphere.

### Shadows -> latitude and time

Shadow length gives the sun's **elevation angle**:

$$ \tan(\text{elevation}) = \frac{\text{object height}}{\text{shadow length}} $$

The sun's elevation at solar noon is:

$$ \text{elevation}_{noon} = 90^\circ - |\text{latitude} - \delta| $$

where $\delta$ is the solar declination (between -23.44 and +23.44 degrees, depending on the
date). With a known date and a measured noon elevation you get the latitude; with a known
latitude and a measured elevation you get the time of day. The code below computes elevation
and azimuth from first principles so you can test a candidate location, date and time against
the shadows in the photo.

## Step 4 - narrow and confirm

```text
country  ->  region (vegetation, terrain, plate variant)
         ->  city   (transit operator, signage, phone code, architecture)
         ->  street (a business name, a bus line number, a distinctive building)
         ->  exact  (street-level imagery, satellite view, building footprint)
```

Useful map resources:

- **OpenStreetMap** for searching by feature and for its editor's raw tag data.
- **Overpass Turbo** for querying OSM by tag (every pharmacy with a given name in a region).
- Satellite imagery for building footprints, roof colour, car park layout, tree positions.
- Street-level imagery for the final confirmation, including Mapillary and KartaView where
  commercial coverage is missing.

Confirmation means: at least **three** independent features in the photo match the candidate
location (a building corner, a sign, a tree, a kerb line), and nothing contradicts it.

## Code

```python
#!/usr/bin/env python3
"""Geolocation helpers: EXIF GPS extraction, solar position, shadow maths, map links.

  python3 geoloc.py exif photo.jpg
  python3 geoloc.py sun 48.8583 2.2945 2026-06-21 12:00
  python3 geoloc.py shadow 1.8 2.4          # object height, shadow length -> elevation
  python3 geoloc.py latitude 2026-06-21 63.4  # date + noon elevation -> latitude
  python3 geoloc.py --selftest
"""
from __future__ import annotations

import datetime as dt
import json
import math
import shutil
import subprocess
import sys


# --------------------------------------------------------------------------- #
# EXIF GPS
# --------------------------------------------------------------------------- #
def dms_to_decimal(degrees: float, minutes: float, seconds: float, ref: str) -> float:
    value = abs(degrees) + minutes / 60.0 + seconds / 3600.0
    return -value if ref.upper() in ("S", "W") else value


def decimal_to_dms(value: float, is_lat: bool) -> str:
    ref = ("N" if value >= 0 else "S") if is_lat else ("E" if value >= 0 else "W")
    v = abs(value)
    d = int(v)
    m = int((v - d) * 60)
    s = (v - d - m / 60) * 3600
    return f"{d}d {m}' {s:.2f}\" {ref}"


def exif_gps(path: str) -> tuple[float, float] | None:
    """Read GPS from a file using exiftool's numeric JSON output."""
    if shutil.which("exiftool") is None:
        return None
    p = subprocess.run(["exiftool", "-json", "-n", "-GPSLatitude", "-GPSLongitude", path],
                       capture_output=True, timeout=60)
    try:
        data = json.loads(p.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    lat, lon = data[0].get("GPSLatitude"), data[0].get("GPSLongitude")
    if lat is None or lon is None:
        return None
    return float(lat), float(lon)


def map_links(lat: float, lon: float, zoom: int = 18) -> list[str]:
    return [
        f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map={zoom}/{lat}/{lon}",
        f"https://www.google.com/maps/search/?api=1&query={lat},{lon}",
        f"https://www.bing.com/maps?cp={lat}~{lon}&lvl={zoom}",
    ]


# --------------------------------------------------------------------------- #
# solar position (NOAA-style low-precision algorithm)
# --------------------------------------------------------------------------- #
def julian_day(when: dt.datetime) -> float:
    """Julian day number for a UTC datetime."""
    y, m = when.year, when.month
    d = (when.day + when.hour / 24 + when.minute / 1440
         + when.second / 86400)
    if m <= 2:
        y -= 1
        m += 12
    a = y // 100
    b = 2 - a + a // 4
    return int(365.25 * (y + 4716)) + int(30.6001 * (m + 1)) + d + b - 1524.5


def solar_declination(when: dt.datetime) -> float:
    """Solar declination in degrees (the sun's latitude on the celestial sphere)."""
    n = julian_day(when) - 2451545.0
    mean_long = (280.460 + 0.9856474 * n) % 360
    mean_anom = math.radians((357.528 + 0.9856003 * n) % 360)
    ecl_long = math.radians(mean_long + 1.915 * math.sin(mean_anom)
                            + 0.020 * math.sin(2 * mean_anom))
    obliquity = math.radians(23.439 - 0.0000004 * n)
    return math.degrees(math.asin(math.sin(obliquity) * math.sin(ecl_long)))


def equation_of_time(when: dt.datetime) -> float:
    """Minutes by which the true sun leads the mean sun."""
    n = julian_day(when) - 2451545.0
    mean_long = math.radians((280.460 + 0.9856474 * n) % 360)
    mean_anom = math.radians((357.528 + 0.9856003 * n) % 360)
    ecl_long = mean_long + math.radians(1.915 * math.sin(mean_anom)
                                        + 0.020 * math.sin(2 * mean_anom))
    obliquity = math.radians(23.439 - 0.0000004 * n)
    y = math.tan(obliquity / 2) ** 2
    eot = (y * math.sin(2 * mean_long)
           - 2 * 0.0167 * math.sin(mean_anom)
           + 4 * 0.0167 * y * math.sin(mean_anom) * math.cos(2 * mean_long)
           - 0.5 * y * y * math.sin(4 * mean_long)
           - 1.25 * 0.0167 ** 2 * math.sin(2 * mean_anom))
    return math.degrees(eot) * 4


def solar_position(lat: float, lon: float, when_utc: dt.datetime) -> tuple[float, float]:
    """Return (elevation_deg, azimuth_deg_from_north_clockwise)."""
    decl = math.radians(solar_declination(when_utc))
    eot = equation_of_time(when_utc)
    minutes = when_utc.hour * 60 + when_utc.minute + when_utc.second / 60
    true_solar_time = (minutes + eot + 4 * lon) % 1440
    hour_angle = math.radians(true_solar_time / 4 - 180)
    lat_r = math.radians(lat)

    sin_elev = (math.sin(lat_r) * math.sin(decl)
                + math.cos(lat_r) * math.cos(decl) * math.cos(hour_angle))
    sin_elev = max(-1.0, min(1.0, sin_elev))
    elevation = math.degrees(math.asin(sin_elev))

    cos_az_num = math.sin(decl) - math.sin(lat_r) * sin_elev
    cos_az_den = math.cos(lat_r) * math.cos(math.asin(sin_elev))
    if abs(cos_az_den) < 1e-9:
        azimuth = 0.0
    else:
        cos_az = max(-1.0, min(1.0, cos_az_num / cos_az_den))
        azimuth = math.degrees(math.acos(cos_az))
        if math.sin(hour_angle) > 0:
            azimuth = 360 - azimuth
    return elevation, azimuth


# --------------------------------------------------------------------------- #
# shadow maths
# --------------------------------------------------------------------------- #
def elevation_from_shadow(object_height: float, shadow_length: float) -> float:
    """Sun elevation in degrees from an object's height and its shadow's length."""
    if shadow_length <= 0:
        return 90.0
    return math.degrees(math.atan2(object_height, shadow_length))


def shadow_length(object_height: float, elevation_deg: float) -> float:
    if elevation_deg <= 0:
        return float("inf")
    return object_height / math.tan(math.radians(elevation_deg))


def latitude_from_noon_elevation(noon_elevation: float, when: dt.datetime,
                                 northern: bool = True) -> float:
    """lat = decl +/- (90 - noon_elevation). Two solutions; pick with `northern`."""
    decl = solar_declination(when)
    offset = 90.0 - noon_elevation
    return decl + offset if northern else decl - offset


def shadow_azimuth(sun_azimuth: float) -> float:
    """A shadow points 180 degrees away from the sun."""
    return (sun_azimuth + 180) % 360


def check_candidate(lat: float, lon: float, when_utc: dt.datetime,
                    measured_elevation: float, tolerance: float = 3.0) -> tuple[bool, str]:
    """Does a candidate location/time reproduce the elevation measured in the photo?"""
    elev, azim = solar_position(lat, lon, when_utc)
    ok = abs(elev - measured_elevation) <= tolerance
    return ok, (f"computed elevation {elev:.1f} deg, azimuth {azim:.1f} deg "
                f"(shadow points {shadow_azimuth(azim):.1f} deg); "
                f"measured {measured_elevation:.1f} deg -> "
                f"{'consistent' if ok else 'INCONSISTENT'}")


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "exif":
        got = exif_gps(argv[1])
        if not got:
            print("[-] no GPS tags (or exiftool is missing)")
            return 1
        lat, lon = got
        print(f"{lat:.6f}, {lon:.6f}")
        print(decimal_to_dms(lat, True), decimal_to_dms(lon, False))
        for url in map_links(lat, lon):
            print(url)
    elif cmd == "sun":
        lat, lon = float(argv[1]), float(argv[2])
        when = dt.datetime.fromisoformat(f"{argv[3]}T{argv[4]}")
        elev, azim = solar_position(lat, lon, when)
        print(f"elevation {elev:.2f} deg, azimuth {azim:.2f} deg from north")
        print(f"a 1 m pole casts a {shadow_length(1.0, elev):.2f} m shadow "
              f"pointing {shadow_azimuth(azim):.1f} deg")
    elif cmd == "shadow":
        h, s = float(argv[1]), float(argv[2])
        print(f"sun elevation {elevation_from_shadow(h, s):.2f} deg")
    elif cmd == "latitude":
        when = dt.datetime.fromisoformat(f"{argv[1]}T12:00")
        e = float(argv[2])
        print(f"northern solution: {latitude_from_noon_elevation(e, when, True):.2f}")
        print(f"southern solution: {latitude_from_noon_elevation(e, when, False):.2f}")
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    # DMS conversion, both hemispheres
    assert abs(dms_to_decimal(48, 51, 29.99, "N") - 48.858331) < 1e-5
    assert abs(dms_to_decimal(2, 17, 40.0, "E") - 2.294444) < 1e-5
    assert dms_to_decimal(33, 51, 30, "S") < 0
    assert dms_to_decimal(118, 15, 0, "W") < 0
    assert decimal_to_dms(-33.8688, True).endswith("S")
    assert decimal_to_dms(151.2093, False).endswith("E")

    # solar declination: near the extremes at the solstices, near zero at the equinoxes
    d_jun = solar_declination(dt.datetime(2026, 6, 21, 12))
    d_dec = solar_declination(dt.datetime(2026, 12, 21, 12))
    d_mar = solar_declination(dt.datetime(2026, 3, 20, 12))
    assert 23.0 < d_jun < 23.5, d_jun
    assert -23.5 < d_dec < -23.0, d_dec
    assert abs(d_mar) < 1.0, d_mar

    # solar position: the sun is high at noon in summer at mid latitude
    elev, azim = solar_position(48.8583, 2.2945, dt.datetime(2026, 6, 21, 12, 0))
    assert 60 < elev < 66, elev            # Paris, summer solstice, ~64 deg
    assert 150 < azim < 210, azim          # roughly due south around solar noon

    # and below the horizon in the middle of the night
    elev_night, _ = solar_position(48.8583, 2.2945, dt.datetime(2026, 6, 21, 0, 0))
    assert elev_night < 0, elev_night

    # southern hemisphere: sun to the NORTH at local noon
    elev_s, azim_s = solar_position(-33.8688, 151.2093, dt.datetime(2026, 12, 21, 1, 0))
    assert elev_s > 60, elev_s
    # sun in the northern half of the sky (it is ~1 h before local solar noon here)
    assert azim_s < 90 or azim_s > 270, azim_s

    # shadow maths round trip
    e = elevation_from_shadow(1.8, 1.8)
    assert abs(e - 45.0) < 1e-9, e
    assert abs(shadow_length(1.8, 45.0) - 1.8) < 1e-9
    assert elevation_from_shadow(1.0, 0.0) == 90.0
    assert shadow_length(1.0, 0.0) == float("inf")
    assert abs(shadow_azimuth(180.0) - 0.0) < 1e-9
    assert abs(shadow_azimuth(90.0) - 270.0) < 1e-9

    # latitude from a noon elevation, checked against the forward calculation
    when = dt.datetime(2026, 6, 21, 12)
    noon_elev, _ = solar_position(48.8583, 0.0, dt.datetime(2026, 6, 21, 12, 0))
    lat_guess = latitude_from_noon_elevation(noon_elev, when, northern=True)
    assert abs(lat_guess - 48.8583) < 1.5, (lat_guess, noon_elev)

    # candidate checking
    ok, msg = check_candidate(48.8583, 2.2945, dt.datetime(2026, 6, 21, 12, 0), 64.0)
    assert ok, msg
    bad, msg2 = check_candidate(48.8583, 2.2945, dt.datetime(2026, 12, 21, 12, 0), 64.0)
    assert not bad, msg2

    # map links
    links = map_links(48.8583, 2.2945)
    assert any("openstreetmap.org" in u for u in links)
    assert all(str(48.8583) in u for u in links)

    print(f"selftest ok: DMS conversion, declination {d_jun:.2f}/{d_dec:.2f}, "
          f"Paris solstice noon elevation {elev:.1f} deg, shadow maths, latitude recovery")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **Screenshots and re-uploads strip EXIF.** Most social platforms remove it on upload, so its
  absence tells you nothing; its presence is a gift.
- **GPS can be wrong or spoofed.** Check it against the visual content before trusting it.
- **The thumbnail may be uncropped.** Always extract it.
- **Reverse image search fails on ordinary streets.** It works for landmarks and for images
  that have been published before; a random pavement will return nothing, which is information.
- **Left/right-hand traffic is only decisive with a moving vehicle** or clearly parked cars in
  the direction of travel; a one-way street can fool you.
- **Beware of planted decoys.** Authors sometimes include a misleading sign; look for
  *consistency* across several independent clues.
- **Shadows give the elevation, not the location.** They constrain latitude given a date, or
  time given a latitude - they never give longitude alone.
- **Solar azimuth conventions differ.** The code above measures clockwise from true north;
  compass readings in the field may be magnetic, which differs by the local declination.
- **The camera's timestamp may be in the wrong timezone**, or unset. `OffsetTimeOriginal` and
  `GPSTimeStamp` (which is UTC) are more reliable when present.
- **Do not geolocate real private individuals.** If the trail leads to someone who is obviously
  not part of the challenge, stop.

## Tools

`exiftool`, a browser with Google Lens / Yandex Images / Bing Visual Search / TinEye,
OpenStreetMap and Overpass Turbo, satellite and street-level imagery (including Mapillary and
KartaView), SunCalc for an interactive sun-position check, and the script above for the maths.

## References

- ExifTool GPS tag documentation: https://exiftool.org/
- NOAA Solar Calculator and the low-precision solar position equations it documents:
  https://gml.noaa.gov/grad/solcalc/
- OpenStreetMap: https://www.openstreetmap.org/ and Overpass Turbo: https://overpass-turbo.eu/
- Mapillary (crowd-sourced street-level imagery): https://www.mapillary.com/

# Demo 08 - Free-to-play game: ad-SDK & privacy sweep

## Where this came from

A platform compliance reviewer screens a free-to-play game (`game.apk`) for the
density of advertising/monetization SDKs (a privacy red flag for kids/family
categories) and for outdated native media libraries.

The bundle ships a heavy ad stack plus older native libs:

- Trackers: **Unity Ads**, **AppLovin**, **Flurry**, **Facebook Audience
  Network**, **AppsFlyer**
- `libpng16.so.1.6.36` -> **libpng 1.6.36** (`CVE-2019-7317`, MEDIUM; fixed 1.6.37)
- `libz.so.1.2.11` -> **zlib 1.2.11** (`CVE-2018-25032`, MEDIUM; fixed 1.2.12)

## How to run

```sh
python demos/08-game-adtech/make_sample.py
python -m sbomx scan demos/08-game-adtech/game.apk --format table

# Export the tracker/vuln list for the privacy review record:
python -m sbomx scan demos/08-game-adtech/game.apk --format sarif -o game.sarif.json
```

## Expected result

- **7 components** (5 ad/analytics SDKs + libpng + zlib).
- **2 vulnerabilities** (`CVE-2019-7317`, `CVE-2018-25032`, both MEDIUM).
- **5 trackers** spanning Advertisement / Analytics / Profiling categories.
- Exit code **1**.

## How to act

Five distinct ad/analytics SDKs in one game warrants a data-sharing disclosure
review and (for child-directed categories) likely SDK removal. Bump libpng
(>= 1.6.37) and zlib (>= 1.2.12).

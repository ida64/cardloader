# CardLoader

CardLoader lets the Nintendo Switch load XCI game images from the SD card.

Target: FS 23.5.0 on Atmosphère 1.12.2 (commit `3e8915011`).

## Host build and tests

Requires a C11 compiler and Python 3.

```sh
make check   # unit tests
make demo    # build a synthetic XCI on a FAT32 image, run a full card activation
```

## Device build

All device builds use the `devkitpro/devkita64:libnx26` Docker image and an Atmosphère checkout at the matching
commit.

```sh
# package3 with the hooked kernel
ATMD=/path/to/Atmosphere sh device/kern/build.sh package3.orig package3

# xci sysmodule
ATMO=/path/to/Atmosphere sh device/xci/build.sh

# front ends
make nro-switch
make tesla
```

## Usage

Put images in `sdmc:/xci/`, either as `name.xci` or split as `name.xc0` + `name.xc1`. Open CardLoader (the app or the
overlay) and select a game. The slot starts empty at boot. The sysmodule logs to `sdmc:/switch/CardLoader/xci.log`.

## FS Patch

System module patch for gamecard fs rng is available at https://github.com/ida64/sys-patch but is not upstream yet.

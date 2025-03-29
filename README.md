# yaeed
aka **Yet Another Esp Exception Decoder**

A stupidly simple python script that takes path to .elf and stacktrace text files and decodes the exception.

## Requirements

Python3 and Xtensa toolchain has to be installed.

## Usage

```
echo "Backtrace: 0x400d999f:0x3ffcfeb0 0x400dc82e:0x3ffcff00 0x4010064e:0x3ffcff70" >  ~/stacktrace.txt

python3 yaeed.py ~/Documents/myproject/.pio/build/esp32dev/firmware.elf  ~/stacktrace.txt
```

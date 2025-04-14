# yaeed - Yet Another ESP Exception Decoder

A stupidly simple Python script to decode ESP32 and ESP8266 stack traces using an ELF file and a stack trace input. 

## Features

- Decodes ESP32 and ESP8266 stack traces.
- Extracts exception codes and their meanings (e.g., `Illegal instruction`, `LoadStoreError`).
- Parses key registers like `PC` and `EXCVADDR`.
- Converts instruction addresses (e.g., `0x400d999f`) to function names and file-line references using `addr2line`.
- Supports input from either a file or command-line argument.

## Requirements

- **Python 3.x**: Ensure Python 3 is installed on your system.
- **Xtensa Toolchain**: The `xtensa-esp32-elf-addr2line` tool must be available in your PATH or specified manually.
  - Install it via the ESP-IDF or PlatformIO toolchain.
- **ELF File**: Generated during the compilation of your ESP32/ESP8266 project (e.g., `firmware.elf`).

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/yourusername/yaeed.git
   cd yaeed
   ```
2. Ensure the Xtensa toolchain is installed and xtensa-esp32-elf-addr2line is accessible:
   ```
   xtensa-esp32-elf-addr2line --version
   ```

## Usage

Run the script with an ELF file and either a stack trace file or raw stack trace text.

**Decode a stack trace from a file:**

```
echo "Backtrace: 0x400d999f:0x3ffcfeb0 0x400dc82e:0x3ffcff00 0x4010064e:0x3ffcff70" > stacktrace.txt

python3 yaeed.py -e ~/myproject/.pio/build/esp32dev/firmware.elf -s stacktrace.txt
```

**Decode raw stack trace** 

```
python3 yaeed.py -e ~/myproject/.pio/build/esp32dev/firmware.elf -t "Backtrace: 0x400d999f:0x3ffcfeb0 0x400dc82e:0x3ffcff00"
```

## Options

```
  usage: 
  
  yaeed.py [-h] [-e ELF] [-s TRACEFILE] [-t TRACE] [--addr2line ADDR2LINE] [--verbose]
  -h, --help            Show this help message and exit
  -e, --elf ELF         Path to the ELF file from the sketch compilation
  -s, --tracefile TRACEFILE
                        Path to the file containing the stack trace
  -t, --trace TRACE     Stack trace content as a string
  --addr2line ADDR2LINE Path to addr2line executable (default: xtensa-esp32-elf-addr2line)
  --verbose             Print verbose debugging output
```

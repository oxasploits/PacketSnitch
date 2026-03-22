# PacketSnitch

![PacketSnitch Logo](https://raw.githubusercontent.com/oxagast/PacketSnitch/refs/heads/main/Logo/logo-packetsnitch.webp)

## Overview

PacketSnitch is a Python tool for extracting payloads and rich metadata from network packet capture (`.pcap`) files. It generates testcases for fuzzing, protocol analysis, and research by saving raw packet data and detailed information about each packet, including protocol, entropy, geoip, banners, and more. The tool optionally performs active reconnaissance to enrich output with server banners, SSL certificate info, and web page titles.

## Features

- Extracts TCP payloads from `.pcap` files and saves them as binary testcase files.
- Generates JSON info files for each testcase, containing:
  - Packet metadata (timestamps, MAC/IP addresses, ports, flags, checksums)
  - MIME type and magic description
  - Shannon entropy and character statistics
  - GeoIP lookup for source/destination IPs
  - Port descriptions (ICANN database)
  - MAC vendor lookup
  - Active recon: server banners, SSL certificate info, web page titles (optional)
- Consolidates all testcase info into `all_testcases_info.json`.
- Supports filtering by source/destination port.
- Handles compressed payloads (gzip/zlib).
- Verbose/debug output modes.

## Requirements

- Python 3.7+ (backend)
- NodeJS 16.4 / Electron Forge 7.11 (frontend) 
- Ollama LLM server (maxmind-m2.5:cloud)
- Dependencies:
  - electron forge
  - webpack
  - fs-extra
  - electron-squirrel-start
  - copy-webpack-plugin
  - ollama
  - scapy
  - numpy
  - requests
  - pyyaml
  - python-magic
  - chardet
  - geoip2
  - beautifulsoup4
  - scipy
- Databases:
  - GeoIP database (MaxMind `.mmdb`)
  - MAC vendor CSV
  - ICANN port description CSV


## Usage

(Dev)

```bash
python3 gen_testcase.py traffic.pcap -o output_dir [-s SRC_PORT] [-d DST_PORT] [-T TIMEOUT] [-a] [-c conf.yaml] [-v]
```

```bash
npm run make
npm start
```

### Arguments

- `traffic.pcap`: Path to the `.pcap` file to parse.
- `-o, --output`: Output directory for testcases (default: `testcases`)
- `-s, --source-port`: Only generate testcases from this source port.
- `-d, --dest-port`: Only generate testcases for this destination port.
- `-T, --timeout`: Timeout for network requests (default: 3 seconds)
- `-a, --active-recon`: Perform active recon (banners, SSL, titles)
- `-c, --conf`: Path to YAML config file (default: `conf.yaml`)
- `-v, --verbose`: Increase verbosity (repeat for more detail)

### Example

```bash
python3 gen_testcase.py traffic.pcap -o output_dir -T 5 -a -v
```

## Output Structure

- `output_dir/<dest_port>/pcap.data_packet.<index>.dat`: Raw payloads
- `output_dir/<dest_port>/pcap.info_packet.<index>.json`: Metadata for each testcase
- `all_testcases_info.json`: Consolidated info for all testcases

## Configuration

Edit `conf.yaml` to specify database locations:

```yaml
active_recon: true
output_dir: "testcases"
ollama:
  use_llm: true
#  model: "deepseek-r1:latest"
  model: "minimax-m2.5:cloud"
  response_length: 200
  pcap_percentage: 10
threads: 4
```

## Notes

- Active recon may take longer and requires network access.
- Ensure database files are present and paths are correct in `conf.yaml`.
- The tool will prompt before overwriting output directories.

## License

GPL v3

## Author

Marshall Whittaker

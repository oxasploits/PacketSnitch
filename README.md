![PacketSnitch](https://raw.githubusercontent.com/oxagast/PacketSnitch/refs/heads/main/Main/Orig-Pages/assets/images/packet-snitch-tag.png)

## Overview

PacketSnitch is a Python tool for extracting payloads and rich metadata from network packet capture (`.pcap`) files. It generates testcases for fuzzing, protocol analysis, and research by saving raw packet data and detailed information about each packet, including protocol, entropy, geoip, banners, and more. The tool optionally performs active reconnaissance to enrich output with server banners, SSL certificate info, and web page titles.

## Screenshot

This is a screenshot of *PacketSnitch alpha v0.9.114*.
![Screenshot 14](https://raw.githubusercontent.com/oxagast/PacketSnitch/refs/heads/main/Documentation/packetsnitch_win_ss14.png)

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

## License

GNU GPLv3

## Author

Marshall Whittaker

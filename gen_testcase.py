# oxagas# Import standard and third-party libraries for argument parsing, file handling, networking, compression, and data processing
import argparse
import csv
import json
import shutil
import os
import socket
import ssl
import sys
import zlib
import time
from datetime import datetime
from decimal import Decimal
import textwrap
import chardet
import geoip2.database
import magic
import numpy as np
import requests
import yaml
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from scipy.stats import entropy

# Try importing scapy for packet parsing
try:
    import scapy.all as scapy
except ImportError:
    import scapy

# Global variables for caching and configuration
checked_ips = []
ar = "False"

# Load YAML configuration file


def config_loader(filename="conf.yaml"):
    if not os.path.exists(filename):
        print("Error: Configuration file not found!", file=sys.stderr)
        sys.exit(1)
    with open(filename, "r") as f:
        return yaml.safe_load(f)


# Lookup port description from ICANN CSV database


def get_port_description(port, protocol="tcp"):
    if not os.path.exists(icann_csv_path):
        print("Error: ICANN port description database file not found!", file=sys.stderr)
        return "ICANN port description file not found!"
    with open(icann_csv_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if "Port Number" in row and "Service Name" in row:
                try:
                    if (
                        int(row["Port Number"]) == port
                        and row["Transport Protocol"].lower() == protocol
                    ):
                        return (
                            row["Description"]
                            if "Description" in row
                            else "No description available"
                        )
                except ValueError:
                    continue


# Perform reverse DNS lookup for an IP address


def reverse_dns_lookup(ip):
    try:
        dat = socket.gethostbyaddr(ip)
        return (
            {"Resolved": True, "Error": "", "Hostnames": dat}
            if dat and len(dat) > 0
            else {"Resolved": False, "Error": "No PTR record found", "Hostnames": []}
        )
    except Exception as e:
        return {
            "Resolved": False,
            "Error": "Address resolution error: " + str(e),
            "Hostnames": [],
        }


# Fetch server banner and SSL certificate information for a given IP and port


def get_serv_banner(ip, port, t, hostname):
    socket_cert = "Unavailable"
    encrypted_with = "N/A"
    ssl_version = "N/A"
    pt = "N/A"
    bannerdata = {}
    # Get page title for HTTP/HTTPS ports
    if port in [80, 8080, 443]:
        if port == 443:
            pt = get_page_title("https://" + hostname + ":" + str(port), t)
        else:
            pt = get_page_title("http://" + hostname + ":" + str(port), t)
    else:
        pt = "N/A"
    # Check cache for previous banner fetch
    for item in checked_ips:
        if item.get("IP") == ip and item.get("Port") == port:
            return item
    # Try to fetch SSL certificate
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_sock = context.wrap_socket(s, server_hostname=ip)
        ssl_sock.connect((ip, port))
        if ssl_sock:
            socket_cert = ssl_sock.getpeercert()
            encrypted_with = ssl_sock.cipher()
            ssl_version = ssl_sock.version()
        s.close()
    except Exception:
        pass
    # Try to fetch banner from server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        if len(banner) > 0:
            bannerdata = {
                "IP": ip,
                "Port": port,
                "Banner": banner,
                "Page Title": pt,
                "SSL Cert": socket_cert,
                "SSL Version": ssl_version,
                "Encrypted With": encrypted_with,
            }
            checked_ips.append(bannerdata)
            s.close()
            return bannerdata
        else:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if len(banner) > 0:
                bannerdata = {
                    "IP": ip,
                    "Port": port,
                    "Banner": banner,
                    "Page Title": pt,
                    "SSL Cert": socket_cert,
                    "SSL Version": ssl_version,
                    "Encrypted With": encrypted_with,
                }
                checked_ips.append(bannerdata)
                return bannerdata
            else:
                return {
                    "IP": ip,
                    "Port": port,
                    "Banner": "Error fetching banner",
                    "Page Title": pt,
                    "SSL Cert": socket_cert,
                    "SSL Version": ssl_version,
                    "Encrypted With": encrypted_with,
                }
    except Exception as e:
        nobdat = {
            "IP": ip,
            "Port": port,
            "Banner": "Error fetching banner: " + str(e),
            "Page Title": pt,
            "SSL Cert": socket_cert,
            "SSL Version": ssl_version,
            "Encrypted With": encrypted_with,
        }
        checked_ips.append(nobdat)
        return nobdat


# Fetch the page title from a URL


def get_page_title(url, t):
    try:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        res = requests.get(url, timeout=t, verify=False)
        res.raise_for_status()
        cont = res.content
        soup = BeautifulSoup(cont, "html.parser")
        return (
            soup.title.string
            if soup.title
            else "Error Fetching title: 200 No webpage title found"
        )
    except Exception as e:
        return "Error fetching title: " + str(e)


# Write raw packet data to a testcase file


def write_testcase(data, output_dir, pdir, index):
    if not os.path.exists(output_dir + "/" + pdir):
        os.mkdir(output_dir + "/" + pdir)
    out = open(
        output_dir + "/" + pdir + "/pcap.data_packet." + str(index) + ".dat", "wb"
    )
    out.write(data)


# Write packet info and extra info to JSON files


def write_info(output_dir, pdir, index, dt_json, pkt_json):
    out = open(
        output_dir + "/" + pdir + "/pcap.info_packet." + str(index) + ".json", "wb"
    )
    merge_json = {
        "Packet Info": json.loads(pkt_json),
        "Extra Info": json.loads(dt_json),
    }
    out.write(json.dumps(merge_json).encode())
    out.close()
    main = open("all_testcases_info.json", "a")
    main.write(json.dumps(merge_json) + "\n")
    main.close()
    if verbose >= 2:
        print(json.dumps(merge_json, indent=2))
    return merge_json


# Determine IP network class (A/B/C/D/E)


def get_netclass(ip):
    fo = int(ip.split(".")[0])
    if 0 <= fo <= 127:
        return "A"
    elif 128 <= fo <= 191:
        return "B"
    elif 192 <= fo <= 223:
        return "C"
    else:
        return "Unknown (D/E)?"


# Safely decompress data using zlib/gzip


def safe_decompress(compressed_data):
    # Initialize decompressor
    # Handle gzip and zlib formats
    dco = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    result = b""
    try:
        result = dco.decompress(compressed_data)
        result += dco.flush()
    except zlib.error as e:
        pass
    return result


# Get GeoIP information for an IP address


def get_geoip_info(ip):
    if not os.path.exists(geodat_path):
        return {"Location": "Error: GeoIP database not found!"}
    try:
        with geoip2.database.Reader(geodat_path) as reader:
            response = reader.city(ip)
            return {
                "Country": response.country.name,
                "City": response.city.name,
                "Postal Code": response.postal.code,  # type: ignore
                "Time Zone": response.location.time_zone,  # type: ignore
            }
    except geoip2.errors.AddressNotFoundError:  # type: ignore
        return {"Location": "Localnet"}
    except Exception as e:
        return {"Location": "Error: " + str(e)}


# Analyze packet data for MIME type, decompression, and traits


def get_datatypes(data, dport, srcip, destip, tmout):
    mime_type = magic.from_buffer(data, mime=True)
    descs = []
    dedata = ""
    compressedd = {"Decompressed": False}
    for ln in data.splitlines():
        descs.append(magic.from_buffer(ln))
        dedata = safe_decompress(ln)
        if dedata and len(dedata) > 0:
            compressedd = {
                "Decompressed data": {
                    "Decompressed Hex Encoded": dedata.hex(),
                    "Decompressed ASCII Encoded": dedata.decode(errors="ignore"),
                },
            }
    udescs = list(set(descs))
    if "empty" in udescs:
        udescs.remove("empty")
    if "data" in udescs:
        udescs.remove("data")
    if udescs == []:
        udescs = ["Unknown data type"]
    trait_struct = get_traits(data, dport, srcip, destip, tmout)
    dt = {
        "MIME Type": mime_type,
        "Decompressed": compressedd,
        "Data Types": udescs,
        "Traits": trait_struct,
    }
    return dt


# Get service name for a port using socket library


def get_serv(port, protocol="tcp"):
    try:
        serv_name = socket.getservbyport(port, protocol)
        return serv_name
    except Exception:
        return "Unknown"


# Extract traits from packet data (entropy, network info, banners, charset, etc.)


def get_traits(data, dport, srcip, destip, timeout):
    counts = np.bincount(list(data))
    entop = entropy(counts, base=2)
    data_len = len(data)
    protostr = get_serv(dport)
    charset = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    chars_used = len(set(data))
    uniq_chars = set(data)
    if ar:
        hostn = reverse_dns_lookup(destip)
    else:
        hostn = {
            "Resolved": False,
            "Error": "Active recon not performed",
            "Hostnames": [],
        }
    if ar:
        banner = get_serv_banner(
            destip,
            dport,
            timeout,
            hostn.get("Hostnames")[0] if hostn.get("Resolved") else destip,
        )
    else:
        banner = "Active recon not performed"
    encoding = chardet.detect(data)
    loc_info_src = get_geoip_info(srcip)
    loc_info_dest = get_geoip_info(destip)
    nc_info_src = get_netclass(srcip)
    nc_info_dest = get_netclass(destip)
    port_desc = get_port_description(dport)
    return {
        "Shannon Entropy": entop,
        "Network Data": {
            "Source IP": {
                "Class": nc_info_src,
                "Location": loc_info_src,
            },
            "Destination IP": {
                "Class": nc_info_dest,
                "Location": loc_info_dest,
            },
            "Port Protcol": protostr,
            "Port Description": port_desc,
            "Hostnames": hostn,
        },
        "Length": data_len,
        "Server Info": banner,
        "Characters": {
            "Charset": charset,
            "Encoding": encoding,
            "Characters used": chars_used,
            "Unique characters": bytearray(list(uniq_chars)).hex(),
        },
    }


# Lookup MAC address vendor from CSV database


def mac_addr_to_vendor(mac):
    if not os.path.exists(mac_vendors_path):
        print("Error: MAC vendor database file not found!", file=sys.stderr)
        return "Error: MAC vendor file not found!"
    with open(mac_vendors_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if "Mac Prefix" in row and "Vendor Name" in row:
                if mac.upper().startswith(row["Mac Prefix"].upper()):
                    return row["Vendor Name"]


# Parse .pcap file and generate testcases and info files


def parse_pcap(pcap_path, srcp, dstp, tmout):
    print("Generating testcases based on " + pcap_path + ".  This will take a while...")
    s = 0
    packets = scapy.rdpcap(pcap_path)  # type: ignore
    for p in packets:
        mac_addr_src = p.src if p.haslayer("Ethernet") else "N/A"
        mac_addr_dst = p.dst if p.haslayer("Ethernet") else "N/A"
        mac_vendor_src = (
            mac_addr_to_vendor(mac_addr_src) if mac_addr_src != "N/A" else "N/A"
        )
        mac_vendor_dst = (
            mac_addr_to_vendor(mac_addr_dst) if mac_addr_dst != "N/A" else "N/A"
        )
        if p.haslayer("TCP"):
            raw_d = p["TCP"].payload.original
            sport = p["TCP"].sport
            dport = p["TCP"].dport
            dport_dir = str(dport)
            if (srcp is None or sport == srcp) and (dstp is None or dport == dstp):
                if raw_d is not None and len(raw_d) > 0:
                    write_testcase(raw_d, args.output, dport_dir, s)
                    dt_struct = get_datatypes(
                        raw_d, dport, p["IP"].src, p["IP"].dst, tmout
                    )
                    timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                        "%Y-%m-%d %H:%M:%S.%f"
                    )
                    flag_data = ""
                    if p["TCP"].flags.S:
                        flag_data += "SYN|"
                    if p["TCP"].flags.A:
                        flag_data += "ACK|"
                    if p["TCP"].flags.F:
                        flag_data += "FIN|"
                    if p["TCP"].flags.R:
                        flag_data += "RST|"
                    if p["TCP"].flags.P:
                        flag_data += "PSH|"
                    if p["TCP"].flags.U:
                        flag_data += "URG|"
                    if p["TCP"].flags.ECE:
                        flag_data += "ECE|"
                    if p["TCP"].flags.CWR:
                        flag_data += "CWR|"
                    if flag_data.endswith("|"):
                        flag_data = flag_data[:-1]

                    pkt_struct = {
                        "Packet Processed": int(s),
                        "Packet Timestamp": timestamp,
                        "Ethernet Frame": {
                            "MAC Source": mac_addr_src,
                            "MAC Destination": mac_addr_dst,
                            "MAC Source Vendor": mac_vendor_src,
                            "MAC Destination Vendor": mac_vendor_dst,
                        },
                        "IP": {
                            "Source IP": str(p["IP"].src),
                            "Destination IP": str(p["IP"].dst),
                            "IP Checksum": hex(int(p["IP"].chksum)),
                            "IP layer length": int(p["IP"].len),
                        },
                        "TCP": {
                            "Source port": int(sport),
                            "Destination port": int(dport),
                            "TCP checksum": int(p["TCP"].chksum),
                            "Urgent flag": bool(p["TCP"].urgptr),
                            "TCP Flag Data": {
                                "List": str(p["TCP"].flags),
                                "Translated": flag_data if flag_data else "None",
                            },
                            "Options": list(p["TCP"].options),
                            "TCP layer length": int(p["TCP"].dataofs * 4),
                            "Wire length": len(p["TCP"]),
                        },
                        "Raw data": {
                            "Payload": {
                                "Hex Encoded": raw_d.hex(),
                                "ASCII Encoded": raw_d.decode(errors="ignore"),
                            },
                            "Packet": bytes(p).hex(),
                            "Payload Length": len(raw_d),
                        },
                    }
                    write_info(
                        args.output,
                        dport_dir,
                        s,
                        json.dumps(dt_struct).encode(),
                        json.dumps(pkt_struct).encode(),
                    )
                    s = s + 1
    print("Generated " + str(s) + " testcases.", file=sys.stderr)


# Argument parser setup for command-line options
parser = argparse.ArgumentParser(
    prog="gen_testcase.py",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(
        f"""
This script generates payload testcases from a .pcap file. It extracts packet data,
writes testcases, and gathers extra information such as MIME types, entropy, geoip,
network class, banners, and more. Optionally, it performs active reconnaissance
to enrich the output with additional network and server information.

        Outputs:
          - Testcase files: output_dir/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: output_dir/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for all testcases
                                 """,
    ),
    epilog="Example usage: \n   python3 gen_testcase.py traffic.pcap -o output_dir -s 80 -d 8080 -T 5 -a",
)
parser.add_argument("pcap_file", help="The .pcap file to parse.")
parser.add_argument(
    "-o",
    "--output",
    help="The output directory for the testcases.",
    default="testcases",
)
parser.add_argument(
    "-s",
    "--source-port",
    help="Only generate testcases from this source port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
parser.add_argument(
    "-T",
    "--timeout",
    help="Timeout for network requests in seconds (default: 3).",
    type=int,
    default=3,
)
parser.add_argument(
    "-a",
    "--active-recon",
    help="Perform active reconnaissance to gather extra info (geoip, banners, titles).",
    action="store_true",
)
parser.add_argument(
    "-c",
    "--conf",
    help="Path to configuration YAML file (default: conf.yaml).",
)
parser.add_argument(
    "-v",
    "--verbose",
    help="Enable verbose output for debugging.",
    action="count",
    default=0,
)
verbose = parser.parse_args().verbose
args = parser.parse_args()
config = config_loader(args.conf if args.conf else "conf.yaml")

# Load database paths from config and print status
if config["database_locations"]["geoip"]:
    geodat_path = config["database_locations"]["geoip"]
    if verbose >= 1:
        if os.path.exists(geodat_path):
            print("Using GeoIP Database found at: " + geodat_path, file=sys.stderr)
        else:
            print(
                "Error: GeoIP database file not found at specified location!",
                file=sys.stderr,
            )
else:
    if verbose >= 1:
        print(
            "Error: GeoIP database location not specified in config!", file=sys.stderr
        )
if config["database_locations"]["mac_vendors"]:
    mac_vendors_path = config["database_locations"]["mac_vendors"]
    if verbose >= 1:
        if os.path.exists(mac_vendors_path):
            print(
                "Using MAC Vendor Database found at: " + mac_vendors_path,
                file=sys.stderr,
            )
        else:
            print(
                "Error: MAC vendor database file not found at specified location!",
                file=sys.stderr,
            )
else:
    if verbose >= 1:
        print(
            "Error: MAC vendor database location not specified in config!",
            file=sys.stderr,
        )
if config["database_locations"]["icann_ports"]:
    icann_csv_path = config["database_locations"]["icann_ports"]
    if verbose >= 1:
        if os.path.exists(icann_csv_path):
            print(
                "Using ICANN Port Description Database found at: " + icann_csv_path,
                file=sys.stderr,
            )
        else:
            print(
                "Error: ICANN port description database file not found at specified location!",
                file=sys.stderr,
            )
else:
    if verbose >= 1:
        print(
            "Error: ICANN port description database location not specified in config!",
            file=sys.stderr,
        )

# Set active recon flag from config if not provided as argument
if not args.active_recon:
    if config["active_recon"]:
        ar = config["active_recon"]
    else:
        ar = False

# Main execution logic: check files, handle output directory, and run parsing
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(args.output):
    os.mkdir(args.output)
    parse_pcap(args.pcap_file, args.source_port, args.dest_port, args.timeout)
    sys.exit(0)
else:
    if (
        input(
            "Output directory already exists. Do you want to continue and potentially overwrite files? (y/n): "
        ).lower()
        != "y"
    ):
        print("Exiting to prevent overwriting files.", file=sys.stderr)
        sys.exit(1)
    try:
        if os.path.exists("all_testcases_info.json"):
            os.remove("all_testcases_info.json")
        if os.path.isdir(args.output):
            shutil.rmtree(args.output, ignore_errors=True)
        # Small delay to ensure file system has completed deletions
        time.sleep(1)
        os.mkdir(args.output)
        parse_pcap(args.pcap_file, args.source_port, args.dest_port, args.timeout)
        sys.exit(0)
    except Exception as e:
        print("Error clearing output directory: " + str(e), file=sys.stderr)
        sys.exit(1)

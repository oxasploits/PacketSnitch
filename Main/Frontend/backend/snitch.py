# oxagast
# Import standard and third-party libraries for argument parsing, file handling, networking, compression, and data processing
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
import threading
import numpy as np
import requests
import ollama
from ollama import ResponseError
import yaml
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from scipy.stats import entropy
from tqdm import tqdm
from threading import Thread

# Try importing scapy for packet parsing
try:
    import scapy.all as scapy
except ImportError:
    import scapy

# Global variables for caching and configuration
ar = "False"
percentage_pcap = 10
nthreads = 6
nllmthreads = 5
threads = []
pktnum = 0
response_length = 100
llm_model = "minimax-m2.5:cloud"
use_llm = False
summaries = []


def llm_query(packet_infos):
    if verbose == 0:
        print(".", end="", flush=True)
    try:
        if ollama and use_llm and packet_infos:
            # these are for retreies
            for resc in range(3):
                try:
                    if verbose == 0:
                        print(".", end="", flush=True)
                    res = ollama.generate(
                        model=llm_model,
                        prompt=f"Tell me what you can about the following network capture (encoded in json, from pcap), its payload, and any interesting or unusual traits... respond with a single paragraph around {response_length} words: {packet_infos}",
                    )
                    if res and "response" in res:
                        if verbose == 0:
                            print(".", end="", flush=True)
                        summaries.append(res["response"])
                    else:
                        return {"Summary": ""}
                except ResponseError as re:
                    if verbose >= 2:
                        print(
                            f"LLM API response error (attempt {resc + 1}/3): {str(re)}",
                            file=sys.stderr,
                        )
                    time.sleep(2**resc)  # Exponential backoff
        else:
            return {"Summary": "LLM integration not enabled"}
    except Exception as e:
        return {"Summary": "LLM integration error: " + str(e)}


# Load YAML configuration file
def config_loader(filename="conf.yaml"):
    if not os.path.exists(filename):
        print("Error: Configuration file not found!", file=sys.stderr)
        sys.exit(1)
    with open(filename, "r") as f:
        return yaml.safe_load(f)


# Lookup port description from ICANN CSV database
def get_port_description(port, protocol="tcp"):
    if verbose == 0:
        print(".", end="", flush=True)
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
    if verbose == 0:
        print(".", end="", flush=True)
    try:
        dat = socket.gethostbyaddr(ip)
        return (
            {"Resolved": True, "Hostnames": dat}
            if dat and len(dat) > 0
            else {"Resolved": False, "Error": "No PTR record found"}
        )
    except Exception as e:
        return {
            "Resolved": False,
            "Error": "Address resolution error: " + str(e),
        }


checked_ips = []


# Fetch server banner and SSL certificate information for a given IP and port
def get_serv_banner(ip, port, t, hostname):
    if verbose == 0:
        print(".", end="", flush=True)
    socket_cert = "Unavailable"
    encrypted_with = "N/A"
    ssl_version = "N/A"
    pt = "N/A"
    bannerdata = {}
    # Get page title for HTTP/HTTPS ports
    try:
        if port == 443:
            pt = get_page_title("https://" + hostname + ":" + str(port), t)
        else:
            pt = get_page_title("http://" + hostname + ":" + str(port), t)
    except Exception:
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
                "Banner": banner,
                "Page Title": pt,
                "Encryption Data": {
                    "SSL Cert": socket_cert,
                    "SSL Version": ssl_version,
                    "Encrypted With": encrypted_with,
                }
                if ssl_version != "N/A"
                else "N/A",
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
                    "Banner": banner,
                    "Page Title": pt,
                    "Encryption Data": {
                        "SSL Cert": socket_cert,
                        "SSL Version": ssl_version,
                        "Encrypted With": encrypted_with,
                    }
                    if ssl_version != "N/A"
                    else "N/A",
                }
                checked_ips.append(bannerdata)
                return bannerdata
            else:
                return {
                    "Page Title": pt,
                    "Encryption Data": {
                        "SSL Cert": socket_cert,
                        "SSL Version": ssl_version,
                        "Encrypted With": encrypted_with,
                    }
                    if ssl_version != "N/A"
                    else "N/A",
                }
    except Exception as e:
        nobdat = {
            "Page Title": pt,
            "Encryption Data": {
                "SSL Cert": socket_cert,
                "SSL Version": ssl_version,
                "Encrypted With": encrypted_with,
            }
            if ssl_version != "N/A"
            else "N/A",
        }
        checked_ips.append(nobdat)
        return nobdat


# Fetch the page title from a URL
def get_page_title(url, t):
    if verbose == 0:
        print(".", end="", flush=True)
    try:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        res = requests.get(url, timeout=t, verify=False)
        res.raise_for_status()
        cont = res.content
        soup = BeautifulSoup(cont, "html.parser")
        return soup.title.string if soup.title else "N/A"
    except Exception:
        return "N/A"


# Write raw packet data to a testcase file
def write_testcase(data, output_dir, pdir, index):
    if verbose == 0:
        print(".", end="", flush=True)
    if not os.path.exists(output_dir + "/" + pdir):
        try:
            os.mkdir(output_dir + "/" + pdir)
        except Exception as e:
            print("Error: Could not create minor dir: " + str(e), file=sys.stderr)
    out = open(
        output_dir + "/" + pdir + "/pcap.data_packet." + str(index) + ".dat", "wb"
    )
    out.write(data)


all_info = []


# Write packet info and extra info to JSON files
def join_info(output_dir, pdir, index, dt_json, pkt_json, perp, host):
    if verbose == 0:
        print(".", end="", flush=True)
    out = open(
        output_dir + "/" + pdir + "/pcap.info_packet." + str(index) + ".json", "wb+"
    )
    merge_json = {
        "Packet Info": json.loads(pkt_json),
        "Extra Info": json.loads(dt_json),
    }
    out.write(json.dumps(merge_json).encode())
    out.close()
    if verbose >= 2:
        print(json.dumps(merge_json, indent=2))
    all_info.append({"Host": host, "Packet": merge_json})
    return merge_json


by_host_dict = {}


def by_host(out, final_summary):
    if verbose == 0:
        print(".", end="", flush=True)
    for host in all_info:
        if host.get("Host") not in by_host_dict:
            by_host_dict[host.get("Host")] = []
        else:
            by_host_dict[host.get("Host")].append(host.get("Packet"))
    open(out + "/all_testcases_info_by_host.json", "w+").write(
        json.dumps({"Host": by_host_dict, "Final Summary": final_summary}, indent=2)
    )


# Determine IP network class (A/B/C/D/E)
def get_netclass(ip):
    if verbose == 0:
        print(".", end="", flush=True)
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
    if verbose == 0:
        print(".", end="", flush=True)
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
    if verbose == 0:
        print(".", end="", flush=True)
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
        if verbose == 0:
            print(".", end="", flush=True)
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
    if verbose == 0:
        print(".", end="", flush=True)
    try:
        serv_name = socket.getservbyport(port, protocol)
        return serv_name
    except Exception:
        return "Unknown"


# Extract traits from packet data (entropy, network info, banners, charset, etc.)
def get_traits(data, dport, srcip, destip, timeout):
    if verbose == 0:
        print(".", end="", flush=True)
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
            "Encoding": encoding
            if entop <= 4.85
            else "Unavailable for high entropy data",
            "Characters used": chars_used,
            "Unique characters": bytearray(list(uniq_chars)).hex(),
        },
    }


# Lookup MAC address vendor from CSV database
def mac_addr_to_vendor(mac):
    if verbose == 0:
        print(".", end="", flush=True)
    if not os.path.exists(mac_vendors_path):
        print("Error: MAC vendor database file not found!", file=sys.stderr)
        return "Error: MAC vendor file not found!"
    with open(mac_vendors_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if "Mac Prefix" in row and "Vendor Name" in row:
                if mac.upper().startswith(row["Mac Prefix"].upper()):
                    return row["Vendor Name"]


def packet_loop(p, from_p, pcap_path, percentage_p, srcp, dstp, tmout):
    total_pkts = len(scapy.rdpcap(pcap_path))  # type: ignore
    per_pkts = int((percentage_p / 100) * total_pkts)
    pp = int((percentage_p / 100) * per_pkts)
    s = from_p
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
                write_testcase(raw_d, outd, dport_dir, s)
                dt_struct = get_datatypes(raw_d, dport, p["IP"].src, p["IP"].dst, tmout)
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
                    }
                    if get_geoip_info(p["IP"].src).get("Location") == "Localnet"
                    and get_geoip_info(p["IP"].dst).get("Location") == "Localnet"
                    else "N/A",
                    "IP": {
                        "Source IP": str(p["IP"].src),
                        "Destination IP": str(p["IP"].dst),
                        "IP Checksum": hex(int(p["IP"].chksum)),
                        "IP layer length": int(p["IP"].len),
                    },
                    "TCP": {
                        "Source port": int(sport),
                        "Destination port": int(dport),
                        "TCP checksum": hex(int(p["TCP"].chksum)),
                        "Urgent flag": bool(p["TCP"].urgptr),
                        "TCP Flag Data": {
                            "Flags": flag_data if flag_data else "None",
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
                data_back = join_info(
                    outd,
                    dport_dir,
                    s,
                    json.dumps(dt_struct).encode(),
                    json.dumps(pkt_struct).encode(),
                    pp,
                    p["IP"].dst
                    if get_geoip_info(p["IP"].dst).get("Location") != "Localnet"
                    else p["IP"].src,
                )
                s = s + 1
                return data_back


# Parse .pcap file and generate testcases and info files
def parse_pcap(pcap_path, srcp, dstp, tmout, percentage_p, from_p, to_p, thread_id):
    if verbose >= 2:
        print(
            "Starting thread "
            + str(thread_id)
            + " for packets "
            + str(from_p)
            + " to "
            + str(to_p),
            file=sys.stderr,
        )
        time.sleep(1)
    packets = scapy.rdpcap(pcap_path)  # type: ignore
    for p in packets[int(from_p) : int(to_p)]:
        if verbose == 0:
            print(".", end="", flush=True)
        packet_loop(p, from_p, pcap_path, percentage_p, srcp, dstp, tmout)


summaries_batch = []


def information_seive(sz):
    batch_size = sz
    # loop over a batch of packets stored in all_info and for every batch_size packets send them to the llm for analysis, where their response will be added to summaries[] for later
    for i in range(0, len(all_info), batch_size):
        if verbose == 0:
            print(".", end="", flush=True)
        if i + batch_size > len(all_info):
            batch = all_info[i:]
            summaries_batch.append(batch)
        else:
            batch = all_info[i : i + batch_size]
            summaries_batch.append(batch)

        if verbose >= 2 and batch:
            print(
                f"\nLLM analysis for batch {i} to {i + batch_size}\n",
                file=sys.stderr,
            )
    for b in range(nllmthreads):
        t = threading.Thread(
            target=llm_query,
            args=(json.dumps(summaries_batch[b]),),
            name="LLM Analysis Thread " + str(b),
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
        if verbose >= 2:
            print("Completed: " + t.name, file=sys.stderr)


def start_threading():
    if __name__ == "__main__":
        pcap_percentage = 100
        print(
            "Spooling up " + str(nthreads) + " threads to process packets...",
            file=sys.stderr,
        )
        for c in range(nthreads):
            step = int(totalp / nthreads)
            start = int(c * step) if c != 0 else 0
            end = int((c + 1) * step) if c != nthreads - 1 else totalp
            t = threading.Thread(
                target=parse_pcap,
                args=(
                    args.pcap_file,
                    args.source_port,
                    args.dest_port,
                    args.timeout,
                    pcap_percentage,
                    start,
                    end,
                    c,
                ),
                name="Packet Processing Thread " + str(c),
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()


# Argument parser setup for command-line options
parser = argparse.ArgumentParser(
    prog="snitch.py",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(
        f"""
PacketSnitch.
This software analyzes pcap network captures. It extracts mostly TCP packet data,
writes testcases, and gathers extra information such as MIME types, entropy, geoip,
network class, banners, and more. Optionally, it performs active reconnaissance
to enrich the output with additional network and server information.  A full capture
summary is generated using a large languuage model to provide insights into the data.

        Outputs:
          - Testcase files: output_dir/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: output_dir/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for the entire
            capture.
                                 """,
    ),
    epilog="Example usage: \n   python3 snitch.py traffic.pcap -o output_dir -s 80 -d 8080 -T 5 -a",
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
    help="Only generate from this source port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate for this destination port.",
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
totalp = 0
packets = scapy.rdpcap(args.pcap_file)  # type: ignore
# The PacketList object provides a summary of included protocols
# Use len() to get the total number of packets in the file
total_packets = len(packets)
# To count specifically TCP packets using a filter function:
totalp = len([p for p in packets if p.haslayer("TCP")])
if totalp == 0:
    print("No packets found matching the specified port filters.", file=sys.stderr)
    exit(1)
if "threads" in config and config["threads"]:
    nthreads = config["threads"]
outd = "testcases"
if args.output and args.output != "testcases":
    outd = args.output
    print("Using output directory: " + args.output, file=sys.stderr)
if "output_dir" in config:
    outd = config["output_dir"]
    print("Using output directory from config: " + outd, file=sys.stderr)
# Set active recon flag from config if not provided as argument
if not args.active_recon:
    if config["active_recon"]:
        ar = config["active_recon"]
    else:
        ar = False
if "ollama" in config and config["ollama"].get("model"):
    if config["ollama"].get("use_llm", False) and verbose >= 1:
        print(
            "LLM integration enabled. Using model: "
            + config["ollama"]["model"]
            + ". LLM analysis will be included for every "
            + str(config["ollama"].get("pcap_percentage", 10))
            + "% of packets.",
            file=sys.stderr,
        )
        llm_model = config["ollama"]["model"]
    response_length = config["ollama"].get("response_length", 200)
    bs = config["ollama"].get("batch_size", 5)
    use_llm = config["ollama"].get("use_llm", False)
else:
    llm_model = "minimax-m2.5:cloud"
    response_length = 200
    use_llm = False
if llm_model and use_llm:
    if llm_model.endswith(":cloud"):
        if verbose >= 2:
            print(
                "Using cloud-based LLM model: "
                + llm_model
                + ". Ensure you have network connectivity and API access.",
                file=sys.stderr,
            )
print(
    "Preparing to process "
    + str(totalp)
    + " packets with "
    + str(nthreads)
    + " threads.",
    file=sys.stderr,
)
# Main execution logic: check files, handle output directory, and run parsing
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(outd):
    try:
        os.mkdir(outd)
        final_s = start_threading()
        by_host(outd, final_s)
    except Exception as e:
        final_s = start_threading()
        by_host(outd, final_s)
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
        if os.path.isdir(outd):
            shutil.rmtree(outd, ignore_errors=True)
        # Small delay to ensure file system has completed deletions
        time.sleep(1)
        try:
            os.mkdir(outd)
            final_s = start_threading()
            by_host(outd, final_s)
        except Exception as e:
            final_s = start_threading()
            by_host(outd, final_s)
    finally:
        information_seive(bs)
        if verbose == 0:
            print(".", end="", flush=True)
        if config.get("final_summary", True) and config["ollama"].get("use_llm", True):
            drilldown = (
                " ".join(summaries) if summaries else "No LLM summaries generated."
            )
            try:
                final_res = ollama.generate(
                    model=llm_model,
                    prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
                    + drilldown[:200000],
                )
                if final_res and "response" in final_res:
                    print(
                        "\nFinal LLM Summary of Packet Analyses:\n"
                        + final_res["response"]
                    )
                    final_summary = final_res["response"]
                    open(outd + "/final_summary.txt", "w").write(final_summary)
                    print("\n" + final_summary)
                    print("\nFinal summary saved to: " + outd + "/final_summary.txt")
                else:
                    print(
                        "\nLLM Final summary generation failed or returned no response."
                    )
            except Exception as e:
                print("\nLLM Final summary generation error: " + str(e))

        print(
            "Processing complete. Generated testcases and info files are located in: "
            + outd,
            file=sys.stderr,
        )

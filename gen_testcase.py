# oxagast
# use:
#   tcpdump -w ~/capture.pcap 'port 9000'
#   python3 pcap_gen_testcases.py ~/capture.pcap
# this will create a testcase directory of each destination port filled with files each
# the data section of the packets in the pcap file.  One packet is one file.  TCP header
# info is stripped.

import os
import sys
import argparse
import magic
import json
import numpy as np
from scipy.stats import entropy
import socket
import chardet
import gzip
import zlib

try:
    import scapy.all as scapy
except ImportError:
    import scapy


def write_testcase(data, output_dir, pdir, index):
    if not os.path.exists(output_dir + "/" + pdir):
        os.mkdir(output_dir + "/" + pdir)
    out = open(
        output_dir + "/" + pdir + "/pcap.data_packet." + str(index) + ".dat", "wb"
    )
    out.write(data)


def write_info(output_dir, pdir, index, dt_json, pkt_json):
    out = open(
        output_dir + "/" + pdir + "/pcap.info_packet." + str(index) + ".json", "wb"
    )
    merge_json = {
        "Packet Data": json.loads(pkt_json),
        "Extra Info": json.loads(dt_json),
    }
    out.write(json.dumps(merge_json).encode())
    return merge_json


def get_datatypes(data, dport):
    mime_type = magic.from_buffer(data, mime=True)
    descs = []
    dedata = ""
    for ln in data.splitlines():
        descs.append(magic.from_buffer(ln))
        if magic.from_buffer(ln) == "gzip compressed data":
            dedata = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16).decompress(ln)
            get_datatypes(dedata, dport)
            dt = {
                "MIME Type": mime_type,
                "data": descs,
                "Decompressed data": dedata.hex(),
            }
            return dt
    udescs = list(set(descs))
    if "empty" in udescs:
        udescs.remove("empty")
    if "data" in udescs:
        udescs.remove("data")
    trait_struct = get_traits(data, dport)
    dt = {
        "MIME Type": mime_type,
        "data": udescs,
        "Traits": trait_struct,
    }
    return dt


def get_serv(port, protocol="tcp"):
    try:
        service_name = socket.getservbyport(port, protocol)
        return service_name
    except Exception:
        return "Unknown"


def get_traits(data, dport):
    counts = np.bincount(list(data))
    entop = entropy(counts, base=2)
    data_len = len(data)
    protostr = get_serv(dport)
    charset = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    chars_used = len(set(data))
    uniq_chars = set(data)
    encoding = chardet.detect(data)
    return {
        "Shannon Entropy": entop,
        "Length": data_len,
        "Protocol": protostr,
        "Characters": {
            "Charset": charset,
            "Characters used": chars_used,
            "Unique characters": bytearray(list(uniq_chars)).hex(),
            "Encoding": encoding,
        },
    }


def parse_pcap(pcap_path, srcp, dstp):
    print(
        "Generating testcases based on " + sys.argv[1] + ".  This will take a while..."
    )
    s = 0
    packets = scapy.rdpcap(pcap_path)
    for p in packets:
        if p.haslayer("TCP"):
            raw_d = p["TCP"].payload.original
            sport = p["TCP"].sport
            dport = p["TCP"].dport
            dport_dir = str(dport)
            if (srcp is None or sport == srcp) and (dstp is None or dport == dstp):
                if raw_d is not None and len(raw_d) > 0:
                    write_testcase(raw_d, args.output, dport_dir, s)
                    dt_struct = get_datatypes(raw_d, dport)
                    pkt_struct = {
                        "Packet Processed": int(s),
                        "IP": {
                            "Source IP": str(p["IP"].src),
                            "Destination IP": str(p["IP"].dst),
                            "IP Checksum": int(p["IP"].chksum),
                        },
                        "TCP": {
                            "Source port": int(sport),
                            "Destination port": int(dport),
                            "TCP checksum": int(p["TCP"].chksum),
                            "Urgent flag": bool(p["TCP"].urgptr),
                            "TCP flags": str(p["TCP"].flags),
                            "Options": list(p["TCP"].options),
                        },
                        "Payload": raw_d.hex(),
                        "Packet": bytes(p).hex(),
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


parser = argparse.ArgumentParser(
    description="Generate payload testcases from a .pcap file.", prog="gen_testcases"
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
    help="Only generate testcases for this destination port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
args = parser.parse_args()
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(args.output):
    os.mkdir(args.output)
print(parse_pcap(args.pcap_file, args.source_port, args.dest_port))
print("Done.", file=sys.stderr)
sys.exit(0)

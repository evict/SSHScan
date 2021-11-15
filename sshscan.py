#!/usr/bin/env python3

import sys
import socket
import struct
from yaml import safe_load
from typing import List, Tuple
from secrets import token_bytes
from binascii import hexlify
from optparse import OptionParser, OptionGroup


def banner():
    banner = """
      _____ _____ _    _ _____
     /  ___/  ___| | | /  ___|
     \ `--.\ `--.| |_| \ `--.  ___ __ _ _ __
      `--. \`--. |  _  |`--. \/ __/ _` | '_ \\
     /\__/ /\__/ | | | /\__/ | (_| (_| | | | |
     \____/\____/\_| |_\____/ \___\__,_|_| |_|
                                            evict
                """
    return banner


def print_columns(cipherlist):
    # adjust the amount of columns to display
    cols = 2
    while len(cipherlist) % cols != 0:
        cipherlist.append("")
    else:
        split = [
            cipherlist[i : i + int(len(cipherlist) / cols)]
            for i in range(0, len(cipherlist), int(len(cipherlist) / cols))
        ]
        for row in zip(*split):
            print("            " + "".join(str.ljust(c, 37) for c in row))
    print("\n")


def return_diff_list(detected, strong):

    results = []

    for item in detected:
        if item not in strong:
            results.append(item)
    
    return results

def parse_results(version, kex, salg, enc, mac, cmpv):

    version = version.decode("utf-8").rstrip()
    kex = kex.decode("utf-8").split(",")
    salg = salg.decode("utf-8").split(",")
    enc = enc.decode("utf-8").split(",")
    mac = mac.decode("utf-8").split(",")
    cmpv = cmpv.decode("utf-8").split(",")

    with open("config.yml") as fd:
        config = safe_load(fd)

    weak_ciphers = return_diff_list(enc, config["ciphers"])
    weak_macs = return_diff_list(mac, config["macs"])
    weak_kex = return_diff_list(kex, config["kex"])
    weak_hka = return_diff_list(salg, config["hka"])

    compression = True if "zlib@openssh.com" in cmpv else False

    print("    [+] Detected the following ciphers: ")
    print_columns(enc)
    print("    [+] Detected the following KEX algorithms: ")
    print_columns(kex)
    print("    [+] Detected the following MACs: ")
    print_columns(mac)
    print("    [+] Detected the following HostKey algorithms: ")
    print_columns(salg)

    print("    [+] Target SSH version is: %s" % version)
    print("    [+] Retrieving ciphers...")

    if weak_ciphers:
        print("    [+] Detected the following weak ciphers: ")
        print_columns(weak_ciphers)
    else:
        print("    [+] No weak ciphers detected!")

    if weak_kex:
        print("    [+] Detected the following weak KEX algorithms: ")
        print_columns(weak_kex)
    else:
        print("    [+] No weak KEX detected!")

    if weak_macs:
        print("    [+] Detected the following weak MACs: ")
        print_columns(weak_macs)
    else:
        print("    [+] No weak MACs detected!")

    if weak_hka:
        print("    [+] Detected the following weak HostKey algorithms: ")
        print_columns(weak_hka)
    else:
        print("    [+] No weak HostKey algorithms detected!")

    if compression:
        print("    [+] Compression has been enabled!")


def unpack_ssh_name_list(kex, n):
    """
    Unpack the name-list from the packet
    The comma separated list is preceded by an unsigned
    integer which specifies the size of the list.
    """

    size = struct.unpack("!I", kex[n : n + 4])[0] + 1

    # jump to the name-list
    n += 3
    payload = struct.unpack(f"!{size}p", kex[n : n + size])[0]

    # to the next integer
    n += size

    return payload, n


def unpack_msg_kex_init(kex):

    # the MSG for KEXINIT looks as follows
    #      byte         SSH_MSG_KEXINIT
    #      byte[16]     cookie (random bytes)
    #      name-list    kex_algorithms
    #      name-list    server_host_key_algorithms
    #      name-list    encryption_algorithms_client_to_server
    #      name-list    encryption_algorithms_server_to_client
    #      name-list    mac_algorithms_client_to_server
    #      name-list    mac_algorithms_server_to_client
    #      name-list    compression_algorithms_client_to_server
    #      name-list    compression_algorithms_server_to_client
    #      name-list    languages_client_to_server
    #      name-list    languages_server_to_client
    #      boolean      first_kex_packet_follows
    #      uint32       0 (reserved for future extension)

    packet_size = struct.unpack("!I", kex[0:4])[0]
    print(f"[*] KEX size: {packet_size}")
    message = kex[5]  # 20 == SSH_MSG_KEXINIT

    if message != 20:
        raise ValueError("did not receive SSH_MSG_KEXINIT")

    cookie = struct.unpack("!16p", kex[6:22])[0]

    print(f"[*] server cookie: {hexlify(cookie).decode('utf-8')}")

    kex_size = struct.unpack("!I", kex[22:26])[0]
    kex_size += 1

    kex_algos = struct.unpack(f"!{kex_size}p", kex[25 : 25 + kex_size])[0]

    n = 25 + kex_size

    server_host_key_algo, n = unpack_ssh_name_list(kex, n)

    enc_client_to_server, n = unpack_ssh_name_list(kex, n)
    enc_server_to_client, n = unpack_ssh_name_list(kex, n)

    mac_client_to_server, n = unpack_ssh_name_list(kex, n)
    mac_server_to_client, n = unpack_ssh_name_list(kex, n)

    cmp_client_to_server, n = unpack_ssh_name_list(kex, n)
    cmp_server_to_client, n = unpack_ssh_name_list(kex, n)

    return (
        kex_algos,
        server_host_key_algo,
        enc_server_to_client,
        mac_server_to_client,
        cmp_server_to_client,
    )


def pack_msg_kexinit_for_server(kex, salg, enc, mac, cmpv):

    kex_fmt = f"!I{len(kex)}s"
    sal_fmt = f"!I{len(salg)}s"
    enc_fmt = f"!I{len(enc)}s"
    mac_fmt = f"!I{len(mac)}s"
    cmp_fmt = f"!I{len(cmpv)}s"

    kex = struct.pack(kex_fmt, len(kex), kex)
    sal = struct.pack(sal_fmt, len(salg), salg)
    enc = struct.pack(enc_fmt, len(enc), enc)
    mac = struct.pack(mac_fmt, len(mac), mac)
    cmpv = struct.pack(cmp_fmt, len(cmpv), cmpv)

    # languages are not used, therefore null
    # 4 bytes are reserved
    remain = b"\x00\x00\x00\x00"

    packet = b"\x20"
    packet += token_bytes(16)
    packet += kex
    packet += sal
    # we are lazy and have the ctos and stoc options same.
    # this should not be the case
    packet += enc
    packet += enc
    packet += mac
    packet += mac
    packet += cmpv
    packet += cmpv
    packet += b"\x00"
    packet += remain
    packet += b"\x00" * 8

    # + unsigned int + header
    size = len(packet) + 4 + 2

    # properly calculate the padding with length % 8
    padding_len = size % 8

    if padding_len < 4:
        padding_len = 4

    return _pack_packet(packet)


def retrieve_initial_kexinit(host: str, port: int) -> Tuple[List, List]:

    s = return_socket_for_host(host, port)

    version = s.recv(2048)
    s.send(version)

    kex_init = s.recv(4096)
    s.close()

    return kex_init, version


def return_socket_for_host(host, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    return s


def _pack_packet(packet):

    block_size = 8

    # https://github.com/paramiko/paramiko/blob/master/paramiko/packet.py#L631
    padding_len = 3 + block_size - ((len(packet) + 8) % block_size) + 1

    if padding_len < block_size:
        padding_len = block_size

    header = struct.pack(">IB", len(packet) + padding_len, padding_len)
    padding = b"\x00" * padding_len

    packet = header + packet + padding

    return packet


def main():

    print(banner())
    parser = OptionParser(usage="usage %prog [options]", version="%prog 2.0")
    parameters = OptionGroup(parser, "Options")

    parameters.add_option(
        "-t",
        "--target",
        type="string",
        help="Specify target as 'target' or 'target:port' (port 22 is default)",
        dest="target",
    )
    parameters.add_option(
        "-l",
        "--target-list",
        type="string",
        help="File with targets: 'target' or 'target:port' seperated by a newline (port 22 is default)",
        dest="targetlist",
    )
    parser.add_option_group(parameters)

    options, arguments = parser.parse_args()

    targets = []

    target = options.target
    targetlist = options.targetlist

    if target:
        targets.append(target)

    else:
        if targetlist:
            with open(targetlist) as fd:
                for item in fd.readlines():
                    targets.append(item.rstrip())

        else:
            print("[-] No target specified!")
            sys.exit(0)

    # we send first packets to make sure we match keys
    for target in targets:

        if ":" not in target:
            target += ":22"

        host, port = target.split(":")
        port = int(port)

        try:
            kex_init, version = retrieve_initial_kexinit(host, port)

        except socket.timeout:
            print("    [-] Timeout while connecting to %s on port %i\n" % (host, port))

        except socket.error as e:
            if e.errno == 61:
                print("    [-] %s\n" % (e.strerror))
            else:
                print(
                    "    [-] Error while connecting to %s on port %i\n" % (host, port)
                )

    # parse the server KEXINIT message
    kex, salg, enc, mac, cmpv = unpack_msg_kex_init(kex_init)

    parse_results(version, kex, salg, enc, mac, cmpv)


if __name__ == "__main__":
    main()

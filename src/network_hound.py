from scapy.all import *
from prettytable import PrettyTable
import pandas
import argparse
import socket
import time

df = pandas.DataFrame(
    columns=["Protocol", "Source", "Destination", "Length", "Info", "Timestamp", "Window Size", "Flags"])


def packet_callback(packet):

    protocol_name = "TCP"
    if packet.proto != 6:
        protocol_name = "UDP"

    x = PrettyTable()
    x.field_names = ["Protocol", "Source",
                     "Destination", "Length", "Info"]
    x.add_row([protocol_name, packet.src, packet.dst,
              packet.len,  packet.summary()])
    print("New Packet:")
    print(x)

    # only for TCP packets
    if protocol_name == "TCP":
        y = PrettyTable()
        y.field_names = ["Timestamp", "Window Size", "Flags"]
        y.add_row([time.ctime(packet.time), packet.window,
                   packet.sprintf("%TCP.flags%")])
        print(y)


def packet_callback_csv(packet, num_packets):

    global df
    if packet.proto != 6:
        protocol_name = "UDP"
        df = pandas.concat([df, pandas.DataFrame({"Protocol": [protocol_name],
                                                  "Source": [packet.src],
                                                  "Destination": [packet.dst],
                                                  "Info": [packet.summary()],
                                                  })], ignore_index=True)
        # count packets and informs user for each collected 50 package
        num_packets[0] += 1
        if num_packets[0] % 50 == 0:
            print(f"{num_packets[0]} packets captured so far...")

    else:
        protocol_name = "TCP"
        df = pandas.concat([df, pandas.DataFrame({"Protocol": [protocol_name],
                                                  "Source": [packet.src],
                                                  "Destination": [packet.dst],
                                                  "Info": [packet.summary()],
                                                  "Timestamp": [time.ctime(packet.time)],
                                                  "Window Size": [packet.window],
                                                  "Flags": [packet.sprintf("%TCP.flags%")]
                                                  })], ignore_index=True)
        # count packets and informs user for each collected 50 package
        num_packets[0] += 1
        if num_packets[0] % 50 == 0:
            print(f"{num_packets[0]} packets captured so far...")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface",
                        help="The interface name", default="wlo1")
    parser.add_argument(
        "-t", "--tcp", help="Sniff TCP packets", action="store_true")
    parser.add_argument(
        "-u", "--udp", help="Sniff UDP packets", action="store_true")
    parser.add_argument(
        "-s", "--source", help="Source IP address to filter by")
    parser.add_argument("-d", "--destination",
                        help="Destination IP address to filter by")
    parser.add_argument("-o", "--output", help="Save packets to a file")

    args = parser.parse_args()

    # Getting the interface name and protocols
    interface = args.interface
    protocols = []

    if args.tcp:
        protocols.append("tcp")
    if args.udp:
        protocols.append("udp")

    # If no protocol is specified, default is TCP
    if not protocols:
        protocols.append("tcp")

    # Constructing the filter string
    filter_string = " or ".join(
        [f"{proto}" for proto in protocols if proto in ["tcp", "udp"]])

    # Adding source and destination IP filters if specified
    if args.output:
        with open(args.output, "w") as f:
            print("Writing to file...")
            num_packets = [0]
            sniff(iface=interface, filter=filter_string,
                  prn=lambda x: packet_callback_csv(x, num_packets))
            df.to_csv(args.output, index=False)
            print(
                f"\nWriting operation interrupted by user, {num_packets[0]} packets have been written in {args.output} ")
    else:
        sniff(iface=interface, filter=filter_string, prn=packet_callback)


if __name__ == '__main__':
    main()

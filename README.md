# Network Hound

<img src="https://github.com/LiterallyEthical/network-hound/blob/main/images/title_image.png" height="415" width="830">

This is a network packet sniffer that captures and analyzes network packets on a given interface.
The tool is implemented using [Scapy](https://scapy.net/) and [Pandas](https://pandas.pydata.org/).
The packets can be saved to a **csv** file for later analysis. The tool can filter the packets based on TCP
and/or UDP protocols and source and destination IP adresses.

## Features

- Sniff packets on a given interface
- Filter packets based on TCP and/or UDP protocols and source and destination IP addresses
- Display captured packets on the console (in a readable table format)
- Save captured packets to a csv file for later analysis

## Usage

```md
python network_sniffer.py [-h] [-i INTERFACE] [-t] [-u] [-s SOURCE] [-d DESTINATION] [-o OUTPUT]

optional arguments:
-h, --help show this help message and exit
-i INTERFACE, --interface INTERFACE
The interface name (default: wlo1)
-t, --tcp Sniff TCP packets
-u, --udp Sniff UDP packets
-s SOURCE, --source SOURCE
Source IP address to filter by
-d DESTINATION, --destination DESTINATION
Destination IP address to filter by
-o OUTPUT, --output OUTPUT
Save packets to a file
```

## Requirements

- Scapy
- PrettyTable
- Pandas
- argparse
- socket
- time

## Installation

### Recommended Way of using pip

```
python -m pip install scapy pandas argparse socket time prettytable
```

OR

```
python -m pip install -r requirements.txt
```

## Examples

To sniff TCP packets on the default interface(wlo1):

```md
python network_sniffer.py
```

To sniff both TCP and UDP packets on the default interface:

```md
python network_sniffer.py -t -u
```

To filter packets based on source and destination IP addresses:

```md
python network_sniffer.py -t -u -s <source_ip> -d <destination_ip>
```

To save captured packets to a file:

```md
python network_sniffer.py -t -o <file_name>
```

##### Warning!

> CSV files will be write-protected, don't try to rewrite them again.

## Support

If you have any issues or questions, please feel free to contact me at ibrahimtahaistikbal@gmail.com

## Disclaimer

This tool is intended for legitimate and legal use only. Any unauthorized use of this tool is strictly prohibited.

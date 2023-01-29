# Network Hound

This is a network packet sniffer that captures and analyzes network packets on a given interface.
The tool is implemented using [Scapy](https://scapy.net/) and [Pandas](https://pandas.pydata.org/).
The packets can be saved to a **csv** file for later analysis. The tool can filter the packets based on TCP
and/or UDP protocols and source and destination IP adresses.

## Features

* Sniff packets on a given interface
* Filter packets based on TCP and/or UDP protocols and source and destination IP addresses
* Display captured packets on the console (in a readable table format)
* Save captured packets to a csv file for later analysis

## Usage

```vb
python network_sniffer.py [-h] [-i INTERFACE] [-t] [-u] [-s SOURCE] [-d DESTINATION] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        The interface name (default: wlo1)
  -t, --tcp             Sniff TCP packets
  -u, --udp             Sniff UDP packets
  -s SOURCE, --source SOURCE
                        Source IP address to filter by
  -d DESTINATION, --destination DESTINATION
                        Destination IP address to filter by
  -o OUTPUT, --output OUTPUT
                        Save packets to a file
```


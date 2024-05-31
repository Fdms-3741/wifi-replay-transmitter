# Packet transmitter

Author: Fernando Dias 

## Description

This program reads from a pcap file and replays all data from packet following the intervals from the timestamp.

## Installation 

This program requires the pcap library. For the rpi4, it can be installed with `apt-get`:
```
apt-get install libpcap-dev
```

This program can be installed using make as follows:

```
$ make
```

Other options for make includes compiling a debug version that displays messages through each step and sending the current folder elsewhere and compiling it. 

### Debug version

The ta

## Usage 

This program can be used with the following format:

```
./packet-injector [OPTIONS] <FILENAME>
```


## Development information

This file contains all information relevant to the packet\_injector progress

### Functionality

* [x] Reads pcap file
* [x] Open interface for injection
* [x] Injects packet in interface
* [x] Gets filename from command line
* [ ] Gets interface from command line
* [ ] Reads from CSV file (?)


### Options to implement

* [ ] -i/--interface: sets the injection interface
* [ ] -v/--verbose: Displays more information


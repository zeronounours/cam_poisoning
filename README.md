CAM Poisoning
=============

This program poison the network to set the attacker in a man-in-the-middle
(MitM) position, using a CAM poisoning attack.

CAM poisoning is an attack against switches which falsify the association
between a MAC address and a port of the switch. The goal is to change the
behavior of switches for them to send Ethernet frames to the attacker's port.

This attack is named after the CAM tables (Content Addressable Memory) of
switches which store the MAC-port association.

**Why using CAM poisoning instead of ARP spoofing/poisoning?**
Here are few thoughts
  * Advantages:
    - CAM poisoning can intercept protocols which are not IP-based
    - Frame content is legitimate compare to ARP spoofing which breaks the
    couple (MAC, IP): program like arpwatch won't be able to detect CAM
    poisoning
    - Switch protections are usually disabled

  * Disadvantages:
    - The traffic greatly increase what can be easily detected
    - It is less efficient than ARP spoofing: some frames may not be
    intercepted

How it works
------------
To poison a switch, you only need to send an Ethernet frame with the poisoned
MAC address as the sender. Doing so, you will receive poisoned frames until
the legitimate host send new frames.

However, intercepted frames have to be retransmitted for the communications to
continue and the attack to stay undetected. They cannot be sent as such because
the switch may still be poisoned. It may result it the switch sending back the
frames to the attacker or to discard it (switch-dependent). The program
currently broadcast an ARP request to force the host to respond and restore the
CAM tables.

In a nutshell, the attack is a loop consisting of the following steps:

  1. Poison the target hosts
  2. Read incoming frames for a given duration
  3. For each frame to retransmit:
    * Restore the destination MAC address (with ARP),
    * Retransmit the frame,
    * Restore the newly poisoned sender address.
  4. Go back to 1.


Setup
-----
### Install from the tarball
To install from the tarball, you need:
* A C compiler and standard library headers

System-specific installation:
* __debian__: `sudo apt-get install build-essential`
* __archlinux__: `sudo pacman -S base-devel`

### Install from the repository
To install from the repository, you need:
* A C compiler and standard library headers
* `autotools` to generate the configuration

System-specific installation:
* __debian__: `sudo apt-get install build-essential autotools-dev`
* __archlinux__: `sudo pacman -S base-devel`

Before compiling, the working environment need to be set up:
```bash
autoreconf --install
```


Compilation
-----------
From the package directory, run:

```bash
./configure
make
```

Installation
------------
Once compiled, from the package directory, run:

```bash
make install
```

Usage
-----
### Architecture
The CAM poisoner cannot be run alone. It only handles frame interception and
retransmission. It relies on an third-party program to modify intercepted
frames.

Communication between the third-party program and this program is performed
through UNIX domain sockets:
  * The CAM poisoner will send all intercepted frames to the third-party socket
  * The third-party socket can send back any frame to the CAM poisoner for
  injection in the network

For testing purposes, a `tester` program is compiled with the package (but not
installed). It handles the role of the third-party program, but it does not
modify any frames. Instead, it sends them back to the CAM poisoner for
retransmission. Intercepted frames can still be explored using packet
dissectors like Wireshark.

### Basic usage
**Important note**: the program heavily relies on raw sockets which require
privileges. The programs should either be run as `root` or with a user with
`CAP_NET_RAW` capabilities.

First run the third-party program which will modify the frames. For testing
purpose, you can use the in-package `tester` program:
```bash
cd /path/to/package
./src/tester
```

The path to the UNIX socket is given on start-up
```
# ./src/tester
The IPC socket has been opened here: /var/run/cam_poisoning/tester.sock
Wait for incoming packets
```
testing
You can then start the CAM poisoner program:
```bash
cam_poisoning 192.168.1.1 192.168.1.2 /var/run/cam_poisoning/tester.sock
```

* `192.168.1.1` and `192.168.1.2` are the two hosts which must be intercepted
* `/var/run/cam_poisoning/tester.sock` is the path to the UNIX socket of the
third-party program

See `cam_poisoning --help` for a full list of options.


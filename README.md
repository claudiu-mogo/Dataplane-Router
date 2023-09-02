## Dataplane Router

This project aims to emulate the Dataplane of a Router, thus implementing the forwarding mechanism.

The following actions are being performed when a packet gets to the router:

- Packet parsing: The router must determine which headers are present and what values are
contained in their fields, constructing and initializing corresponding internal structures.
At this stage, if the router detects that a received packet is malformed (too short), it discards it.

- Layer2 Validation: The packets contain an Ethernet header;
our router must only consider packets sent to itself (the MAC destination field is the same as
the MAC address of the interface on which the packet was received) or sent to everyone (the MAC
destination field is the broadcast address, FF:FF:FF:FF:FF:FF). Any other packet must be discarded.

- Next Header: The router checks the Ether Type field in the Ethernet header to discover the next header.
In this context, we will be interested in only two possibilities: [IPv4] and [ARP].
The router's subsequent actions will depend on the type of this header. Anything else will be ignored.

#### IPv4

- Destination Check: The router can be the recipient of a packet.
In this context, the router will respond only to ICMP messages.

- Checksum Verification: If the checksums differ, the packet has been corrupted and must be discarded.

- TTL (Time to Live) Check and Update: Packets with a TTL field set to 1 or 0 must be dropped.
The router will send back an ICMP "Time exceeded" message to the packet's sender.
Otherwise, the TTL field is decremented.

- Routing Table Lookup: The router searches the destination IP address of the packet in the routing table
to determine the next hop's IP address and the interface on which the packet should be sent.
If nothing is found, the packet is discarded. The router will send back an ICMP "Destination unreachable"
message to the packet's sender.

- Update Checksum: We modified the TTL field, so it must be recalculated

- L2 Address Rewrite: To determine the next hop's MAC address, the router uses the ARP.
The source address will be the router's interface address from which the packet is being forwarded.

- Forward the New Packet on the Corresponding Interface to the Next Hop.

#### ARP

- ARP Cache Lookup: The router checks its ARP cache to see if there is a current entry
for the IPv4 address of the next hop.

- Packet Queuing for Later: If the required address is not found in the ARP cache, the router will need
to make a query by generating an ARP packet and waiting for a response. The original packet that needed
to be routed is added to a queue so that it can be sent later after the ARP response arrives.

- Generating an ARP Request: The router generates an ARP packet to inquire about the MAC address
of the machine with the IPv4 address of the next hop.
The destination MAC address will be the broadcast address (FF:FF:FF:FF:FF:FF).

- Parsing ARP Reply: When the router receives an ARP reply packet, it will add it to the local ARP cache.
Additionally, the router will go through the list of packets waiting for ARP responses and
send those for which the next hop's address is now known.

#### ICMP Cases

- Destination Unreachable (Type 3, Code 0) - Sent when there is no route to the destination,
typically when the packet is not intended for the router.

- Time Exceeded (Type 11, Code 0) - Sent if the packet is dropped due to
the Time to Live (TTL) field expiring.

- The router is also a network entity, it can receive ICMP messages of type "Echo request"
intended for itself. It must respond with an ICMP message of type "Echo reply" (Type 0, Code 0).

#### Steps made in main:

- Before the actual listening (the while loop) for each router:

1. Initialize an empty queue, which will be populated with packets for which we don't currently
know the route to the destination.
2. Allocate and read the routing table from the executable's parameters,
later putting the entries into a trie data structure (explained later).
3. Allocate an ARP table, initially empty.

- Listen on all interfaces, save the received packet in a buffer, and record the interface on which
it was received. In the sockaddr_in structure, store the IP address of the interface on which the packet
was received to determine if we (the router) were the final destination of the packet.

- Check if the packet is of any ARP type. If not, verify the correctness of the data and update it.

- Search the ARP table. If we found a MAC/ARP entry, then complete an IP packet.

- Otherwise, put the current packet in the queue and generate an ARP request to broadcast.

#### Additional structures:

Queue:

- Our queue is denoted as Q, and we also maintain a globally declared length.
- The structure placed in the queue, typically referred to as an "element," 
contains the buffer that defines the respective packet and its length.
- When we receive a reply, we iterate through the queue to determine which packets we can send.
- If we cannot send a packet immediately, we enqueue it and keep track of how many are left unsent.

Trie:

- Structure used for a faster search through the Routing table
- A node in the trie contains a pointer to an entry in the routing table, pointers to its two children,
and an indicator of whether it is a node that should be considered.
- A node with relevant information is located at level x if x is the length of the associated subnet mask.
- The root is at level 0 and does not contain relevant information.
- Because the masks and addresses are in network order, we can traverse them in reverse.
- We traverse an IP address: for a 0 bit, we go left; for a 1 bit, we descend right.
- At the sought-after level, we create or modify the existing node with a pointer to the entry.

#### How to test:

sudo python3 checker/topo.py

Thus, the virtual topology will be initialized, and a terminal will open for each host,
one terminal for each router, and one for the controller (with which we will not interact);
the terminals can be identified by their titles.

Each host is a simple Linux machine, from whose terminal you can run commands that generate IP traffic
to test the functionality of the implemented router.
Some commands that can be used are: arping, ping, and netcat.

To start the router 0 and 1 respectively, run "make run_router0" or "make run_router1"
from the fitting terminal.

Automatic testing: ./checker/checker.sh

# WEC-REC_networking
ICMP is a protocol which is usedot typically talk about the network problems, like, data is getting to 
destination in time or is there any packet loss in between and others. Though it can also be used for a DDoS attack
(Distributed Denial of Service) where the host is swarmed with a lot of packets to traffic jam the host network 
depriving the users of the resources on the host network.

So ICMP is different from TCP/IP as it doesnt require the usual handshake(or the connection between the devices) , 
it can be sent to anyone and not even specifying ports is required, ICMP is a Layer 3 protocol like the IP and 
not a transport layer protocol.
The role of ICMP is to provide the path data is taking from its source to destination


ICMP header file:

TYPE | CODE | CHECKSUM

type  -  ICMP type  
type 8-echo require
type 0-echo reply
type 3-destination unreachable 

code  -  ICMP subtype
code 0-dest  network unreachable
code 1-dest host unreachable

checksum-for verificaton of header

ICMP can send the following commands

1.echo request:	Sent by hosts and gateways to test whether a destination is alive and reachable.
2.information request:	Sent by hosts and gateways to obtain an Internet address for a network to which they are attached. This message type is sent with the network portion of IP destination address set to a value of 0.
3.timestamp request:   Sent to request that the destination machine return its current value for time of day.
4.address mask request:	Sent by host to learn its subnet mask. The host can either send to a gateway, if it knows the gateway address, or send a broadcast message.
5.destination unreachable:	Sent when a gateway cannot deliver an IP datagram.
6.source quench:	Sent by discarding machine when datagrams arrive too quickly for a gateway or host to process, in order to request that the original source slow down its rate of sending datagrams.
7.redirect message:	Sent when a gateway detects that some host is using a nonoptimum route.
8.echo reply:	Sent by any machine that receives an echo request in reply to the machine which sent the request.
9.information reply:	Sent by gateways in response to requests for network addresses, with both the source and destination fields of the IP datagram specified.
10.timestamp reply:	Sent with current value of time of day.
11.address mask reply:	Sent to machines requesting subnet masks.
12.parameter problem:	Sent when a host or gateway finds a problem with a datagram header.
13.time exceeded:	Sent when the following are true:
Each IP datagram contains a time-to-live counter (hop count), which is decremented by each gateway.
A gateway discards a datagram because its hop count has reached a value of 0.
14.Internet Timestamp:	Used to record the time stamps through the route.


A PING is a echo command Echo, it is how you can find out, “If I wanted to send some data to you, 
are you there, and, for this echo packet, how long did it take, all up, for me to send it and you to receive it?”
It gives RTT(round trip time) which is the estimate of the distance as time:
How far away are you, in time, all things being as best they can be? This is the ‘smallest’ RTT you see, when doing a sequence of pings. 
How variable is the time, as a rough indication of congestion and delay? This is the range of RTT you see, how bad it can be, 
how good it can be and how much it ranges in-between. This is what we call both delay and jitter: 
jitter is the variability, and delay is the ‘how long?’ part.
How reliable are you? What is the loss of packets over this series of pings?

Basically it tells a device if another device is alive or not based on a request and reply mechanism.

here 4(by default) icmp request packets are sent to the mentioned address giving it a specific ttl(time to live) 
which is a maximum number of hops it can do before reaching the required address, if it goes beyond that then an error
is issued and the source is notified about the same


1.CheckSum Calculation
 A 16 bit check sum is sent along with the ICMP message which is for checking the integrity of the message
 
 The 16 bit number is divided into 2 bit parts then added cumulatively to get a and then finally the sum is complemented 
 and sent along with the message.

2.Header Format

header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
    )

basic structure of an ICMP message:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     ICMP_ECHO  |     0        |          checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           self.own_id         |        self.seq_number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

!-Big endian
B - Unsigned Char (8 bits)
B - Unsigned Char (8 bits)
H - Unsigned Short (16 bits)
H - Unsigned Short (16 bits)
H - Unsigned Short (16 bits)
implying the type of each part: icmp_echo,type and code,checksum,id,sequence number    
(documentation from -https://docs.python.org/3/library/struct.html)

Payload can be of arbitrary length but alwasys of a fixed size (packet length) 55 bytes

3.Sending Ping packet:
An ICMP socket is created:
         
         icmp_socket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp")) 

         SOCK_RAW - since it is a one way packet transfer without a connection and also since i
         nner protocol "icmp" is used
         
         This socket will create and send ICMP packets to the destination and help us access the header and 
         other useful information

Then the time at which the packet is sent is stored

Count of packets is kept track of and a ping packet is sent

    Sending One Ping Packet:
    the payload data is contructed and stored into a header file(ICMP header) and packed into as binary 
    data and the final check sum is calculated using the data 
    
    The final header is sent using the socket to the destination IP 

The sent packet is then received along with the time,packet size, IP information and ICMP information

3.Receiving Ping Packet:
Use the select module to receive incoming echo replies
The select function is a blocking function that takes stops the code until it receives a response

The input received from the icmp_socket is then divided into packet data and address (It comes as a tuple)
This packet data is then unpaced into a dictionary with all the attributes of a ICMP header file 
namely :"type","code","checksum","packet_id","seq_number"
Even the IP header contents are extracted.

Finally receive_time(time taken to receive the packet),packet_size(received packet size),IP,
IP_header(header contents of IP) and ICMP_header are returned back

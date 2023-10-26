import socket
import time
import os
import math
import struct
import select

# ICMP parameters
ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
ICMP_ECHO = 8 # Echo request (per RFC792)
ICMP_MAX_RECV = 2048 # Max size of incoming buffer

IP = input("Enter the IP address or the Domain name to be pinged \n")
cnt = input("Enter the number of packets to be sent \n")
cnt = int(cnt)

def cal_checksum(data):
     sum = 0

    # Iterate through 16-bit segments
     for i in range(0, len(data), 2):

        if i + 1 < len(data):     #Since we check two numbers at once hence the i+1
            # Combine two bytes into a 16-bit value
            segment = (data[i] << 8) + data[i + 1]            #Shift by 8 bits and take the first pair of numbers as a segments 
            sum += segment                                 #keep incrementing the sum
        else:
            sum += data[i]                    # If there's a leftover byte                    
            

    # Shift 32-bit sum to 16-bit
     while (sum >> 16):
        sum = (sum & 0xffff) + (sum >> 16)

    # Take one's complement to get the checksum
     checksum = (~sum) & 0xffff
     checksum = socket.htons(checksum)

     return checksum

def to_ip(addr):    #Function created inorder to handle IP address as well as Hostnames
    ip = True
    if ip:
        addr = socket.gethostbyname(addr)
        parts = addr.split(".")
        if not len(parts) == 4:
            ip = False
        for part in parts:
            number = 0
            try:
                number = int(part)
            except ValueError:
                ip = False
            if number > 255:
                ip = False
        
        if ip:
            return addr
    else:
        return socket.gethostbyname(addr)

class Ping(object):
    def __init__(self,destinantion,packet_size=55,timer=50000,own_id=None,source_address=False):
        self.destination = destinantion   #Destinantion address where the ping is supposed to go
        self.timer = timer                 #timer till which the device will wait for the response
        
        # hostname = socket.gethostname()
        self.source_address = "127.0.0.1"
               
        if own_id == None:
            self.own_id = os.getpid()     #To get the currnt process id so that the receiver knows the packet number
        else:
            self.own_id = own_id

        self.ttl = None
        self.dest_ip = to_ip(self.destination)

        self.min_time = 9999999  #MIN RTT
        self.max_time = 0.0      #MAX RTT
        self.total_time = 0.0    #RTT
        self.sent_packets = 0 #Number of packets sent
        self.received_packets = 0 #Number of packets received back
        self.packet_size = packet_size
        self.seq_number = 0             # to keep track of multiple ping packets sent

        self.start()



    def start(self):
        print("Ping request sent to %s : %d data bits"%(self.dest_ip,self.packet_size))
    
    def success(self, delay, ip, packet_size, ip_header, icmp_header):
        #delay is the time taken to reach back to the sender,ip is the address of the destination
        #packet_size the sent packet size
        #ip_header has the details about the ip message sent as icmp header is always enlosed in ip header(this is to send back error messages)
        print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms" % (packet_size,ip, icmp_header["seq_number"], ip_header["ttl"], delay))

    def exit_statistics(self):

        lost_packets = self.sent_packets - self.received_packets
        print(f"Packet Lost: {lost_packets}")

        lost_rate = (float(lost_packets)/self.sent_packets) * 100
        print(f"{self.sent_packets} packets transmitted , {self.received_packets} packets received , {self.ttl} = ttl , {lost_rate}% packets lost ")
        if self.received_packets != 0:
            print(f"round-trip min/avg/max/stddev = {self.min_time}/{self.total_time/self.received_packets}/{self.max_time}/{math.sqrt(self.total_time/2)} ms")
        else:
            print(f"round-trip min/avg/max/stddev = 0/0/0/0 ms")

    def unpack_header(self,names,struct_format,data):   #this is to convert the recieved header into easy to read and extract infofmation form 
        unpacked_data = struct.unpack(struct_format,data)
        return dict(zip(names,unpacked_data))     
    
    def send_ping(self,count = None):
        print(count)
        while True:
            delay = self.do()
            self.seq_number+=1
            if  count and self.seq_number>=count:
                break
        self.exit_statistics()

    def do(self):   
        #Function which send and receives packets and extracts the neccessary details until time runs out
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #Here we use SOCK_RAW-as we need to access the inner protocols (ICMP) which are not accessible by SOCK_DGRAM/SOCK_STREAM used for UDP and TCP Protocols
            # icmp_socket.setblocking(0)
            # icmp_socket.bind((self.source_address,1))  #Here we bind back to ourself since raw sockets dont include source address so we won't be able to receive back the icmp response 
        except socket.error as e:
            print("Error creating ICMP socket:", e)

        send_time = self.send_one_ping(icmp_socket)
        # print("Send Time:",send_time)
        if send_time == None:
            return
        self.sent_packets += 1

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_ping(icmp_socket) 
        icmp_socket.close()

        print("Receive Time:",receive_time," Pckt size: ",packet_size)
        if receive_time:            
                self.received_packets += 1   #inclrease count of recieved packets by one
                self.ttl = ip_header["ttl"]    #show the ttl sotred in the IP header
                delay = (receive_time - send_time) * 1000.0    #delay is the total time taken
                self.total_time += delay
                if self.min_time > delay:
                    self.min_time = delay
                if self.max_time < delay:
                    self.max_time = delay

                self.success(delay, ip, packet_size, ip_header, icmp_header)
                return delay
        else:
            print("Request time out") # if receive time exceeds set threshold limit then error statement is produced

    def send_one_ping(self,icmp_socket):  
        #Processes behind each icmp echo request sent

        checksum = 0

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack("!BBHH",ICMP_ECHO,0,checksum,self.seq_number)

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
               padBytes += [(i & 0xff)]  # And to keep only the last 8 bits and not beyond
        data = bytes(padBytes)

        checksum = cal_checksum(header + data)  #calculate the actual checksum

        header = struct.pack("!BBHH",ICMP_ECHO,0,checksum,self.seq_number) #update it with the actual checksum

        packet = header + data
        send_time = time.time()

        try:
            icmp_socket.sendto(packet,(self.dest_ip,80)) #PORT number is not required for icmp packets
        except socket.error as e:
            print(f"Socket error: {e}")      

        return send_time

    def receive_one_ping(self,icmp_socket):    
        #Processes behind each icmp echo request received
        #Timer in ms
        timer = self.timer/1000.0

        while True:
            select_start = time.time() #start the select module for accepting the incoming echo replies
            inputready, outputready,exceptready = select.select([icmp_socket],[],[],timer)
            select_duration = time.time() - select_start

            receive_time = time.time()  #time at which reply is received

            if not inputready:
                if timer <= 0:
                    return None, 0, 0, 0, 0
                return None,0,0,0,0
            
            packet_data,address = icmp_socket.recvfrom(2048) #Max buffer size=2048 of received data
            # print(f"Packet data: {packet_data} \n")
            
            icmp_header = self.unpack_header(names = ["type","code","checksum","seq_number"],
                                                         struct_format="!BBHH",data =packet_data[20:26])    #20-28 refers to the first 8 bytes which include type,code,checksum,packet_id and sequence_number
            ip_header = self.unpack_header(names=["version", "type", "length",
						                              "id", "flags", "ttl", "protocol",  #Basic IP header file format
						                              "checksum", "src_ip", "dest_ip"],
                                                      struct_format="!BBHHHBBHII", 
                data = packet_data[:20])                                                  #First 20 bytes are IP header information
                
            packet_size = len(packet_data) - 28   #Total size - IP_header size(20) - ICMP_header(8) = Actual Payload 
                # print("Src_ip: ", {ip_header["src_ip"]})
            ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))               #To convert to readable ip address format, src_ip has it 
                
            return receive_time, packet_size, ip, ip_header, icmp_header

p1 = Ping(destinantion=IP)
p1.send_ping(cnt)

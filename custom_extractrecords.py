def extractrecords(packet):
    global services
    instances={key:None for key in services}
    print(instances)
    trigger_packet=sa.UDP(sport=5353,dport=5353)/sa.DNS(qr=1,aa=1,rd=0)
    global name
    global instance_names
    global instance_names_rrname
    trigger_packet[sa.DNS].ar=sa.DNSRR(rrname=name,type=1,rclass=32769,ttl=120,rdata=my_ip)
    for i in range(packet[sa.DNS].arcount):
        if packet[sa.DNS].ar[i].type==33 or packet[sa.DNS].ar[i].type==33:
            rrname=packet[sa.DNS].ar[i].rrname.decode("utf-8")
            pos=rrname.find("._")
            instances[rrname[pos+1:]]==rrname
    instances={packet[sa.DNS].an[i].rrname.decode("utf-8"):packet[sa.DNS].an[i].rdata.decode("utf-8") for i in range(packet[sa.DNS].ancount ) if packet[sa.DNS].an[i].type==12 }            
    instance_names={tricky_padding(key):key for key in instances.values()}
    instance_names_rrname={key:tricky_padding(key) for key in instances.values()}
    Records={service:{typee:None for typee in ["33","16"]} for service in instance_names_rrname.values()}
    print(instance_names_rrname)
    for i in range(packet[sa.DNS].ancount):
        if packet[sa.DNS].an[i].type!=12:
            continue
        if trigger_packet[sa.DNS].ancount==0 :
            trigger_packet[sa.DNS].an=sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=instance_names_rrname[packet[sa.DNS].an[i].rdata.decode('utf-8')].encode("utf-8","backslashreplace") )
        else:
            trigger_packet[sa.DNS].an=trigger_packet[sa.DNS].an/sa.DNSRR(rrname=packet[sa.DNS].an[i].rrname,type=12,rclass=32769,ttl=120,rdata=instance_names_rrname[packet[sa.DNS].an[i].rdata.decode('utf-8')].encode("utf-8","backslashreplace") )
        trigger_packet[sa.DNS].an=sa.DNSRRNSEC(rrname=name.encode("utf-8","backslashreplace") ,nextname=name.encode("utf-8","backslashreplace") ,rclass=32769,ttl=120,typebitmaps=[1])
    for i in range(packet[sa.DNS].ancount):
        if packet[sa.DNS].an[i].type==33:
            trigger_packet[sa.DNS].an=trigger_packet[sa.DNS].an/sa.DNSRRSRV(rrname=instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")].encode('utf-8'),type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8","backslashreplace") )
            global current_name
            current_name=packet[sa.DNS].an[i].target.decode("utf-8")
            Records[instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")]]["33"]=sa.DNSRRSRV(rrname=instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")].encode('utf-8'),type=33,rclass=32769,ttl=120,priority=0,weight=100,port=packet[sa.DNS].an[i].port,target=name.encode("utf-8","backslashreplace") )
        if packet[sa.DNS].an[i].type==16 and packet[sa.DNS].an[i].rrname.decode("utf-8") in instance_names_rrname.keys():
            Records[instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")]]["16"]=sa.DNSRR(rrname=instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")].encode('utf-8'),type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
            trigger_packet[sa.DNS].an=trigger_packet[sa.DNS].an/sa.DNSRR(rrname=instance_names_rrname[packet[sa.DNS].an[i].rrname.decode("utf-8")].encode('utf-8'),type=16,rclass=32769,ttl=120,rdata=change_txt(packet[sa.DNS].an[i].rdata))
    
    for i in Records.keys():
        trigger_packet[sa.DNS].an=trigger_packet[sa.DNS].an/sa.DNSRRNSEC(rrname=i.encode("utf-8","backslashreplace") ,nextname=i.encode("utf-8","backslashreplace") ,rclass=32769,ttl=120,typebitmaps=[33,16])        
    return True,instances,Records,trigger_packet

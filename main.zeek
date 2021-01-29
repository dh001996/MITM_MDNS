@load mdns
@load policy/protocols/dns/auth-addl
@load extra
@load detect
global services_found : table[addr] of  mdns::services;
global service_requests : table[addr] of table[string] of mdns::Records;
#global services_found_info ;
global ports : table[addr] of port ;
global A_Queue: table [addr] of table[string] of addr;
global AAAA_Queue: table [addr] of table[string] of addr;
global log_req :bool =F;
global log_rep :bool =F;
event zeek_init()
{
    print "Program starting";
    Log::create_stream(mdns::MDNS,[$columns=mdns::Records, $path="mdns"]);
    Log::create_stream(mdns::change,[$columns=mdns::Records_extra, $path="changes"]);
    Log::create_stream(mdns::MDNS_RECORDS,[$columns=mdns::Records_extra, $path="mdns_extra"]);
    local filter_extra : Log::Filter =[$name="mdns_filter_extra",$pred=mdns::mdns_extra_keep,$path="mdns_extra"];
    local filter_changes : Log::Filter =[$name="mdns_changes",$pred=mdns::mdns_extra_keep,$path="changes"];
    local filter: Log::Filter =[$name="mdns_filter",$pred=mdns::mdns_keep,$path="mdns",$path_func=mdns::split_log];
    Log::add_filter(mdns::MDNS, filter);
    Log::remove_filter(mdns::MDNS,"default");
    Log::add_filter(mdns::changes, filter);
    Log::remove_filter(mdns::changes,"default");
    Log::add_filter(mdns::MDNS_RECORDS, filter_extra);
    Log::remove_filter(mdns::MDNS_RECORDS,"default");
}
event dns_request(c: connection, msg: dns_msg, query:string, qtype: count, qclass : count)
{
   # print "+++++++++++++  REQUEST  ++++++++++++++++++++++++++++++";
    #print (fmt("Query : %s",query));
    local tmp  = mdns::Records($id=c$dns$uid,$ts=c$dns$ts,$p=c$id$resp_p,$host=c$id$orig_h,$mac=c$orig$l2_addr,$is_query=T,$recor=query);
    if (c$id$orig_h !in service_requests)
    {
        if ("_dns-sd._udp" in query)
        {
            print(fmt("%s is browsing services ",c$id$orig_h));       
        }
        else
        {
            print(fmt("%s is looking for this service %s ",c$id$orig_h , query));
        }
        #local tmp  = mdns::Records($id=c$dns$uid,$ts=c$dns$ts,$p=c$id$resp_p,$host=c$id$orig_h,$is_query=T,$recor=set(query));
        service_requests[c$id$orig_h]=table();
        service_requests[c$id$orig_h][query]=tmp; 
        Log::write(mdns::MDNS,service_requests[c$id$orig_h][query]);
    }
    else
     {
        if (query !in service_requests[c$id$orig_h])
        {
            print(fmt("%s is looking for this service %s ",c$id$orig_h , query));
            service_requests[c$id$orig_h][query]=tmp;
            Log::write(mdns::MDNS,service_requests[c$id$orig_h][query]);
         #   add service_requests[c$id$orig_h]$recor[query];
        }
        else
        {
            if ((c$dns$ts-service_requests[c$id$orig_h][query]$ts)> 3 sec && service_requests[c$id$orig_h][query]$id==c$dns$uid)
            {            
                service_requests[c$id$orig_h][query]$id=c$dns$uid;
                service_requests[c$id$orig_h][query]$ts=c$dns$ts;
                Log::write(mdns::MDNS,service_requests[c$id$orig_h][query]); 
            }
        }
       # event mdns::logging_req(service_requests);
        
     }
    
    
}
event dns_PTR_reply(c: connection, msg: dns_msg, ans : dns_answer, name : string ) &priority = 10
{
    #print "*********************PTR RECORD*********************************";
   # print (fmt("Query: %s and Service : %s",ans$query,name));
    local index : int = extra::find(name,"._");
    local tmp2  = mdns::Records($id=c$dns$uid,$ts=c$dns$ts,$p=c$id$resp_p,$host=c$id$orig_h,$mac=c$orig$l2_addr,$is_query=F,$recor=name);
    if  (c$id$orig_h !in services_found)
     {
         
        local tmp = mdns::services();
        services_found[c$id$orig_h]=tmp;
        print "host added !";
     }
    if (ans$query !in services_found[c$id$orig_h]$liste) 
    {
        if (("_dns-sd._udp" in ans$query)&& (name !in services_found[c$id$orig_h]$liste))
         {
             print(fmt("Service found : %s & host ip: %s",name,c$id$orig_h));
             services_found[c$id$orig_h]$liste[name]=tmp2;
             print ("service added !");
             Log::write(mdns::MDNS,services_found[c$id$orig_h]$liste[name]);
            #log_rep=T;
         }
        if ((index!=-1) && (extra::extract_string(name,0,index) in services_found[c$id$orig_h]$names))
        {
            print(fmt("Service found : %s & host ip: %s",ans$query,c$id$orig_h));
            tmp2$recor=ans$query;
            services_found[c$id$orig_h]$liste[ans$query]=tmp2;
            Log::write(mdns::MDNS,services_found[c$id$orig_h]$liste[ans$query]);
            print ("service added !");
         #   services_found[c$id$orig_h]$info[name]=table();
            #log_rep=T;
        }

    }
    else
    {
        if ((c$dns$ts-services_found[c$id$orig_h]$liste[ans$query]$ts)> 3 sec && services_found[c$id$orig_h]$liste[ans$query]$id==c$dns$uid)
        {
            services_found[c$id$orig_h]$liste[ans$query]$id=c$dns$uid;
            services_found[c$id$orig_h]$liste[ans$query]$ts=c$dns$ts;
            Log::write(mdns::MDNS,services_found[c$id$orig_h]$liste[ans$query]);
        }
    }

    
   # Log::write(mdns::MDNS,[$p=c$id$resp_p,$host=c$id$orig_h,$query=query]);
}
event dns_PTR_reply(c: connection, msg: dns_msg, ans : dns_answer, name : string ) &priority = 9
{
    #print "*********************PTR RECORD 222*********************************";
   # print (fmt("Query: %s and Service : %s",ans$query,name));
    local index : int = extra::find(name,"._");
    if (c$id$orig_h in services_found && "_dns-sd._udp"!in ans$query)
    {
        #print (fmt("Query: %s and Service : %s",ans$query,name));
        if (index!=-1 && name !in services_found[c$id$orig_h]$names  )
        {add services_found[c$id$orig_h]$names[extra::extract_string(name,0,index)];}
        if (index!=-1 && name !in services_found[c$id$orig_h]$info )
        {
            services_found[c$id$orig_h]$info[name]=table();
           # add services_found[c$id$orig_h]$names[extra::extract_string(name,0,index)];
        }
        if (name in services_found[c$id$orig_h]$info && "PTR"!in services_found[c$id$orig_h]$info[name] && name !in services_found[c$id$orig_h]$liste)
            {services_found[c$id$orig_h]$info[name]["PTR"]=ans$query;
            Log::write(mdns::MDNS_RECORDS,[$p=services_found[c$id$orig_h]$liste[ans$query]$p,$host=c$id$orig_h,$service=name,$record_type="PTR",$recor=services_found[c$id$orig_h]$info[name]["PTR"]]);
            }
        
    }

 
}
event dns_SRV_reply(c: connection, msg :dns_msg , ans:dns_answer , target:string , priority : count , weight : count , p: count )
{
    local index : int = extra::find(ans$query,".");
    local name:string = extra::extract_string(ans$query,0,index);
    local service:string =extra::extract_string(ans$query,index+1,|ans$query|-index-1);
    if (c$id$orig_h in services_found)
    {
        if (index!=-1 && name in services_found[c$id$orig_h]$names && ans$query in services_found[c$id$orig_h]$info && "SRV" !in services_found[c$id$orig_h]$info[ans$query])
        {
            services_found[c$id$orig_h]$info[ans$query]["SRV"]=target;
            Log::write(mdns::MDNS_RECORDS,[$p=services_found[c$id$orig_h]$liste[service]$p,$host=c$id$orig_h,$service=ans$query,$record_type="SRV",$recor=services_found[c$id$orig_h]$info[ans$query]["SRV"]]);
        }
        if (index!=-1 && name in services_found[c$id$orig_h]$names && ans$query in services_found[c$id$orig_h]$info && "SRV" in services_found[c$id$orig_h]$info[ans$query] && target!=services_found[c$id$orig_h]$info[ans$query]["SRV"])
        {
            services_found[c$id$orig_h]$info[ans$query]["SRV"]=target;
            Log::write(mdns::changes,[$p=services_found[c$id$orig_h]$liste[service]$p,$host=c$id$orig_h,$service=ans$query,$record_type="SRV",$recor=services_found[c$id$orig_h]$info[ans$query]["SRV"]]);
        }       
    }
}
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
{
    #print "********** TXT ******************";
    local index : int = extra::find(ans$query,"._");
    local name:string = extra::extract_string(ans$query,0,index);
    local service:string =extra::extract_string(ans$query,index+1,|ans$query|-index-1);
    #print ( c$id$orig_h in services_found && index!=-1 && name in services_found[c$id$orig_h]$names && service in services_found[c$id$orig_h]$liste );
    if ( c$id$orig_h in services_found && index!=-1 && name in services_found[c$id$orig_h]$names && ans$query in services_found[c$id$orig_h]$info && "TXT" !in services_found[c$id$orig_h]$info[ans$query])
        {
   #         print services_found[c$id$orig_h]$info[service];
            services_found[c$id$orig_h]$info[ans$query]["TXT"]=extra::join_vec(strs);
            Log::write(mdns::MDNS_RECORDS,[$p=services_found[c$id$orig_h]$liste[service]$p,$host=c$id$orig_h,$service=ans$query,$record_type="TXT",$recor=services_found[c$id$orig_h]$info[ans$query]["TXT"]]);
        }
}
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
    A_Queue[c$id$orig_h]=table();
    A_Queue[c$id$orig_h][ans$query]=a;
}
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
    AAAA_Queue[c$id$orig_h]=table();
    AAAA_Queue[c$id$orig_h][ans$query]=a;
}
event dns_NSEC(c: connection, msg: dns_msg, ans: dns_answer, next_name: string, bitmaps: string_vec)
{
    local index : int = extra::find(ans$query,"._");
    local name:string = extra::extract_string(ans$query,0,index);
    local service:string =extra::extract_string(ans$query,index+1,|ans$query|-index-1);
    if ( c$id$orig_h in services_found && index!=-1 && name in services_found[c$id$orig_h]$names && ans$query in services_found[c$id$orig_h]$info  && "NSEC" !in services_found[c$id$orig_h]$info[ans$query])
    {
        services_found[c$id$orig_h]$info[ans$query]["NSEC"]=next_name+";"+extra::join_vec(bitmaps);
        Log::write(mdns::MDNS_RECORDS,[$p=services_found[c$id$orig_h]$liste[service]$p,$host=c$id$orig_h,$service=ans$query,$record_type="NSEC",$recor=services_found[c$id$orig_h]$info[ans$query]["NSEC"]]);
    }

}
event dns_end(c: connection , msg : dns_msg)
{
    for (host in A_Queue)
    {
    if (host in services_found)
    {
        for (service in services_found[host]$info)
        {
            if ("SRV" in services_found[host]$info[service])
            {
                for (key in A_Queue[host])
                {
                if (services_found[host]$info[service]["SRV"]==key && "A" !in services_found[host]$info[service])
                {
                    services_found[host]$info[service]["A"]=fmt("%s",A_Queue[host][key]);
                    Log::write(mdns::MDNS_RECORDS,[$p=services_found[host]$liste[services_found[host]$info[service]["PTR"]]$p,$host=host,$service=service,$record_type="A",$recor=services_found[host]$info[service]["A"]]);
                }
                }
            }
        }
    }
    }
    for( host in AAAA_Queue)
    {
    if (host in services_found)
    {
        for (service in services_found[host]$info)
        {
            if ("SRV" in services_found[host]$info[service])
            {
                for (key in AAAA_Queue[host])
                {
                if (services_found[host]$info[service]["SRV"]==key && "AAAA" !in services_found[host]$info[service] )
                {
                    services_found[host]$info[service]["AAAA"]=fmt("%s",AAAA_Queue[host][key]);
                    Log::write(mdns::MDNS_RECORDS,[$p=services_found[host]$liste[services_found[host]$info[service]["PTR"]]$p,$host=host,$service=service,$record_type="AAAA",$recor=services_found[host]$info[service]["AAAA"]]);
                }
                }
            }
        }
    }
    }
   # if (log_rep)
   # {event mdns::logging_found(services_found);
   # log_req=F;}
   # if (log_req)
   # {event mdns::logging_req(service_requests);
   # log_req=F;}
}
event zeek_done()
{
    print  services_found;
    print "Requests ::";
    print service_requests;
   # event mdns::logging_found(services_found);
  #  event mdns::logging_req(service_requests);
    print "Program done";
}

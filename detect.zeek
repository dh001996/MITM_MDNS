@load policy/protocols/dns/auth-addl
@load mdns
global service_requests : table[addr] of table[string] of mdns::Records;
global devices : set[mdns::device];
event zeek_init()
{
    print "IDS starting";
	Log::create_stream(mdns::MDNS,[$columns=mdns::Records, $path="mdns"]);
    Log::create_stream(mdns::changes,[$columns=mdns::Records_extra, $path="changes"]);
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
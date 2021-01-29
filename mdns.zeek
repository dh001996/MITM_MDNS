module mdns;
export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { MDNS , MDNS_RECORDS ,changes};
    type Records : record {
        id: string &log;
        ts: time &log;
        p : port &log;
        host : addr &log;
        mac : string &log;
        is_query : bool &log;
        recor : string &log;
    };
    type Records_extra : record {
        p : port &log;
        host : addr &log;
        service : string &log;
        record_type : string &log;
        recor :  string &log;
    };
    type services : record {
        #id : string &default="";
        #ts : time ;
        names : set[string] &default=set();
        liste : table[string] of Records &default=table();
        info : table [string] of table[string] of string &default=table();
    };
    type service : record {
        name : string &default="";
        service_type : string  &default="";
        service_port : port  &default=5353/udp;
        records : table[string] of string  &default=table();
    };
    type device : record {
        domain_name: string  &default="";
        ts: time;
        host : addr ;
        services : table[string] of service &default=table();
    };
    
    # Define a new type called Factor::Info.
    global mdns_keep :function(R : Records):bool;
    global split_log: function(id:Log::ID, path : string , rec : mdns::Records):string;
    global  logging_found: event(services_found :table[addr] of mdns::services);    
    global  logging_req: event(service_requests :table[addr] of table[string] of mdns::Records);
    global  mdns_extra_keep:function(R : Records_extra):bool;
        }
function mdns_keep(R : Records):bool
{
    return (R$p==5353/udp );
}
function mdns_extra_keep(R : Records_extra):bool
{
    return (R$p==5353/udp );
}
function split_log(id:Log::ID,path : string , rec : mdns::Records):string
{
    if (rec$is_query)
    {
        return "Queries";
        
    }
    else
    {
        return "Available_services"; 
    }
   
}
event logging_found(services_found :table[addr] of mdns::services)
{
    for (i in services_found)
    {
        for (j in services_found[i]$liste)
        {
            Log::flush(mdns::MDNS);
            Log::write(mdns::MDNS,services_found[i]$liste[j]);
            for (k in services_found[i]$info[j])
            {
                Log::flush(mdns::MDNS_RECORDS);
                Log::write(mdns::MDNS_RECORDS,[$p=services_found[i]$liste[j]$p,$host=i,$service=j,$record_type=k,$recor=services_found[i]$info[j][k]]);
               }
        }
    }
}
event logging_req(service_requests :table[addr] of table[string] of Records)
{
     for (i in service_requests)
    { for (j in service_requests[i])
       {
           Log::flush(mdns::MDNS);
            Log::write(mdns::MDNS,service_requests[i][j]);
        }
      #  print services_found;
    }
}

module extra;
export
{
    global find : function(str :string, char: string): int;
    global extract_string : function(str:string,pos:int,len:int):string;
    global  join_vec : function(v: vector of string): string;
}

function find(str :string, sub_str: string): int
# return the 1st occurence of the sub_str in the string else -1
{
    if (sub_str !in str)
    {
        return -1;
    }
    local i:int =0;
    while(i<|str|-|sub_str|)
    {
        if (str[i:i+|sub_str|]==sub_str)
        {return i;}
        ++i;

    }
}
function extract_string(str:string,pos:int,len:int):string
{
    local tmp:string ="";
    local i:int =0;
    if (!( (len>0)&&(pos>=0)&&(pos+len <= |str|)))
    {return tmp;}
    while(i<len)
    {
        tmp=tmp+str[pos+i];
        ++i;
    }
    return tmp;
}
function join_vec(v: vector of string): string
{
    local tmp : string ="";
    if (|v|==1)
        {return v[0];}
    local i :int =1;
    if ( |v| > 1) 
    {
        tmp=v[0];    
        while(i<|v|)
    {
        tmp=tmp+" ; "+v[i];
        ++i;
    }
    }
    return tmp; 
}
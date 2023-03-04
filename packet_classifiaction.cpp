#include<iostream>
#include<unordered_map>
#include<sstream>
#include<fstream>
#include<utility>
#include<string>
#include<vector>
#include<bitset>
#define wildcard 0xfffffff
using namespace std;
struct packet_rule
{
    unsigned int src_IP;
    unsigned int dest_IP;
    int prefix;
    pair<int,int>src_port;
    pair<int,int>dest_port;
    pair<int,int>protocol;
    int ID = 0;
};
struct packet
{
    unsigned int src_IP;
    unsigned int dest_IP;
    int src_port;
    int dest_port;
    int protocol;
};
unordered_map<unsigned int,vector<packet_rule> > table;
int erre = 0;
int memaccessnum = 0;
int rule_num = 9311;
vector<string>spilt(const string& str,const string& pattern)
{
    vector<string> result;
    string::size_type begin,end;
    begin = 0;
    end = str.find(pattern);
    while (end != string::npos)
    {
        if(end - begin != 0)
        {
            result.push_back(str.substr(begin,end-begin));
        }
        begin = end + pattern.size();
        end = str.find(pattern,begin);
    }
    if(begin != str.length())
    {
        result.push_back(str.substr(begin));
    }
    return result;
}
vector<string> formatting(string rule)
{
    vector<string> res = spilt(rule," ");
        string src_IP = res[0];
        string dest_IP = res[1];
        string protocol = res[8];
        vector<string>src_IP_wout_slash = spilt(src_IP,"/");
        vector<string>dest_IP_wout_slash= spilt(dest_IP,"/");
        vector<string>protocol_wout_slash= spilt(protocol,"/");
        size_t pos = src_IP_wout_slash[0].find("@");
        src_IP_wout_slash[0] = src_IP_wout_slash[0].substr(pos+1);
        vector<string> rule_formatted;
        rule_formatted.push_back(src_IP_wout_slash[0]);
        rule_formatted.push_back(src_IP_wout_slash[1]);
        rule_formatted.push_back(dest_IP_wout_slash[0]);
        rule_formatted.push_back(dest_IP_wout_slash[1]);
        rule_formatted.push_back(res[2]);
        rule_formatted.push_back(res[4]);
        rule_formatted.push_back(res[5]);
        rule_formatted.push_back(res[7]);
        rule_formatted.push_back(protocol_wout_slash[0]);
        rule_formatted.push_back(protocol_wout_slash[1]);
    return rule_formatted;
}
vector<vector<string> >open_file_formatting(string file_name)
{
    ifstream ifs(file_name);
    if(!ifs.is_open()){
        cout << "failed to open the file\n";
    }
    string rule;
    vector<vector<string> > rule_2d;
    while(getline(ifs,rule))
    {   
        rule_2d.push_back(formatting(rule));
    }
    ifs.close();
    return rule_2d;
}
unsigned int cal_IP(string IP,string prefix)
{
    if(stoi(prefix) == 0)return wildcard;
    unsigned int res = 0;
    vector<string> IP_part = spilt(IP,".");
    res = ( (stoi(IP_part[0]) << 24) + (stoi(IP_part[1]) << 16) + (stoi(IP_part[2]) << 8) + (stoi(IP_part[3])));
    res = (res >> (32-stoi(prefix)));
    return res;
}
unsigned int cal_dest_IP(string IP,string prefix)
{
    if(stoi(prefix) == 0)return wildcard;
    unsigned int res = 0;
    vector<string> IP_part = spilt(IP,".");
    res = ( (stoi(IP_part[0]) << 24) + (stoi(IP_part[1]) << 16) + (stoi(IP_part[2]) << 8) + (stoi(IP_part[3])));
    return res;
}
packet_rule packetalize(vector<string> rule_v)//set packet_value
{
    packet_rule rule;
    rule.src_IP = cal_IP(rule_v[0],rule_v[1]);
    rule.dest_IP = cal_dest_IP(rule_v[2],rule_v[3]);
    rule.prefix = stoi(rule_v[3]);
    rule.src_port.first = stoi(rule_v[4]);
    rule.src_port.second = stoi(rule_v[5]);
    rule.dest_port.first = stoi(rule_v[6]);
    rule.dest_port.second = stoi(rule_v[7]);
    rule.protocol.first = stoi(rule_v[8],0,0);
    rule.protocol.second = stoi(rule_v[9],0,0);
    return rule;
}
void rule_table_build(vector<vector<string> > rule_vec)
{

    for(int i = 0 ;i < rule_num;i++)
    {
        packet_rule rule = packetalize(rule_vec[i]);
        rule.ID = i+1;
        if(table.find(rule.src_IP) == table.end())//not found
        {
            vector<packet_rule> arr;
            arr.push_back(rule);
            table[rule.src_IP] = arr;
        }
        else
        {
            table[rule.src_IP].push_back(rule);
        }
    }
}
bool cmp(packet packet_input,packet_rule rule)
{
    memaccessnum++;
    if((rule.protocol.second == 255) && packet_input.protocol != rule.protocol.first) // not wildcard but not same protocol
        return false;
    else if(packet_input.dest_port > rule.dest_port.second || packet_input.dest_port < rule.dest_port.first) // out of dest_port boundary
        return false;
    else if(packet_input.src_port > rule.src_port.second || packet_input.src_port < rule.src_port.first) // out of src_port boundary
        return false;
    if(rule.dest_IP == wildcard)
        return true;
    bitset<32> bitvec1(packet_input.dest_IP);
    bitset<32> bitvec2(rule.dest_IP);
    for(int i = 0;i <= rule.prefix;i++)
    {
        if(bitvec1[32-i] != bitvec2[32-i])
            return false;
    }
    return true;
}
int search(packet packet_input)
{
    int answer = 99999;
    memaccessnum = 0;
    for (int i = 0; i <= 32; i++)
    {
        if(packet_input.src_IP == 0) packet_input.src_IP = wildcard;
        if(table.find(packet_input.src_IP >> i) == table.end())//not found,then next prefix 
        {
            memaccessnum++;
            continue;
        }  
        else{
            for (packet_rule j:table[packet_input.src_IP >> i])
            {
                if(cmp(packet_input,j))
                {
                    if(j.ID < answer)
                    {
                        answer = j.ID;
                    }
                }
                else 
                    continue;
            }
        }
    }
    return answer;
}
int main()
{
    vector<vector<string> > rule_vec = open_file_formatting("fw1_10K.txt");
    rule_table_build(rule_vec);
    unsigned int src_IP,dest_IP;
    int src_port,dest_port,protocol;
    int line;
    /*
    while(cin >> src_IP >> dest_IP >> src_port >> dest_port >> protocol)
    {
        packet packet_input;
        packet_input.src_IP = src_IP;
        packet_input.dest_IP = dest_IP;
        packet_input.src_port = src_port;
        packet_input.dest_port = dest_port;
        packet_input.protocol = protocol;
        cout << search(packet_input) << "\n";
        cout << "the number of  memory access is: " << memaccessnum << "\n";
        cout << (table.size() * sizeof(table) + rule_num * sizeof(packet_rule)) << " Bytes\n";
    }*/
    ifstream ifs("fw1_10K_trace.txt",ios::in);
    if(!ifs.is_open())
    {
        cout << "failed to open file\n";
        return 1;
    }
    int max_num = 0;
    while(ifs >> src_IP >> dest_IP >> src_port >> dest_port >> protocol >> line)
    {
        packet packet_input;
        packet_input.src_IP = src_IP;
        packet_input.dest_IP = dest_IP;
        packet_input.src_port = src_port;
        packet_input.dest_port = dest_port;
        packet_input.protocol = protocol;
        search(packet_input);
        if(memaccessnum > max_num)
            max_num = memaccessnum;
         /*
            cout << src_IP <<" "<< dest_IP <<" "<< src_port <<" "<< dest_port <<" "<< protocol <<" "<< line << "\n";
            cout << search(packet_input) << "\n";
            erre++;*/
    }
    cout << "the number of  memory access is:" << max_num << "\n"; 
    cout << (table.size() * sizeof(table) + rule_num * sizeof(packet_rule)) << " Bytes\n";
    return 0;
}
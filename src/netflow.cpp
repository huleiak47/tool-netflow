#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <boost/program_options.hpp>

using namespace std;
using namespace boost;
namespace bpo = boost::program_options;

bool list_devices = false;
bool is_shutdown = false;
int device_index = 0;
int ret_code = 1;
MIB_IFTABLE* p_iftable = NULL;
DWORD table_size = 0;
int threshold = 0;
int max_time = 999999;

void init(void)
{
    p_iftable = (MIB_IFTABLE*)malloc(sizeof(MIB_IFTABLE));
    if (!p_iftable)
    {
        printf("allocate memory failed.\n");
        exit(-1);
    }
    DWORD dwSize;
    dwSize = sizeof(MIB_IFTABLE);
    if (GetIfTable(p_iftable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
    {
        free(p_iftable);
        p_iftable = (MIB_IFTABLE*)malloc(dwSize);
        if (!p_iftable)
        {
            printf("allocate memory failed.\n");
            exit(-1);
        }
    }
    table_size = dwSize;
}


void list_all(void)
{
    DWORD dwSize = table_size;
    if (GetIfTable(p_iftable, &dwSize, FALSE) == NO_ERROR)
    {
        for (int i = 0; i < (int) p_iftable->dwNumEntries; i++)
        {
            MIB_IFROW* pIfRow = (MIB_IFROW*) & p_iftable->table[i];
            printf("index:\t %d\n", i);
            wprintf(L"name:\t %s\n", pIfRow->wszName);
            printf("description:\t %s\n", pIfRow->bDescr);
            printf("dwIndex:\t %d\n", pIfRow->dwIndex);
            printf("type:\t ");
            switch (pIfRow->dwType)
            {
            case IF_TYPE_OTHER:
                printf("Other\n");
                break;
            case IF_TYPE_ETHERNET_CSMACD:
                printf("Ethernet\n");
                break;
            case IF_TYPE_ISO88025_TOKENRING:
                printf("Token Ring\n");
                break;
            case IF_TYPE_PPP:
                printf("PPP\n");
                break;
            case IF_TYPE_SOFTWARE_LOOPBACK:
                printf("Software Lookback\n");
                break;
            case IF_TYPE_ATM:
                printf("ATM\n");
                break;
            case IF_TYPE_IEEE80211:
                printf("IEEE 802.11 Wireless\n");
                break;
            case IF_TYPE_TUNNEL:
                printf("Tunnel type encapsulation\n");
                break;
            case IF_TYPE_IEEE1394:
                printf("IEEE 1394 Firewire\n");
                break;
            default:
                printf("Unknown type %ld\n", pIfRow->dwType);
                break;
            }
            printf("physical addr:\t ");
            if (pIfRow->dwPhysAddrLen == 0)
            {
                printf("\n");
            }
            for (int j = 0; j < (int) pIfRow->dwPhysAddrLen; j++)
            {
                if (j == (pIfRow->dwPhysAddrLen - 1))
                {
                    printf("%.2x\n", (int) pIfRow->bPhysAddr[j]);
                }
                else
                {
                    printf("%.2x-", (int) pIfRow->bPhysAddr[j]);
                }
            }
            printf("\n");
        }
    }
    else
    {
        printf("GetIfTable failed.\n");
    }
}

void watch_flow(void)
{
    DWORD oldtick = GetTickCount();
    DWORD old_out_flow = 0;
    DWORD old_in_flow = 0;
    int timeleft = max_time;
    while (1)
    {
        DWORD dwSize = table_size;
        if (GetIfTable(p_iftable, &dwSize, FALSE) != NO_ERROR)
        {
            printf("GetIfTable failed.\n");
            exit(-1);
        }
        DWORD new_out_flow = p_iftable->table[device_index].dwOutOctets;
        DWORD new_in_flow = p_iftable->table[device_index].dwInOctets;
        if (old_out_flow != 0)
        {
            char line[128] = {0};
            char title[128] = {0};
            int size = sprintf(line, "in speed: %.1f KB/S  out speed: %.1f KB/S", (new_in_flow - old_in_flow) / 1024.0, (new_out_flow - old_out_flow) / 1024.0);
            int tsize = sprintf(title, "%.1fK", (new_in_flow - old_in_flow) / 1024.0);
            if (threshold != 0)
            {
                if (new_in_flow - old_in_flow < threshold * 1000)
                {
                    timeleft--;
                    if (timeleft == 0)
                    {
                        if (is_shutdown)
                        {
                            system("shutdown -s -t 0");
                        }
                        exit(ret_code);
                    }
                }
                else
                {
                    timeleft = max_time;
                }
                if (!is_shutdown)
                {
                    size += sprintf(&line[size], "  exit after: %ld S", timeleft);
                    sprintf(&title[tsize], " %ldS Exit", timeleft);
                }
                else
                {
                    size += sprintf(&line[size], "  shutdown after: %ld S", timeleft);
                    sprintf(&title[tsize], " %ldS Shut", timeleft);
                }
            }
            for (int i = size; i < 80; ++i)
            {
                line[i] = ' ';
            }
            printf("%s\r", line);
            SetConsoleTitleA(title);
        }
        old_out_flow = new_out_flow;
        old_in_flow = new_in_flow;

        //wait 1 second
        DWORD newtick;
        do
        {
            Sleep(10);
            newtick = GetTickCount();
        }
        while (newtick - oldtick < 1000);
        oldtick = newtick;
    }
}

void help(bpo::options_description& opts)
{
    stringstream ss;
    ss << "usage: netflow --shutdown --maxtime 600 --threshold 500 --index 21" << endl;
    ss << opts << endl;
    printf("%s", ss.str().c_str());
}
void parse_commandline(int argc, char** argv)
{
    bpo::options_description opts("netflow options");
    opts.add_options()
    ("help,h", "show help information.")
    ("list,l", bpo::value<bool>(&list_devices)->default_value(false)->implicit_value(true), "list information of all devices and exit.")
    ("index,i", bpo::value<int>(&device_index)->default_value(0), "the index of device to watch over.")
    ("threshold,t", bpo::value<int>(&threshold)->default_value(0), "the threshold of incoming speed to exit or shutdown computer, unit is KB/S. if not set, program will never exit.")
    ("shutdown,s", bpo::value<bool>(&is_shutdown)->default_value(false)->implicit_value(true), "set program to shutdown computer but not exit.")
    ("maxtime,m", bpo::value<int>(&max_time)->default_value(999999), "when the incoming speed is under threshold for `maxtime` seconds, program will exit or shutdown computer.")
    ("retcode,r", bpo::value<int>(&ret_code)->default_value(1), "program will exit with this value.")
    ;
    bpo::variables_map vm;
    try
    {
        bpo::store(bpo::parse_command_line(argc, argv, opts), vm);
    }
    catch (bpo::error& e)
    {
        printf("%s\n", e.what());
        help(opts);
        exit(-1);
    }

    if (vm.count("help"))
    {
        help(opts);
        exit(0);
    }

    vm.notify();
}

void on_exit(void)
{
    if (p_iftable)
    {
        free(p_iftable);
    }
}

int main(int argc, char** argv)
{
    parse_commandline(argc, argv);
    atexit(on_exit);
    init();
    if (list_devices)
    {
        list_all();
    }
    else
    {
        watch_flow();
    }
    return 0;
}

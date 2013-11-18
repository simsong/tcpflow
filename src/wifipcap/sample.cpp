#include <iostream>
#include "wifipcap.h"

class TestCB : public WifipcapCallbacks
{
private:
    bool fcs_ok;
public:
    virtual void PacketBegin(const struct timeval& t, const u_char *pkt, u_int len, int origlen) {
	//cout << t << " {" << endl;
    }
    virtual void PacketEnd()    {
	//cout << "}" << endl;
    }
 
    virtual bool Check80211FCS() { return true; }

    virtual void Handle80211DataFromAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, u_int len)     {
	if (!fcs_ok) {
            std::cout << "  " << "802.11 data:\t" 
                      << hdr->sa << " -> " 
                      << hdr->da << "\t" 
                      << len << std::endl;
	}
    }
    virtual void Handle80211DataToAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, u_int len) 
    {
	if (!fcs_ok) {
            std::cout << "  " << "802.11 data:\t" 
                      << hdr->sa << " -> " 
                      << hdr->da << "\t" 
                      << len << std::endl;
	}
    }


    virtual void HandleEthernet(const struct timeval& t, const ether_hdr_t *hdr, const u_char *rest, u_int len) {
        std::cout << " Ethernet: " << hdr->sa << " -> " << hdr->da << std::endl;
    }
    
    virtual void Handle80211MgmtProbeRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {
	if (!fcs_ok) {
	    std::cout << "  " << "802.11 mgmt:\t" 
                      << hdr->sa << "\tprobe\t\"" 
                      << body->ssid.ssid << "\"" << std::endl;
	}
    }

    virtual void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body)    {
	if (!fcs_ok) {
	    std::cout << "  " << "802.11 mgmt:\t" 
                      << hdr->sa << "\tbeacon\t\"" 
                      << body->ssid.ssid << "\"" << std::endl;
	}
    }

    virtual void HandleTCP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const tcp_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, u_int len) {
	if (ip4h && hdr)
	    std::cout << "  " << "tcp/ip:     \t" 
                      << ip4h->src << ":" << hdr->sport << " -> " 
                      << ip4h->dst << ":" << hdr->dport 
                      << "\t" << ip4h->len << std::endl;
	else
	    std::cout << "  " << "tcp/ip:     \t" << "[truncated]" << std::endl;
    }   

    virtual void HandleUDP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const udp_hdr_t *hdr, const u_char *rest, u_int len)	{
        if (ip4h && hdr)
            std::cout << "  " << "udp/ip:     \t" 
                      << ip4h->src << ":" << hdr->sport << " -> " 
                      << ip4h->dst << ":" << hdr->dport 
                      << "\t" << ip4h->len << std::endl;
        else
            std::cout << " " << "udp/ip:     \t" << "[truncated]" << std::endl;
    }
};

/**
 * usage: test <pcap_trace_file>
 */
int main(int argc, char **argv)
{
#ifdef _WIN32
    if (argc == 1) {
        pcap_if_t *alldevs;
        pcap_if_t *d;
        int i=0;
        char errbuf[PCAP_ERRBUF_SIZE];
    
        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)        {
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            exit(1);
        }
    
        /* Print the list */
        for(d= alldevs; d != NULL; d= d->next)        {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }
    
        if (i == 0)        {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return 1;
        }

        /* We don't need any more the device list. Free it */
        pcap_freealldevs(alldevs);
	return 1;
    }
#endif

    bool live = argc == 3 && atoi(argv[2]) == 1;
    Wifipcap *wcap = new Wifipcap(argv[1], live);
    wcap->Run(new TestCB());
    return 0;
}

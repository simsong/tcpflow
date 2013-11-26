#include <iostream>
#include "wifipcap.h"

/* Demonstration of how to process pcap packets with a simple callback class */

class TestCB : public WifipcapCallbacks
{
public:
    TestCB(){}
    virtual ~TestCB(){};
    virtual const char *name()  {return "TestCB";} // override with your own name!
    virtual void PacketBegin(const WifiPacket &p, const u_char *pkt, size_t len, int origlen)  {
        TimeVal t(p.header->ts);
        std::cout << &t << " {";
    }
    virtual void PacketEnd(const WifiPacket &p )    {
        std::cout << "}" << std::endl;
    }
 
    virtual bool Check80211FCS(const WifiPacket &p )  { return true; } // please calculate FCS

    virtual void Handle80211DataFromAP(const WifiPacket &p, const mac_hdr_t *hdr, const u_char *rest, u_int len)      {
        std::cout << "802.11 data:\t" 
                      << hdr->sa << " -> " 
                      << hdr->da << "\t" 
                      << len ;
    }
    virtual void Handle80211DataToAP(const WifiPacket &p, const mac_hdr_t *hdr, const u_char *rest, u_int len) 
    {
        std::cout << "802.11 data:\t" 
                  << hdr->sa << " -> " 
                  << hdr->da << "\t" 
                  << len ;
    }


    virtual void Handle80211MgmtProbeRequest(const WifiPacket &p,  const mgmt_header_t *hdr, const mgmt_body_t *body)  {
        std::cout << "802.11 mgmt:\t" 
                  << hdr->sa << "\tprobe\t\"" 
                  << body->ssid.ssid << "\"" ;
    }

    virtual void Handle80211MgmtBeacon(const WifiPacket &p,  const struct mgmt_header_t *hdr, const struct mgmt_body_t *body)    {
        std::cout << "802.11 mgmt:\t" 
                  << hdr->sa << "\tbeacon\t\"" 
                  << body->ssid.ssid << "\"" ;
    }

    virtual void HandleTCP(const WifiPacket &p,  const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const tcp_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, u_int len)  {
	if (ip4h && hdr)
	    std::cout << "tcp/ip:     \t" 
                      << ip4h->src << ":" << hdr->sport << " -> " 
                      << ip4h->dst << ":" << hdr->dport 
                      << "\t" << ip4h->len ;
	else
	    std::cout << "tcp/ip:     \t" << "[truncated]" ;
    }   

    virtual void HandleUDP(const WifiPacket &p,  const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const udp_hdr_t *hdr, const u_char *rest, u_int len)  {
        if (ip4h && hdr)
            std::cout << "udp/ip:     \t" 
                      << ip4h->src << ":" << hdr->sport << " -> " 
                      << ip4h->dst << ":" << hdr->dport 
                      << "\t" << ip4h->len ;
        else
            std::cout << " " << "udp/ip:     \t" << "[truncated]" ;
    }
};


/**
 * usage: test <pcap_trace_file>
 */
int main(int argc, char **argv)
{
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

    bool live = argc == 3 && atoi(argv[2]) == 1;
    Wifipcap *wcap = new Wifipcap(argv[1], live);
    wcap->Run(new TestCB());
    return 0;
}


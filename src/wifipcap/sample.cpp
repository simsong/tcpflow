
#include <iostream>
#include "wifipcap.h"

using namespace std;

class TestCB : public WifipcapCallbacks
{
private:
    bool fcs_ok;
public:
	/*
    void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen)
    {
	cout << t << " {" << endl;
    }
    void PacketEnd()
    {
	cout << "}" << endl;
    }
	*/
 
    bool Check80211FCS() { return true; }

    void Handle80211DataFromAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) 
    {
	if (!fcs_ok) {
	    cout << "  " << "802.11 data:\t" 
		 << hdr->sa << " -> " 
		 << hdr->da << "\t" 
		 << len << endl;
	}
    }
    void Handle80211DataToAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) 
    {
	if (!fcs_ok) {
	    cout << "  " << "802.11 data:\t" 
		 << hdr->sa << " -> " 
		 << hdr->da << "\t" 
		 << len << endl;
	}
    }

    void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta, bool fcs_ok) {
	this->fcs_ok = fcs_ok;
    }

	void HandleEthernet(const struct timeval& t, const ether_hdr_t *hdr, const u_char *rest, int len) {
		cout << " Ethernet: " << hdr->sa << " -> " << hdr->da << endl;
	}
    
    void Handle80211MgmtProbeRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body)
    {
	if (!fcs_ok) {
	    cout << "  " << "802.11 mgmt:\t" 
		 << hdr->sa << "\tprobe\t\"" 
		 << body->ssid.ssid << "\"" << endl;
	}
    }

    void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body)
    {
	if (!fcs_ok) {
	    cout << "  " << "802.11 mgmt:\t" 
		 << hdr->sa << "\tbeacon\t\"" 
		 << body->ssid.ssid << "\"" << endl;
	}
    }

    void HandleTCP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const tcp_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, int len)
    {
	if (ip4h && hdr)
	    cout << "  " << "tcp/ip:     \t" 
		 << ip4h->src << ":" << hdr->sport << " -> " 
		 << ip4h->dst << ":" << hdr->dport 
		 << "\t" << ip4h->len << endl;
	else
	    cout << "  " << "tcp/ip:     \t" << "[truncated]" << endl;
    }   

	void HandleUDP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const udp_hdr_t *hdr, const u_char *rest, int len)
	{
		if (ip4h && hdr)
			cout << "  " << "udp/ip:     \t" 
		 << ip4h->src << ":" << hdr->sport << " -> " 
		 << ip4h->dst << ":" << hdr->dport 
		 << "\t" << ip4h->len << endl;
		else
			cout << " " << "udp/ip:     \t" << "[truncated]" << endl;
	}
};

/**
 * usage: test <pcap_trace_file>
 */
int main(int argc, char **argv) {
#ifdef _WIN32
	if (argc == 1) {
 pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i == 0)
    {
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

/**
 * wifi datalink function and callbacks to handle 802.11
 *
 */ 


#include "tcpflow.h"

#include "wifipcap.h"
class Tcpflow_Callbacks : public WifipcapCallbacks {
private:
    bool fcs_ok;                        // framechecksum is okay?
public:
    Tcpflow_Callbacks():fcs_ok(){};

#ifdef DEBUG_WIFI
    void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen) {
	cout << t << " {" << endl;
    }
    void PacketEnd() {
	cout << "}" << endl;
    }
#endif
 
    bool Check80211FCS() { return true; } // check the frame checksums
    void Handle80211DataFromAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {
	if (!fcs_ok) {
            cout << hdr->sa;

	    cout << "  " << "802.11 data from AP:\t" 
		 << hdr->sa << " -> " 
		 << hdr->da << "\t" 
		 << len << endl;
	}
    }
    void Handle80211DataToAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {
	if (!fcs_ok) {
	    cout << "  " << "802.11 data to AP:\t" 
		 << hdr->sa << " -> " 
		 << hdr->da << "\t" 
		 << len << endl;
	}
    }

    void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta,const u_char *ptr, int len, bool flag) {
        std::cerr << "fcs set to " << flag << "\n";
	this->fcs_ok = flag;
    }

    void HandleEthernet(const struct timeval& t, const ether_hdr_t *hdr, const u_char *rest, int len) {
        cout << " Ethernet: " << hdr->sa << " -> " << hdr->da << endl;
    }
    
    void Handle80211MgmtProbeRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {
	if (!fcs_ok) {
	    cout << "  " << "802.11 mgmt:\t" 
		 << hdr->sa << "\tprobe\t\"" 
		 << body->ssid.ssid << "\"" << endl;
	}
    }

    void Handle80211MgmtAssocRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {
	if (!fcs_ok) {
	    cout << "  " << "802.11 mgmt:\t" 
		 << hdr->sa << "\tassocRequest\t\"" 
		 << body->ssid.ssid << "\"" << endl;
	}
    }

    void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {
	if (!fcs_ok || 1) {
	    cout << "  " << "802.11 mgmt:\t" 
		 << hdr->sa << "\tbeacon\t\"" 
		 << body->ssid.ssid << "\"" << endl;
	} else {
            cout << "GADS\n";
        }
    }
};

/* Entrance point */
static Wifipcap *wcap = 0;
static Wifipcap::PcapUserData data;
void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    if(wcap==0){
        wcap = new Wifipcap();
        data.wcap = wcap;
        data.cbs  = new Tcpflow_Callbacks();
        data.header_type = DLT_IEEE802_11_RADIO;
    }
    Wifipcap::handle_packet(reinterpret_cast<u_char *>(&data),h,p);
}    

#ifdef STANDALONE
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
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
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
    wcap->Run(new Tcpflow_Callbacks());
    return 0;
}

#endif

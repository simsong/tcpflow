/**********************************************************************
 * Log:
 * 2006-03-12: Parts originally authored by Doug Madory as wifi_parser.c
 * 2013-03-15: Substantially modified by Simson Garfinkel for inclusion into tcpflow
 * 2013-11-18: reworked static calls to be entirely calls to a class. Changed TimeVal pointer to an instance variable that includes the full packet header.
 **********************************************************************/

//*do 11-18

#include "config.h"		// pull in HAVE_ defines

#define __STDC_FORMAT_MACROS 

#include <stdint.h>
#include <inttypes.h>

#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <stdarg.h>
#include <errno.h>

#ifdef HAVE_NET_ETHERNET_H
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <net/ethernet.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#pragma GCC diagnostic ignored "-Wcast-align"

#include "wifipcap.h"

#include "cpack.h"
#include "extract.h"
#include "oui.h"
#include "ethertype.h"
#include "icmp.h"
#include "ipproto.h"

/* wifipcap uses a MAC class which is somewhat lame, but works */

MAC MAC::broadcast(0xffffffffffffULL);
MAC MAC::null((uint64_t)0);
int WifiPacket::debug=0;
int MAC::print_fmt(MAC::PRINT_FMT_COLON);

std::ostream& operator<<(std::ostream& out, const MAC& mac) {
    const char *fmt = MAC::print_fmt == MAC::PRINT_FMT_COLON ? 
	"%02x:%02x:%02x:%02x:%02x:%02x" :
	"%02x%02x%02x%02x%02x%02x";
    char buf[24];
    sprintf(buf, fmt, 
	    (int)((mac.val>>40)&0xff),
	    (int)((mac.val>>32)&0xff),
	    (int)((mac.val>>24)&0xff),
	    (int)((mac.val>>16)&0xff),
	    (int)((mac.val>>8)&0xff),
	    (int)((mac.val)&0xff)
        );
    out << buf;
    return out;
}

std::ostream& operator<<(std::ostream& out, const struct in_addr& ip) {
    out << inet_ntoa(ip);
    return out;
}

struct tok {
    int v;			/* value */
    const char *s;		/* string */
};

#if 0
static const struct tok ethertype_values[] = { 
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_MPLS_MULTI,	"MPLS multicast" },
    { ETHERTYPE_IPV6,		"IPv6" },
    { ETHERTYPE_8021Q,		"802.1Q" },
    { ETHERTYPE_VMAN,		"VMAN" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "ARP"},
    { ETHERTYPE_REVARP,         "Reverse ARP"},
    { ETHERTYPE_NS,             "NS" },
    { ETHERTYPE_SPRITE,         "Sprite" },
    { ETHERTYPE_TRAIL,          "Trail" },
    { ETHERTYPE_MOPDL,          "MOP DL" },
    { ETHERTYPE_MOPRC,          "MOP RC" },
    { ETHERTYPE_DN,             "DN" },
    { ETHERTYPE_LAT,            "LAT" },
    { ETHERTYPE_SCA,            "SCA" },
    { ETHERTYPE_LANBRIDGE,      "Lanbridge" },
    { ETHERTYPE_DECDNS,         "DEC DNS" },
    { ETHERTYPE_DECDTS,         "DEC DTS" },
    { ETHERTYPE_VEXP,           "VEXP" },
    { ETHERTYPE_VPROD,          "VPROD" },
    { ETHERTYPE_ATALK,          "Appletalk" },
    { ETHERTYPE_AARP,           "Appletalk ARP" },
    { ETHERTYPE_IPX,            "IPX" },
    { ETHERTYPE_PPP,            "PPP" },
    { ETHERTYPE_SLOW,           "Slow Protocols" },
    { ETHERTYPE_PPPOED,         "PPPoE D" },
    { ETHERTYPE_PPPOES,         "PPPoE S" },
    { ETHERTYPE_EAPOL,          "EAPOL" },
    { ETHERTYPE_JUMBO,          "Jumbo" },
    { ETHERTYPE_LOOPBACK,       "Loopback" },
    { ETHERTYPE_ISO,            "OSI" },
    { ETHERTYPE_GRE_ISO,        "GRE-OSI" },
    { 0, NULL}
};
#endif

/*max length of an IEEE 802.11 packet*/
#ifndef MAX_LEN_80211
#define MAX_LEN_80211 3000
#endif

/* from ethereal packet-prism.c */
#define pletohs(p)  ((u_int16_t)					\
		     ((u_int16_t)*((const u_int8_t *)(p)+1)<<8|		\
		      (u_int16_t)*((const u_int8_t *)(p)+0)<<0))
#define pntohl(p)   ((u_int32_t)*((const u_int8_t *)(p)+0)<<24|	\
		     (u_int32_t)*((const u_int8_t *)(p)+1)<<16|	\
		     (u_int32_t)*((const u_int8_t *)(p)+2)<<8|	\
		     (u_int32_t)*((const u_int8_t *)(p)+3)<<0)
#define COOK_FRAGMENT_NUMBER(x) ((x) & 0x000F)
#define COOK_SEQUENCE_NUMBER(x) (((x) & 0xFFF0) >> 4)
/* end ethereal code */

/* Sequence number gap */
#define SEQ_GAP(current, last)(0xfff & (current - last))

/* In the following three arrays, even though the QoS subtypes are listed, in the rest of the program
 * the QoS subtypes are treated as "OTHER_TYPES". The file "ieee802_11.h" currently doesn't account for
 * the existence of QoS subtypes. The QoS subtypes might need to be accomodated there in the future.
 */
#if 0
static const char * mgmt_subtype_text[] = {
    "AssocReq",
    "AssocResp",
    "ReAssocReq",
    "ReAssocResp",
    "ProbeReq",
    "ProbeResp",
    "",
    "",
    "Beacon",
    "ATIM",
    "Disassoc",
    "Auth",
    "DeAuth",
    "Action", /*QoS mgmt_subtype*/
    "",
    ""
};

static const char * ctrl_subtype_text[] = {
    "", "", "", "", "", "", "", "",
    "BlockAckReq", /*QoS ctrl_subtype*/
    "BlockAck",    /*QoS ctrl_subtype*/
    "PS-Poll",
    "RTS",
    "CTS",
    "ACK",
    "CF-End",
    "CF-End+CF-Ack"
};

static const char * data_subtype_text[] = {
    "Data",
    "Data+CF-Ack",
    "Data+CF-Poll",
    "Data+CF-Ack+CF-Poll",
    "Null(no_data)",
    "CF-Ack(no_data)",
    "CF-Poll(no_data)",
    "CF-Ack+CF-Poll(no_data)",
    "QoS_Data", /*QoS data_subtypes from here on*/
    "QoS_Data+CF-Ack",
    "QoS_Data+CF-Poll",
    "QoS_Data+CF-Ack+CF-Poll",
    "QoS_Null(no_data)",
    "",
    "QoS_CF-Poll(no_data)",
    "QoS_CF-Ack+CF-Poll(no_data)"
};
#endif

///////////////////////////////////////////////////////////////////////////////
// crc32 implementation needed for wifi checksum

/* crc32.c
 * CRC-32 routine
 *
 * $Id: crc32.cpp,v 1.1 2007/02/14 00:05:50 jpang Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Credits:
 *
 * Table from Solomon Peachy
 * Routine from Chris Waters
 */

/*
 * Table for the AUTODIN/HDLC/802.x CRC.
 *
 * Polynomial is
 *
 *  x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^8 + x^7 +
 *      x^5 + x^4 + x^2 + x + 1
 */
static const uint32_t crc32_ccitt_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
    0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
    0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
    0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
    0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
    0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
    0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
    0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
    0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
    0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
    0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
    0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
    0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
    0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
    0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
    0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
    0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
    0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
    0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
    0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
    0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
    0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
    0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
    0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
    0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
    0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
    0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
    0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
    0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
    0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
    0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
    0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
    0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
    0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
    0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
    0x2d02ef8d
};

#define CRC32_CCITT_SEED    0xFFFFFFFF

static uint32_t crc32_ccitt_seed(const uint8_t *buf, size_t len, uint32_t seed);

static uint32_t crc32_ccitt(const uint8_t *buf, size_t len)
{
    return ( crc32_ccitt_seed(buf, len, CRC32_CCITT_SEED) );
}

static uint32_t crc32_ccitt_seed(const uint8_t *buf, size_t len, uint32_t seed)
{
    uint32_t crc32 = seed;

    for (unsigned int i = 0; i < len; i++){
        crc32 = crc32_ccitt_table[(crc32 ^ buf[i]) & 0xff] ^ (crc32 >> 8);
    }

    return ( ~crc32 );
}

/*
 * IEEE 802.x version (Ethernet and 802.11, at least) - byte-swap
 * the result of "crc32()".
 *
 * XXX - does this mean we should fetch the Ethernet and 802.11
 * Frame Checksum (FCS) with "tvb_get_letohl()" rather than "tvb_get_ntohl()",
 * or is fetching it big-endian and byte-swapping the CRC done
 * to cope with 802.x sending stuff out in reverse bit order?
 */
static uint32_t crc32_802(const unsigned char *buf, size_t len)
{
    uint32_t c_crc;

    c_crc = crc32_ccitt(buf, len);

    /* Byte reverse. */
    c_crc = ((unsigned char)(c_crc>>0)<<24) |
        ((unsigned char)(c_crc>>8)<<16) |
        ((unsigned char)(c_crc>>16)<<8) |
        ((unsigned char)(c_crc>>24)<<0);

    return ( c_crc );
}
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

/* Translate Ethernet address, as seen in struct ether_header, to type MAC. */
/* Extract header length. */
static size_t extract_header_length(u_int16_t fc)
{
    switch (FC_TYPE(fc)) {
    case T_MGMT:
	return MGMT_HDRLEN;
    case T_CTRL:
	switch (FC_SUBTYPE(fc)) {
	case CTRL_PS_POLL:
	    return CTRL_PS_POLL_HDRLEN;
	case CTRL_RTS:
	    return CTRL_RTS_HDRLEN;
	case CTRL_CTS:
	    return CTRL_CTS_HDRLEN;
	case CTRL_ACK:
	    return CTRL_ACK_HDRLEN;
	case CTRL_CF_END:
	    return CTRL_END_HDRLEN;
	case CTRL_END_ACK:
	    return CTRL_END_ACK_HDRLEN;
	default:
	    return 0;
	}
    case T_DATA:
	return (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
    default:
	return 0;
    }
}

///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

#pragma GCC diagnostic ignored "-Wcast-align"
void WifiPacket::handle_llc(const mac_hdr_t &mac,const u_char *ptr, size_t len,u_int16_t fc)
{
    if (len < 7) {
	// truncated header!
	cbs->HandleLLC(*this,NULL, ptr, len);
	return;
    }

    // http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets

    llc_hdr_t hdr;
    hdr.dsap   = EXTRACT_LE_8BITS(ptr); // Destination Service Access point
    hdr.ssap   = EXTRACT_LE_8BITS(ptr + 1); // Source Service Access Point
    hdr.control= EXTRACT_LE_8BITS(ptr + 2); // ignored by most protocols
    hdr.oui    = EXTRACT_24BITS(ptr + 3);
    hdr.type   = EXTRACT_16BITS(ptr + 6);


    /* "When both the DSAP and SSAP are set to 0xAA, the type is
     * interpreted as a protocol not defined by IEEE and the LSAP is
     * referred to as SubNetwork Access Protocol (SNAP).  In SNAP, the
     * 5 bytes that follow the DSAP, SSAP, and control byte are called
     * the Protocol Discriminator."
     */

    if(hdr.dsap==0xAA && hdr.ssap==0xAA){
        cbs->HandleLLC(*this,&hdr,ptr+8,len-8);
        return;
    }

    if (hdr.oui == OUI_ENCAP_ETHER || hdr.oui == OUI_CISCO_90) {
        cbs->HandleLLC(*this,&hdr, ptr+8, len-8);
        return;
    }
        
    cbs->HandleLLCUnknown(*this,ptr, len);
}

void WifiPacket::handle_wep(const u_char *ptr, size_t len)
{
    // Jeff: XXX handle TKIP/CCMP ? how can we demultiplex different
    // protection protocols?

    struct wep_hdr_t hdr;
    u_int32_t iv;

    if (len < IEEE802_11_IV_LEN + IEEE802_11_KID_LEN) {
	// truncated!
	cbs->HandleWEP(*this,NULL, ptr, len);
	return;
    }
    iv = EXTRACT_LE_32BITS(ptr);
    hdr.iv = IV_IV(iv);
    hdr.pad = IV_PAD(iv);
    hdr.keyid = IV_KEYID(iv);
    cbs->HandleWEP(*this,&hdr, ptr, len);
}

///////////////////////////////////////////////////////////////////////////////

static const char *auth_alg_text[]={"Open System","Shared Key","EAP"};
#define NUM_AUTH_ALGS	(sizeof auth_alg_text / sizeof auth_alg_text[0])

static const char *status_text[] = {
    "Succesful",  /*  0  */
    "Unspecified failure",  /*  1  */
    "Reserved",	  /*  2  */
    "Reserved",	  /*  3  */
    "Reserved",	  /*  4  */
    "Reserved",	  /*  5  */
    "Reserved",	  /*  6  */
    "Reserved",	  /*  7  */
    "Reserved",	  /*  8  */
    "Reserved",	  /*  9  */
    "Cannot Support all requested capabilities in the Capability Information field",	  /*  10  */
    "Reassociation denied due to inability to confirm that association exists",	  /*  11  */
    "Association denied due to reason outside the scope of the standard",	  /*  12  */
    "Responding station does not support the specified authentication algorithm ",	  /*  13  */
    "Received an Authentication frame with authentication transaction " \
    "sequence number out of expected sequence",	  /*  14  */
    "Authentication rejected because of challenge failure",	  /*  15 */
    "Authentication rejected due to timeout waiting for next frame in sequence",	  /*  16 */
    "Association denied because AP is unable to handle additional associated stations",	  /*  17 */
    "Association denied due to requesting station not supporting all of the " \
    "data rates in BSSBasicRateSet parameter",	  /*  18 */
};
#define NUM_STATUSES	(sizeof status_text / sizeof status_text[0])

static const char *reason_text[] = {
    "Reserved", /* 0 */
    "Unspecified reason", /* 1 */
    "Previous authentication no longer valid",  /* 2 */
    "Deauthenticated because sending station is leaving (or has left) IBSS or ESS", /* 3 */
    "Disassociated due to inactivity", /* 4 */
    "Disassociated because AP is unable to handle all currently associated stations", /* 5 */
    "Class 2 frame received from nonauthenticated station", /* 6 */
    "Class 3 frame received from nonassociated station", /* 7 */
    "Disassociated because sending station is leaving (or has left) BSS", /* 8 */
    "Station requesting (re)association is not authenticated with responding station", /* 9 */
};
#define NUM_REASONS	(sizeof reason_text / sizeof reason_text[0])

const char *Wifipcap::WifiUtil::MgmtAuthAlg2Txt(uint v) {
    return v < NUM_AUTH_ALGS ? auth_alg_text[v] : "Unknown";
}
const char *Wifipcap::WifiUtil::MgmtStatusCode2Txt(uint v) {
    return v < NUM_STATUSES ? status_text[v] : "Reserved";
}
const char *Wifipcap::WifiUtil::MgmtReasonCode2Txt(uint v) {
    return v < NUM_REASONS ? reason_text[v] : "Reserved";
}

///////////////////////////////////////////////////////////////////////////////

// Jeff: HACK -- tcpdump uses a global variable to check truncation
#define TTEST2(_p, _l) ((const u_char *)&(_p) - p + (_l) <= (ssize_t)len) 

void WifiPacket::parse_elements(struct mgmt_body_t *pbody, const u_char *p, int offset, size_t len)
{
    /*
     * We haven't seen any elements yet.
     */
    pbody->challenge_status = NOT_PRESENT;
    pbody->ssid_status = NOT_PRESENT;
    pbody->rates_status = NOT_PRESENT;
    pbody->ds_status = NOT_PRESENT;
    pbody->cf_status = NOT_PRESENT;
    pbody->tim_status = NOT_PRESENT;

    for (;;) {
        if (!TTEST2(*(p + offset), 1))
            return;
        switch (*(p + offset)) {
        case E_SSID:
            /* Present, possibly truncated */
            pbody->ssid_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 2))
                return;
            memcpy(&pbody->ssid, p + offset, 2);
            offset += 2;
            if (pbody->ssid.length != 0) {
                if (pbody->ssid.length >
                    sizeof(pbody->ssid.ssid) - 1)
                    return;
                if (!TTEST2(*(p + offset), pbody->ssid.length))
                    return;
                memcpy(&pbody->ssid.ssid, p + offset,
                       pbody->ssid.length);
                offset += pbody->ssid.length;
            }
            pbody->ssid.ssid[pbody->ssid.length] = '\0';
            /* Present and not truncated */
            pbody->ssid_status = PRESENT;
            break;
        case E_CHALLENGE:
            /* Present, possibly truncated */
            pbody->challenge_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 2))
                return;
            memcpy(&pbody->challenge, p + offset, 2);
            offset += 2;
            if (pbody->challenge.length != 0) {
                if (pbody->challenge.length >
                    sizeof(pbody->challenge.text) - 1)
                    return;
                if (!TTEST2(*(p + offset), pbody->challenge.length))
                    return;
                memcpy(&pbody->challenge.text, p + offset,
                       pbody->challenge.length);
                offset += pbody->challenge.length;
            }
            pbody->challenge.text[pbody->challenge.length] = '\0';
            /* Present and not truncated */
            pbody->challenge_status = PRESENT;
            break;
        case E_RATES:
            /* Present, possibly truncated */
            pbody->rates_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 2))
                return;
            memcpy(&(pbody->rates), p + offset, 2);
            offset += 2;
            if (pbody->rates.length != 0) {
                if (pbody->rates.length > sizeof pbody->rates.rate)
                    return;
                if (!TTEST2(*(p + offset), pbody->rates.length))
                    return;
                memcpy(&pbody->rates.rate, p + offset,
                       pbody->rates.length);
                offset += pbody->rates.length;
            }
            /* Present and not truncated */
            pbody->rates_status = PRESENT;
            break;
        case E_DS:
            /* Present, possibly truncated */
            pbody->ds_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 3))
                return;
            memcpy(&pbody->ds, p + offset, 3);
            offset += 3;
            /* Present and not truncated */
            pbody->ds_status = PRESENT;
            break;
        case E_CF:
            /* Present, possibly truncated */
            pbody->cf_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 8))
                return;
            memcpy(&pbody->cf, p + offset, 8);
            offset += 8;
            /* Present and not truncated */
            pbody->cf_status = PRESENT;
            break;
        case E_TIM:
            /* Present, possibly truncated */
            pbody->tim_status = TRUNCATED;
            if (!TTEST2(*(p + offset), 2))
                return;
            memcpy(&pbody->tim, p + offset, 2);
            offset += 2;
            if (!TTEST2(*(p + offset), 3))
                return;
            memcpy(&pbody->tim.count, p + offset, 3);
            offset += 3;

            if (pbody->tim.length <= 3)
                break;
            if (pbody->rates.length > sizeof pbody->tim.bitmap)
                return;
            if (!TTEST2(*(p + offset), pbody->tim.length - 3))
                return;
            memcpy(pbody->tim.bitmap, p + (pbody->tim.length - 3),
                   (pbody->tim.length - 3));
            offset += pbody->tim.length - 3;
            /* Present and not truncated */
            pbody->tim_status = PRESENT;
            break;
        default:
#ifdef DEBUG_WIFI
            printf("(1) unhandled element_id (%d)  ", *(p + offset) );
#endif
            if (!TTEST2(*(p + offset), 2))
                return;
            if (!TTEST2(*(p + offset + 2), *(p + offset + 1)))
                return;
            offset += *(p + offset + 1) + 2;
            break;
        }
    }
}

/*********************************************************************************
 * Print Handle functions for the management frame types
 *********************************************************************************/

int
WifiPacket::handle_beacon( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
                IEEE802_11_CAPINFO_LEN))
        return 0;
    memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
    offset += IEEE802_11_TSTAMP_LEN;
    pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_BCNINT_LEN;
    pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_CAPINFO_LEN;

    parse_elements(&pbody, p, offset, len);

    /*
      PRINT_SSID(pbody);
      PRINT_RATES(pbody);
      printf(" %s",
      CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
      PRINT_DS_CHANNEL(pbody);
    */
    cbs->Handle80211MgmtBeacon(*this, pmh, &pbody);
    return 1;
}

int WifiPacket::handle_assoc_request( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_LISTENINT_LEN))
        return 0;
    pbody.capability_info = EXTRACT_LE_16BITS(p);
    offset += IEEE802_11_CAPINFO_LEN;
    pbody.listen_interval = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_LISTENINT_LEN;

    parse_elements(&pbody, p, offset, len);

    /*
      PRINT_SSID(pbody);
      PRINT_RATES(pbody);
    */
    cbs->Handle80211MgmtAssocRequest(*this, pmh, &pbody);

    return 1;
}

int WifiPacket::handle_assoc_response( const struct mgmt_header_t *pmh, const u_char *p, size_t len, bool reassoc)
{
    struct mgmt_body_t pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_STATUS_LEN +
                IEEE802_11_AID_LEN))
        return 0;
    pbody.capability_info = EXTRACT_LE_16BITS(p);
    offset += IEEE802_11_CAPINFO_LEN;
    pbody.status_code = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_STATUS_LEN;
    pbody.aid = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_AID_LEN;

    parse_elements(&pbody, p, offset, len);

    /*
      printf(" AID(%x) :%s: %s", ((u_int16_t)(pbody.aid << 2 )) >> 2 ,
      CAPABILITY_PRIVACY(pbody.capability_info) ? " PRIVACY " : "",
      (pbody.status_code < NUM_STATUSES
      ? status_text[pbody.status_code]
      : "n/a"));
    */
    if (!reassoc)
        cbs->Handle80211MgmtAssocResponse(*this, pmh, &pbody);
    else
        cbs->Handle80211MgmtReassocResponse(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_reassoc_request( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_LISTENINT_LEN +
                IEEE802_11_AP_LEN))
        return 0;
    pbody.capability_info = EXTRACT_LE_16BITS(p);
    offset += IEEE802_11_CAPINFO_LEN;
    pbody.listen_interval = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_LISTENINT_LEN;
    memcpy(&pbody.ap, p+offset, IEEE802_11_AP_LEN);
    offset += IEEE802_11_AP_LEN;

    parse_elements(&pbody, p, offset, len);

    /*
      PRINT_SSID(pbody);
      printf(" AP : %s", etheraddr_string( pbody.ap ));
    */
    cbs->Handle80211MgmtReassocRequest(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_reassoc_response( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    /* Same as a Association Reponse */
    return handle_assoc_response(pmh, p, len, true);
}

int
WifiPacket::handle_probe_request( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t  pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    parse_elements(&pbody, p, offset, len);

    /*
      PRINT_SSID(pbody);
      PRINT_RATES(pbody);
    */
    cbs->Handle80211MgmtProbeRequest(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_probe_response( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t  pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
                IEEE802_11_CAPINFO_LEN))
        return 0;

    memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
    offset += IEEE802_11_TSTAMP_LEN;
    pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_BCNINT_LEN;
    pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
    offset += IEEE802_11_CAPINFO_LEN;

    parse_elements(&pbody, p, offset, len);

    /*
      PRINT_SSID(pbody);
      PRINT_RATES(pbody);
      PRINT_DS_CHANNEL(pbody);
    */
    cbs->Handle80211MgmtProbeResponse(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_atim( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    /* the frame body for ATIM is null. */

    cbs->Handle80211MgmtATIM(*this, pmh);

    return 1;
}

int
WifiPacket::handle_disassoc( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t  pbody;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_REASON_LEN))
        return 0;
    pbody.reason_code = EXTRACT_LE_16BITS(p);

    /*
      printf(": %s",
      (pbody.reason_code < NUM_REASONS)
      ? reason_text[pbody.reason_code]
      : "Reserved" );
    */
    cbs->Handle80211MgmtDisassoc(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_auth( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t  pbody;
    int offset = 0;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, 6))
        return 0;
    pbody.auth_alg = EXTRACT_LE_16BITS(p);
    offset += 2;
    pbody.auth_trans_seq_num = EXTRACT_LE_16BITS(p + offset);
    offset += 2;
    pbody.status_code = EXTRACT_LE_16BITS(p + offset);
    offset += 2;

    parse_elements(&pbody, p, offset, len);

    /*
      if ((pbody.auth_alg == 1) &&
      ((pbody.auth_trans_seq_num == 2) ||
      (pbody.auth_trans_seq_num == 3))) {
      printf(" (%s)-%x [Challenge Text] %s",
      (pbody.auth_alg < NUM_AUTH_ALGS)
      ? auth_alg_text[pbody.auth_alg]
      : "Reserved",
      pbody.auth_trans_seq_num,
      ((pbody.auth_trans_seq_num % 2)
      ? ((pbody.status_code < NUM_STATUSES)
      ? status_text[pbody.status_code]
      : "n/a") : ""));
      return 1;
      }
      printf(" (%s)-%x: %s",
      (pbody.auth_alg < NUM_AUTH_ALGS)
      ? auth_alg_text[pbody.auth_alg]
      : "Reserved",
      pbody.auth_trans_seq_num,
      (pbody.auth_trans_seq_num % 2)
      ? ((pbody.status_code < NUM_STATUSES)
      ? status_text[pbody.status_code]
      : "n/a")
      : "");
    */
    cbs->Handle80211MgmtAuth(*this, pmh, &pbody);

    return 1;
}

int
WifiPacket::handle_deauth( const struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    struct mgmt_body_t  pbody;
    int offset = 0;
    //const char *reason = NULL;

    memset(&pbody, 0, sizeof(pbody));

    if (!TTEST2(*p, IEEE802_11_REASON_LEN))
        return 0;
    pbody.reason_code = EXTRACT_LE_16BITS(p);
    offset += IEEE802_11_REASON_LEN;

    /*
      reason = (pbody.reason_code < NUM_REASONS)
      ? reason_text[pbody.reason_code]
      : "Reserved";

      if (eflag) {
      printf(": %s", reason);
      } else {
      printf(" (%s): %s", etheraddr_string(pmh->sa), reason);
      }
    */
    cbs->Handle80211MgmtDeauth(*this, pmh, &pbody);

    return 1;
}


/*********************************************************************************
 * Print Body funcs
 *********************************************************************************/


/** Decode a management request.
 * @return 0 - failure, non-zero success
 *
 * NOTE — this function and all that it calls should be handled as methods in WifipcapCallbacks
 */
 
int
WifiPacket::decode_mgmt_body(u_int16_t fc, struct mgmt_header_t *pmh, const u_char *p, size_t len)
{
    if(debug) std::cerr << "decode_mgmt_body FC_SUBTYPE(fc)="<<(int)FC_SUBTYPE(fc)<<" ";
    switch (FC_SUBTYPE(fc)) {
    case ST_ASSOC_REQUEST:
        return handle_assoc_request(pmh, p, len);
    case ST_ASSOC_RESPONSE:
        return handle_assoc_response(pmh, p, len);
    case ST_REASSOC_REQUEST:
        return handle_reassoc_request(pmh, p, len);
    case ST_REASSOC_RESPONSE:
        return handle_reassoc_response(pmh, p, len);
    case ST_PROBE_REQUEST:
        return handle_probe_request(pmh, p, len);
    case ST_PROBE_RESPONSE:
        return handle_probe_response(pmh, p, len);
    case ST_BEACON:
        return handle_beacon(pmh, p, len);
    case ST_ATIM:
        return handle_atim(pmh, p, len);
    case ST_DISASSOC:
        return handle_disassoc(pmh, p, len);
    case ST_AUTH:
        if (len < 3) {
            return 0;
        }
        if ((p[0] == 0 ) && (p[1] == 0) && (p[2] == 0)) {
            //printf("Authentication (Shared-Key)-3 ");
            cbs->Handle80211MgmtAuthSharedKey(*this, pmh, p, len);
            return 0;
        }
        return handle_auth(pmh, p, len);
    case ST_DEAUTH:
        return handle_deauth(pmh, p, len);
        break;
    default:
        return 0;
    }
}

int WifiPacket::decode_mgmt_frame(const u_char * ptr, size_t len, u_int16_t fc, u_int8_t hdrlen)
{
    mgmt_header_t hdr;
    u_int16_t seq_ctl;

    hdr.da    = MAC::ether2MAC(ptr + 4);
    hdr.sa    = MAC::ether2MAC(ptr + 10);
    hdr.bssid = MAC::ether2MAC(ptr + 16);

    hdr.duration = EXTRACT_LE_16BITS(ptr+2);

    seq_ctl   = pletohs(ptr + 22);

    hdr.seq   = COOK_SEQUENCE_NUMBER(seq_ctl);
    hdr.frag  = COOK_FRAGMENT_NUMBER(seq_ctl);

    cbs->Handle80211(*this, fc, hdr.sa, hdr.da, MAC::null, MAC::null, ptr, len);

    int ret = decode_mgmt_body(fc, &hdr, ptr+MGMT_HDRLEN, len-MGMT_HDRLEN);

    if (ret==0) {
	cbs->Handle80211Unknown(*this, fc, ptr, len);
	return 0;
    }

    return 0;
}

int WifiPacket::decode_data_frame(const u_char * ptr, size_t len, u_int16_t fc)
{
    mac_hdr_t hdr;
    hdr.fc       = fc;
    hdr.duration = EXTRACT_LE_16BITS(ptr+2);
    hdr.seq_ctl  = pletohs(ptr + 22);
    hdr.seq      = COOK_SEQUENCE_NUMBER(hdr.seq_ctl);
    hdr.frag     = COOK_FRAGMENT_NUMBER(hdr.seq_ctl);

    if(FC_TYPE(fc)==2 && FC_SUBTYPE(fc)==8){ // quality of service?
        hdr.qos = 1;
    }
        
    size_t hdrlen=0;

    const MAC address1 = MAC::ether2MAC(ptr+4);
    const MAC address2 = MAC::ether2MAC(ptr+10);
    const MAC address3 = MAC::ether2MAC(ptr+16);
    
    /* call the 80211 callback data callback */

    if (FC_TO_DS(fc)==0 && FC_FROM_DS(fc)==0) {	/* ad hoc IBSS */
	hdr.da = address1;
	hdr.sa = address2;
	hdr.bssid = address3;
	hdrlen = DATA_HDRLEN;
        if(hdr.qos) hdrlen+=2;
        cbs->Handle80211( *this, fc, hdr.sa, hdr.da, hdr.ra, hdr.ta, ptr, len);
	cbs->Handle80211DataIBSS( *this, hdr, ptr+hdrlen, len-hdrlen);
    } else if (FC_TO_DS(fc)==0 && FC_FROM_DS(fc)) { /* from AP to STA */
        hdr.da = address1;
        hdr.bssid = address2;
        hdr.sa = address3;
	hdrlen = DATA_HDRLEN;
        if(hdr.qos) hdrlen+=2;
        cbs->Handle80211( *this, fc, hdr.sa, hdr.da, hdr.ra, hdr.ta, ptr, len);
	cbs->Handle80211DataFromAP( *this, hdr, ptr+hdrlen, len-hdrlen);
    } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)==0) {	/* frame from STA to AP */
        hdr.bssid = address1;
        hdr.sa = address2;
        hdr.da = address3;
	hdrlen = DATA_HDRLEN;
        if(hdr.qos) hdrlen+=2;
        cbs->Handle80211( *this, fc, hdr.sa, hdr.da, hdr.ra, hdr.ta, ptr, len);
	cbs->Handle80211DataToAP( *this, hdr, ptr+hdrlen, len-hdrlen);
    } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {	/* WDS */
        const MAC address4 = MAC::ether2MAC(ptr+18);
        hdr.ra = address1;
        hdr.ta = address2;
        hdr.da = address3;
        hdr.sa = address4;
        hdrlen = DATA_WDS_HDRLEN;
        if(hdr.qos) hdrlen+=2;
        cbs->Handle80211( *this, fc, hdr.sa, hdr.da, hdr.ra, hdr.ta, ptr, len);
	cbs->Handle80211DataWDS( *this, hdr, ptr+hdrlen, len-hdrlen);
    }

    /* Handle either the WEP or the link layer. This handles the data itself */
    if (FC_WEP(fc)) {
        handle_wep(ptr+hdrlen, len-hdrlen-4 ); 
    } else {
        handle_llc(hdr, ptr+hdrlen, len-hdrlen-4, fc); 
    }
    return 0;
}

int WifiPacket::decode_ctrl_frame(const u_char * ptr, size_t len, u_int16_t fc)
{
    u_int16_t du = EXTRACT_LE_16BITS(ptr+2);        //duration

    switch (FC_SUBTYPE(fc)) {
    case CTRL_PS_POLL: {
	ctrl_ps_poll_t hdr;
	hdr.fc = fc;
	hdr.aid = du;
	hdr.bssid =  MAC::ether2MAC(ptr+4);
	hdr.ta =  MAC::ether2MAC(ptr+10);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, MAC::null, hdr.ta, ptr, len);
	cbs->Handle80211CtrlPSPoll( *this, &hdr);
	break;
    }
    case CTRL_RTS: {
	ctrl_rts_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra =  MAC::ether2MAC(ptr+4);
	hdr.ta =  MAC::ether2MAC(ptr+10);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, hdr.ra, hdr.ta, ptr, len);
	cbs->Handle80211CtrlRTS( *this, &hdr);
	break;
    }
    case CTRL_CTS: {
	ctrl_cts_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra =  MAC::ether2MAC(ptr+4);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len);
	cbs->Handle80211CtrlCTS( *this, &hdr);
	break;
    }
    case CTRL_ACK: {
	ctrl_ack_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra =  MAC::ether2MAC(ptr+4);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len);
	cbs->Handle80211CtrlAck( *this, &hdr);
	break;
    }
    case CTRL_CF_END: {
	ctrl_end_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra =  MAC::ether2MAC(ptr+4);
	hdr.bssid =  MAC::ether2MAC(ptr+10);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len);
	cbs->Handle80211CtrlCFEnd( *this, &hdr);
	break;
    }
    case CTRL_END_ACK: {	
	ctrl_end_ack_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra =  MAC::ether2MAC(ptr+4);
	hdr.bssid =  MAC::ether2MAC(ptr+10);
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len);
	cbs->Handle80211CtrlEndAck( *this, &hdr);
	break;
    }
    default: {
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, MAC::null, MAC::null, ptr, len);
	cbs->Handle80211Unknown( *this, fc, ptr, len);
	return -1;
	//add the case statements for QoS control frames once ieee802_11.h is updated
    }
    }
    return 0;
}

#ifndef roundup2
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

void WifiPacket::handle_80211(const u_char * pkt, size_t len /* , int pad */)  
{
    if (debug) std::cerr << "handle_80211(len= " << len << " ";
    if (len < 2) {
	cbs->Handle80211( *this, 0, MAC::null, MAC::null, MAC::null, MAC::null, pkt, len);
	cbs->Handle80211Unknown( *this, -1, pkt, len);
	return;
    }

    u_int16_t fc  = EXTRACT_LE_16BITS(pkt);       //frame control
    size_t hdrlen = extract_header_length(fc);
    /*
      if (pad) {
      hdrlen = roundup2(hdrlen, 4);
      }
    */

    if (debug) std::cerr << "FC_TYPE(fc)= " << FC_TYPE(fc) << " ";

    if (len < IEEE802_11_FC_LEN || len < hdrlen) {
	cbs->Handle80211Unknown( *this, fc, pkt, len);
	return;
    }

    /* Always calculate the frame checksum, but only process the packets if the FCS or if we are ignoring it */
    if (len >= hdrlen + 4) {
        // assume fcs is last 4 bytes (?)
        u_int32_t fcs_sent = EXTRACT_32BITS(pkt+len-4);
        u_int32_t fcs = crc32_802(pkt, len-4);
        
        /*
          if (fcs != fcs_sent) {
          cerr << "bad fcs: ";
          fprintf (stderr, "%08x != %08x\n", fcs_sent, fcs); 
          }
        */
	
        fcs_ok = (fcs == fcs_sent);
    }
    if (cbs->Check80211FCS(*this) && fcs_ok==false){
        cbs->Handle80211Unknown(*this,fc,pkt,len);
        return;
    }


    // fill in current_frame: type, sn
    switch (FC_TYPE(fc)) {
    case T_MGMT:
	if(decode_mgmt_frame(pkt, len, fc, hdrlen)<0)
	    return;
	break;
    case T_DATA:
	if(decode_data_frame(pkt, len, fc)<0)
	    return;
	break;
    case T_CTRL:
	if(decode_ctrl_frame(pkt, len, fc)<0)
	    return;
	break;
    default:
	cbs->Handle80211( *this, fc, MAC::null, MAC::null, MAC::null, MAC::null, pkt, len);
	cbs->Handle80211Unknown( *this, fc, pkt, len);
	return;
    }
}

int WifiPacket::print_radiotap_field(struct cpack_state *s, u_int32_t bit, int *pad, radiotap_hdr *hdr)
{
    union {
        int8_t		i8;
        u_int8_t	u8;
        int16_t		i16;
        u_int16_t	u16;
        u_int32_t	u32;
        u_int64_t	u64;
    } u, u2, u3;
    int rc;

    switch (bit) {
    case IEEE80211_RADIOTAP_FLAGS:
        rc = cpack_uint8(s, &u.u8);
        if (u.u8 & IEEE80211_RADIOTAP_F_DATAPAD)
            *pad = 1;
        break;
    case IEEE80211_RADIOTAP_RATE:
    case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
    case IEEE80211_RADIOTAP_DB_ANTNOISE:
    case IEEE80211_RADIOTAP_ANTENNA:
        rc = cpack_uint8(s, &u.u8);
        break;
    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        rc = cpack_int8(s, &u.i8);
        break;
    case IEEE80211_RADIOTAP_CHANNEL:
        rc = cpack_uint16(s, &u.u16);
        if (rc != 0)
            break;
        rc = cpack_uint16(s, &u2.u16);
        break;
    case IEEE80211_RADIOTAP_FHSS:
    case IEEE80211_RADIOTAP_LOCK_QUALITY:
    case IEEE80211_RADIOTAP_TX_ATTENUATION:
        rc = cpack_uint16(s, &u.u16);
        break;
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        rc = cpack_uint8(s, &u.u8);
        break;
    case IEEE80211_RADIOTAP_DBM_TX_POWER:
        rc = cpack_int8(s, &u.i8);
        break;
    case IEEE80211_RADIOTAP_TSFT:
        rc = cpack_uint64(s, &u.u64);
        break;
    case IEEE80211_RADIOTAP_RX_FLAGS:
        rc = cpack_uint16(s, &u.u16);
        break;
    case IEEE80211_RADIOTAP_TX_FLAGS:
        rc = cpack_uint16(s, &u.u16);
        break;
    case IEEE80211_RADIOTAP_RTS_RETRIES:
        rc = cpack_uint8(s, &u.u8);
        break;
    case IEEE80211_RADIOTAP_DATA_RETRIES:
        rc = cpack_uint8(s, &u.u8);
        break;
        // simson add follows:
    case IEEE80211_RADIOTAP_XCHANNEL:
        rc = cpack_uint8(s, &u.u8);      // simson guess
        break;
    case IEEE80211_RADIOTAP_MCS:
        rc = cpack_uint8(s, &u.u8) || cpack_uint8(s, &u2.u8) || cpack_uint8(s, &u3.u8);      // simson guess
        break;
        // simson end
    default:
        /* this bit indicates a field whose
         * size we do not know, so we cannot
         * proceed.
         */
        //printf("[0x%08x] ", bit);
        fprintf(stderr, "wifipcap: unknown radiotap bit: %d (%d)\n", bit,IEEE80211_RADIOTAP_XCHANNEL);
        return  -1 ;
    }

    if (rc != 0) {
        //printf("[|802.11]");
        fprintf(stderr, "wifipcap: truncated radiotap header for bit: %d\n", bit);
        return  rc ;
    }

    switch (bit) {
    case IEEE80211_RADIOTAP_CHANNEL:
        //printf("%u MHz ", u.u16);
        if (u2.u16 != 0)
            //printf("(0x%04x) ", u2.u16);
            hdr->has_channel = true;
        hdr->channel = u2.u16;
        break;
    case IEEE80211_RADIOTAP_FHSS:
        //printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
        hdr->has_fhss = true;
        hdr->fhss_fhset = u.u16 & 0xff;
        hdr->fhss_fhpat = (u.u16 >> 8) & 0xff;
        break;
    case IEEE80211_RADIOTAP_RATE:
        //PRINT_RATE("", u.u8, " Mb/s ");
        hdr->has_rate = true;
        hdr->rate = u.u8;
        break;
    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        //printf("%ddB signal ", u.i8);
        hdr->has_signal_dbm = true;
        hdr->signal_dbm = u.i8;
        break;
    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        //printf("%ddB noise ", u.i8);
        hdr->has_noise_dbm = true;
        hdr->noise_dbm = u.i8;
        break;
    case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        //printf("%ddB signal ", u.u8);
        hdr->has_signal_db = true;
        hdr->signal_db = u.u8;
        break;
    case IEEE80211_RADIOTAP_DB_ANTNOISE:
        //printf("%ddB noise ", u.u8);
        hdr->has_noise_db = true;
        hdr->noise_db = u.u8;
        break;
    case IEEE80211_RADIOTAP_LOCK_QUALITY:
        //printf("%u sq ", u.u16);
        hdr->has_quality = true;
        hdr->quality = u.u16;
        break;
    case IEEE80211_RADIOTAP_TX_ATTENUATION:
        //printf("%d tx power ", -(int)u.u16);
        hdr->has_txattenuation = true;
        hdr->txattenuation = -(int)u.u16;
        break;
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        //printf("%ddB tx power ", -(int)u.u8);
        hdr->has_txattenuation_db = true;
        hdr->txattenuation_db = -(int)u.u8;
        break;
    case IEEE80211_RADIOTAP_DBM_TX_POWER:
        //printf("%ddBm tx power ", u.i8);
        hdr->has_txpower_dbm = true;
        hdr->txpower_dbm = u.i8;
        break;
    case IEEE80211_RADIOTAP_FLAGS:
        hdr->has_flags = true;
        if (u.u8 & IEEE80211_RADIOTAP_F_CFP)
            //printf("cfp ");
            hdr->flags_cfp = true;
        if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
            //printf("short preamble ");
            hdr->flags_short_preamble = true;
        if (u.u8 & IEEE80211_RADIOTAP_F_WEP)
            //printf("wep ");
            hdr->flags_wep = true;
        if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
            //printf("fragmented ");
            hdr->flags_fragmented = true;
        if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS)
            //printf("bad-fcs ");
            hdr->flags_badfcs = true;
        break;
    case IEEE80211_RADIOTAP_ANTENNA:
        //printf("antenna %d ", u.u8);
        hdr->has_antenna = true;
        hdr->antenna = u.u8;
        break;
    case IEEE80211_RADIOTAP_TSFT:
        //printf("%" PRIu64 "us tsft ", u.u64);
        hdr->has_tsft = true;
        hdr->tsft = u.u64;
        break;
    case IEEE80211_RADIOTAP_RX_FLAGS:
        hdr->has_rxflags = true;
        hdr->rxflags = u.u16;
        break;
    case IEEE80211_RADIOTAP_TX_FLAGS:
        hdr->has_txflags = true;
        hdr->txflags = u.u16;
        break;
    case IEEE80211_RADIOTAP_RTS_RETRIES:
        hdr->has_rts_retries = true;
        hdr->rts_retries = u.u8;
        break;
    case IEEE80211_RADIOTAP_DATA_RETRIES:
        hdr->has_data_retries = true;
        hdr->data_retries = u.u8;
        break;
    }
    return  0 ;
}



void WifiPacket::handle_radiotap(const u_char *p,size_t caplen)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
#define	BIT(n)	(1 << n)
#define	IS_EXTENDED(__p) (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

    // If caplen is too small, just give it a try and carry on.
    if (caplen < sizeof(struct ieee80211_radiotap_header)) {
        cbs->HandleRadiotap( *this, NULL, p, caplen);
        return;
    }

    struct ieee80211_radiotap_header *hdr = (struct ieee80211_radiotap_header *)p;

    size_t len = EXTRACT_LE_16BITS(&hdr->it_len); // length of radiotap header

    if (caplen < len) {
        //printf("[|802.11]");
        cbs->HandleRadiotap( *this, NULL, p, caplen);
        return;// caplen;
    }
    uint32_t *last_presentp=0;
    for (last_presentp = &hdr->it_present;
         IS_EXTENDED(last_presentp) && (u_char*)(last_presentp + 1) <= p + len;
         last_presentp++){
    }

    /* are there more bitmap extensions than bytes in header? */
    if (IS_EXTENDED(last_presentp)) {
        //printf("[|802.11]");
        cbs->HandleRadiotap( *this, NULL, p, caplen);
        return;// caplen;
    }

    const u_char *iter = (u_char*)(last_presentp + 1);
    struct cpack_state cpacker;


    /* Handle malformed data */
    if ((ssize_t)(len - (iter - p)) <= 0) {
        cbs->HandleRadiotap( *this, NULL, p, caplen);
        return;// caplen;
    }

    if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
        /* XXX */
        //printf("[|802.11]");
        cbs->HandleRadiotap( *this, NULL, p, caplen);
        return;// caplen;
    }

    radiotap_hdr ohdr;
    memset(&ohdr, 0, sizeof(ohdr));
	
    /* Assume no Atheros padding between 802.11 header and body */
    int pad = 0;
    uint32_t *presentp;
    int bit0=0;
    for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
         presentp++, bit0 += 32) {

        u_int32_t present, next_present;
        for (present = EXTRACT_LE_32BITS(presentp); present;
             present = next_present) {
            /* clear the least significant bit that is set */
            next_present = present & (present - 1);

            /* extract the least significant bit that is set */
            enum ieee80211_radiotap_type bit = (enum ieee80211_radiotap_type)
                (bit0 + BITNO_32(present ^ next_present));

            /* print the next radiotap field */
            int r = print_radiotap_field(&cpacker, bit, &pad, &ohdr);

            /* If we got an error, break both loops */
            if(r!=0) goto done;
        }
    }
done:;
    cbs->HandleRadiotap( *this, &ohdr, p, caplen);
    //return len + ieee802_11_print(p + len, length - len, caplen - len, pad);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
    handle_80211(p+len, caplen-len);
}

void WifiPacket::handle_prism(const u_char *pc, size_t len)
{
    prism2_pkthdr hdr;

    /* get the fields */
    if (len>=144){
        hdr.host_time 	= EXTRACT_LE_32BITS(pc+32);
        hdr.mac_time 	= EXTRACT_LE_32BITS(pc+44);
        hdr.channel 	= EXTRACT_LE_32BITS(pc+56);
        hdr.rssi 		= EXTRACT_LE_32BITS(pc+68);
        hdr.sq 		= EXTRACT_LE_32BITS(pc+80);
        hdr.signal  	= EXTRACT_LE_32BITS(pc+92);
        hdr.noise   	= EXTRACT_LE_32BITS(pc+104);
        hdr.rate		= EXTRACT_LE_32BITS(pc+116)/2;
        hdr.istx		= EXTRACT_LE_32BITS(pc+128);
        cbs->HandlePrism( *this, &hdr, pc + 144, len - 144);
        handle_80211(pc+144,len-144);
    }
}

///////////////////////////////////////////////////////////////////////////////
///
/// handle_*:
/// handle each of the packet types
///

/// 2018-08-02: slg - I'm not sure why this is commented out.
void WifiPacket::handle_ether(const u_char *ptr, size_t len)
{
#if 0
    ether_hdr_t hdr;

    hdr.da = MAC::ether2MAC(ptr);
    hdr.sa = MAC::ether2MAC(ptr+6);
    hdr.type = EXTRACT_16BITS(ptr + 12);

    ptr += 14;
    len -= 14;

    cbs->HandleEthernet(*this, &hdr, ptr, len);

    switch (hdr.type) {
    case ETHERTYPE_IP:
	handle_ip(ptr, len);
	return;
    case ETHERTYPE_IPV6:
	handle_ip6(ptr, len);
	return;
    case ETHERTYPE_ARP:
	handle_arp( ptr, len);
	return;
    default:
	cbs->HandleL2Unknown(*this, hdr.type, ptr, len);
	return;
    }
#endif
}

///////////////////////////////////////////////////////////////////////////////
/* These are all static functions */
#if 0
void Wifipcap::dl_prism(const PcapUserData &data, const struct pcap_pkthdr *header, const u_char * packet)
{
    WifipcapCallbacks *cbs = data.cbs;

    if(header->caplen < 144) return;    // prism header

    cbs->PacketBegin( packet, header->caplen, header->len);
    handle_prism(cbs,packet+144,header->caplen-144);
    cbs->PacketEnd();
}

void Wifipcap::dl_prism(u_char *user, const struct pcap_pkthdr *header, const u_char * packet)
{
    PcapUserData *data = reinterpret_cast<PcapUserData *>(user);
    Wifipcap::dl_prism(*data,header,packet);
}
#endif

#if 0
void Wifipcap::dl_ieee802_11_radio(const PcapUserData &data, const struct pcap_pkthdr *header,
                                   const u_char * packet)
{

    data.cbs->PacketBegin( packet, header->caplen, header->len);
    handle_radiotap(packet, header->caplen);
    data.cbs->PacketEnd();
}
#endif

void Wifipcap::dl_ieee802_11_radio(const u_char *user, const struct pcap_pkthdr *header, const u_char * packet)
{
    const PcapUserData *data = reinterpret_cast<const PcapUserData *>(user);
    WifiPacket pkt(data->cbs,data->header_type,header,packet);

    data->cbs->PacketBegin(pkt,packet,header->caplen,header->len);
    pkt.handle_radiotap(packet,header->caplen);
    data->cbs->PacketEnd(pkt);

    //Wifipcap::dl_ieee802_11_radio(*data,header,packet);
}

///////////////////////////////////////////////////////////////////////////////

/* None of these are used in tcpflow */

bool Wifipcap::InitNext()
{
    if (morefiles.size() < 1){
	return false;
    }
    if (descr) {
        pcap_close(descr);
    }
    Init(morefiles.front(), false);
    morefiles.pop_front();
    return true;
}

void Wifipcap::Init(const char *name, bool live) {
    if (verbose){
        std::cerr << "wifipcap: initializing '" << name << "'" << std::endl;
    }

    if (!live) {
#ifdef _WIN32
	std::cerr << "Trace replay is unsupported in windows." << std::endl;
	exit(1);
#else
	// mini hack: handle gziped files since all our traces are in
	// this format
	int slen = strlen(name);

	bool gzip = !strcmp(name+slen-3, ".gz");
	bool bzip = !strcmp(name+slen-4, ".bz2");
	
	char cmd[256];
	char errbuf[256];
	if (gzip) 
	    sprintf(cmd, "zcat %s", name);
	else if (bzip)
	    sprintf(cmd, "bzcat %s", name);
	else
	    // using cat here instead of pcap_open or fopen is intentional
	    // neither of these may be able to handle large files (>2GB files)
	    // but cat uses the linux routines to allow it to
	    sprintf(cmd, "cat %s", name);

	FILE *pipe = popen(cmd, "r");
	if (pipe == NULL) {
	    printf("popen(): %s\n", strerror(errno));
	    exit(1);
	}
	descr = pcap_fopen_offline(pipe, errbuf);

        if(descr == NULL) {
            printf("pcap_open_offline(): %s\n", errbuf);
            exit(1);
        }
#endif
    } else {
	char errbuf[256];
	descr = pcap_open_live(name,BUFSIZ,1,-1,errbuf);
        if(descr == NULL) {
            printf("pcap_open_live(): %s\n", errbuf);
            exit(1);
        }
    }

    datalink = pcap_datalink(descr);
    if (datalink != DLT_PRISM_HEADER && datalink != DLT_IEEE802_11_RADIO && datalink != DLT_IEEE802_11) {
	if (datalink == DLT_EN10MB) {
	    printf("warning: ethernet datalink type: %s\n",
		   pcap_datalink_val_to_name(datalink));
	} else {
	    printf("warning: unrecognized datalink type: %s\n",
		   pcap_datalink_val_to_name(datalink));
	}
    }
}




/* object-oriented version of pcap callback. Called with the callbacks object,
 * the DLT type, the header and the packet.
 * This is the main packet processor.
 * It records some stats and then dispatches to the appropriate callback.
 */
void Wifipcap::handle_packet(WifipcapCallbacks *cbs,int header_type,
                             const struct pcap_pkthdr *header, const u_char * packet) 
{
    /* Record start time if we don't have it */
    if (startTime == TIME_NONE) {
	startTime = header->ts;
	lastPrintTime = header->ts;
    }
    /* Print stats if necessary */
    if (header->ts.tv_sec > lastPrintTime.tv_sec + Wifipcap::PRINT_TIME_INTERVAL) {
	if (verbose) {
	    int hours = (header->ts.tv_sec - startTime.tv_sec)/3600;
	    int days  = hours/24;
	    int left  = hours%24;
	    fprintf(stderr, "wifipcap: %2d days %2d hours, %10" PRId64 " pkts\n", 
		    days, left, packetsProcessed);
	}
	lastPrintTime = header->ts;
    }
    packetsProcessed++;

    /* Create the packet object and call the appropriate callbacks */
    WifiPacket pkt(cbs,header_type,header,packet);

    /* Notify callback */
    cbs->PacketBegin(pkt, packet, header->caplen, header->len);
    //int frameLen = header->caplen;
    switch(header_type) {
    case DLT_PRISM_HEADER:
        pkt.handle_prism(packet,header->caplen);
        break;
    case DLT_IEEE802_11_RADIO:
        pkt.handle_radiotap(packet,header->caplen);
        break;
    case DLT_IEEE802_11:
        pkt.handle_80211(packet,header->caplen);
        break;
    case DLT_EN10MB:
        pkt.handle_ether(packet,header->caplen);
        break;
    default:
#if 0
        /// 2018-08-02: slg - I'm also not sure why this is commented out.
	// try handling it as default IP assuming framing is ethernet 
	// (this is for testing)
        pkt.handle_ip(packet,header->caplen);
#endif
        break;
    }
    cbs->PacketEnd(pkt);
}


/* The raw callback from pcap; jump back into the object-oriented domain */
/* note: u_char *user may not be const according to spec */
void Wifipcap::handle_packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char * packet)
{
    Wifipcap::PcapUserData *data = reinterpret_cast<Wifipcap::PcapUserData *>(user);
    data->wcap->handle_packet(data->cbs,data->header_type,header,packet);
}
    

const char *Wifipcap::SetFilter(const char *filter)
{
    struct bpf_program fp;
#ifdef PCAP_NETMASK_UNKNOWN
    bpf_u_int32 netp=PCAP_NETMASK_UNKNOWN;
#else
    bpf_u_int32 netp=0;
#endif


    if(pcap_compile(descr,&fp,(char *)filter,0,netp) == -1) { 
	return "Error calling pcap_compile"; 
    }
    
    if(pcap_setfilter(descr,&fp) == -1) { 
	return "Error setting filter"; 
    }

    return NULL;
}


void Wifipcap::Run(WifipcapCallbacks *cbs, int maxpkts)
{
    /* NOTE: This needs to be fixed so that the correct handle_packet is called  */

    packetsProcessed = 0;
    
    do {
	PcapUserData data(this,cbs,DLT_IEEE802_11_RADIO);
	pcap_loop(descr, maxpkts > 0 ? maxpkts - packetsProcessed : 0,
		  Wifipcap::handle_packet_callback, reinterpret_cast<u_char *>(&data));
    } while ( InitNext() );
}


///////////////////////////////////////////////////////////////////////////////


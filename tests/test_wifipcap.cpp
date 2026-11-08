// Exercise radiotap bitmap decoding at its actual packet-buffer boundary.
// The production decoder receives complete and truncated extension headers.
// A callback records whether metadata was accepted or rejected explicitly.
// Unknown bitmap fields must not require an out-of-range enum conversion.
// Native sanitizer builds detect reads beyond these exact-size vectors.
#include "config.h"
#include "wifipcap.h"
#include <iostream>
#include <vector>

struct Callbacks : WifipcapCallbacks {
    unsigned accepted = 0, rejected = 0;
    bool bounded_payload = true;
    void HandleLLC(const WifiPacket &packet, const llc_hdr_t *, const u_char *rest, size_t len) override
    {
        const size_t offset = static_cast<size_t>(rest - packet.packet);
        bounded_payload = offset <= packet.header->caplen && len <= packet.header->caplen - offset;
    }
    void HandleRadiotap(const WifiPacket &, radiotap_hdr *header, const u_char *, size_t) override
    {
        if (header) ++accepted;
        else ++rejected;
    }
};

static bool check(const std::vector<u_char> &data, bool accepted)
{
    Callbacks callbacks;
    pcap_pkthdr header = {};
    header.caplen = header.len = static_cast<uint32_t>(data.size());
    WifiPacket packet(&callbacks, DLT_IEEE802_11_RADIO, &header, data.data());
    packet.handle_radiotap(data.data(), data.size());
    return callbacks.accepted == (accepted ? 1U : 0U) && callbacks.rejected == (accepted ? 0U : 1U);
}

int main()
{
    bool valid = check({0, 0, 8, 0, 0, 0, 0, 128}, false); // extension bit, no extension bytes
    valid = check({0, 0, 12, 0, 0, 0, 0, 128, 0, 0, 0, 128}, false) && valid;
    valid = check({0, 0, 7, 0, 0, 0, 0, 0}, false) && valid;
    valid = check({0, 0, 9, 0, 2, 0, 0, 0, 0}, true) && valid; // flags byte
    valid = check({0, 0, 9, 0, 0, 0, 32, 0, 0}, true) && valid; // unknown field 21
    // Cover truncated data, QoS, WDS and seven-byte LLC bodies with FCS
    // checking disabled, so the actual parser boundary is exercised directly.
    for (unsigned fc : {0x08U, 0x88U, 0x308U, 0x388U}) {
        for (size_t size = 2; size < 80; ++size) {
            std::vector<u_char> data(size, 0);
            data[0] = fc & 255; data[1] = fc >> 8;
            Callbacks callbacks;
            pcap_pkthdr header = {};
            header.caplen = header.len = static_cast<uint32_t>(size);
            WifiPacket packet(&callbacks, DLT_IEEE802_11, &header, data.data());
            packet.handle_80211(data.data(), data.size());
            valid = callbacks.bounded_payload && valid;
        }
    }
    if (!valid) std::cerr << "Radiotap header boundary handling failed\n";
    return valid ? 0 : 1;
}

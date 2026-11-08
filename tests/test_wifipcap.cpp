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
    if (!valid) std::cerr << "Radiotap header boundary handling failed\n";
    return valid ? 0 : 1;
}

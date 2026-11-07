// Validate the offline PCAP reader used by the standalone Windows release.
// Real temporary streams contain native and swapped classic-PCAP records.
// Valid data must reach the callback unchanged; invalid lengths must fail.
// Truncated headers/data and excessive allocations are rejected explicitly.
// The same reader runs under native sanitizers without a libpcap dependency.
#include "config.h"
#include "pcap_fake.h"
#include <cstring>
#include <iostream>
#include <vector>

static void word(std::vector<uint8_t> &out, uint32_t value, unsigned bytes, bool swapped)
{
    for (unsigned i = 0; i < bytes; ++i)
        out.push_back(static_cast<uint8_t>(value >> ((swapped ? bytes - i - 1 : i) * 8)));
}

static std::vector<uint8_t> capture(uint32_t snaplen, uint32_t caplen, uint32_t length, bool swapped)
{
    std::vector<uint8_t> data;
    word(data, 0xa1b2c3d4, 4, swapped);
    word(data, 2, 2, swapped); word(data, 4, 2, swapped);
    for (unsigned i = 0; i < 2; ++i) word(data, 0, 4, swapped);
    word(data, snaplen, 4, swapped); word(data, 1, 4, swapped);
    word(data, 1, 4, swapped); word(data, 2, 4, swapped);
    word(data, caplen, 4, swapped); word(data, length, 4, swapped);
    data.insert(data.end(), {1, 2, 3, 4});
    return data;
}

static void packet(uint8_t *user, const pcap_pkthdr *header, const uint8_t *data)
{
    const uint8_t expected[] = {1, 2, 3, 4};
    bool valid = header->caplen == 4 && header->len == 4 && header->ts.tv_sec == 1 && header->ts.tv_usec == 2;
    if (valid && std::memcmp(data, expected, 4) == 0) ++*user;
}

static bool check(const std::vector<uint8_t> &data, int expected, bool opens = true)
{
    FILE *file = tmpfile();
    if (!file) return false;
    bool valid = fwrite(data.data(), 1, data.size(), file) == data.size();
    rewind(file);
    char error[PCAP_ERRBUF_SIZE] = {};
    pcap_t *reader = pcap_fopen_offline(file, error);
    if (reader) {
        bpf_program filter = {};
        valid = pcap_compile(reader, &filter, "", 0, 0) == 0 && valid;
        valid = pcap_setfilter(reader, &filter) == 0 && valid;
        pcap_freecode(&filter);
        uint8_t packets = 0;
        int result = pcap_loop(reader, -1, packet, &packets);
        valid = valid && opens && result == expected;
        valid = valid && (expected == 0 ? packets == 1 : packets == 0 && std::strlen(pcap_geterr(reader)) > 0);
        pcap_close(reader);
    } else valid = valid && !opens && std::strlen(error) > 0;
    fclose(file);
    return valid;
}

int main()
{
    bool valid = true;
    for (bool swapped : {false, true}) {
        valid = check(capture(64, 4, 4, swapped), 0) && valid;
        valid = check(capture(4, 8, 8, swapped), -1) && valid;
        valid = check(capture(64, 4, 2, swapped), -1) && valid;
        valid = check(capture(0, 4, 4, swapped), -1, false) && valid;
        valid = check(capture(0xffffffff, 4, 4, swapped), -1, false) && valid;
        auto truncated = capture(64, 4, 4, swapped);
        truncated.resize(42);
        valid = check(truncated, -1) && valid;
        truncated.resize(30);
        valid = check(truncated, -1) && valid;
        truncated.resize(12);
        valid = check(truncated, -1, false) && valid;
    }
    if (!valid) std::cerr << "Offline PCAP reader accepted invalid data or changed valid data\n";
    return valid ? 0 : 1;
}

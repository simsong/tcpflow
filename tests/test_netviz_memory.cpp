// Exercise ownership of the PDF report's trees and time-histogram buckets.
// Real packet counters must survive replacing a condensed histogram.
// Repeated condensation covers moving populated bucket maps between owners.
// Address-tree sums also verify that independent entries remain intact.
// Scope exit releases both structures; ASan checks their allocation lifetimes.
// The normal Makefile test suite runs this under native and sanitizer builds.
#include "config.h"
#include "netviz/time_histogram.h"
#include "iptree.h"

static uint64_t total(const time_histogram &histogram)
{
    uint64_t sum = 0;
    for (auto it = histogram.begin(); it != histogram.end(); ++it) sum += it->second->sum();
    return sum;
}

int main()
{
    for (unsigned run = 0; run < 3; ++run) {
        iptreet<uint64_t, 16> tree(1000);
        uint8_t address[] = {127, 0, 0, 1};
        tree.add(address, sizeof(address), 2);
        ++address[3];
        tree.add(address, sizeof(address), 1);
        if (tree.sum() != 3) return 1;

        time_histogram histogram;
        for (int i = 0; i < 100; ++i) {
            timeval timestamp = {1700000000 + i, 0};
            histogram.insert(timestamp, 80, 2);
            histogram.insert(timestamp, 0, 1, time_histogram::F_NON_TCP);
        }
        if (total(histogram) != 300) return 1;
        histogram.condense(2);
        if (total(histogram) != 300) return 1;
        histogram.condense(3);
        if (total(histogram) != 300) return 1;
    }
}

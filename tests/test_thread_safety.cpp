// Exercise the shared be13 atomic containers with contending real threads.
// Workers increment shared and private histogram keys under the library lock.
// Each worker also races to insert identical set keys exactly once.
// Totals and unique insert counts detect lost writes and incorrect locking.
// This regression runs in ordinary builds and with ThreadSanitizer enabled.
#include "config.h"
#include <atomic>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>
#include "atomic_set_map.h"

int main()
{
    constexpr unsigned workers = 8, iterations = 2000;
    atomic_histogram<unsigned, uint64_t> histogram;
    atomic_set<unsigned> seen;
    std::atomic<unsigned> inserted{0};
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            for (unsigned i = 0; i < iterations; ++i) {
                histogram.add(0, 1);
                histogram.add(worker + 1, 1);
                if (!seen.check_for_presence_and_insert(i)) ++inserted;
            }
        });
    }
    for (auto &thread : threads) thread.join();
    bool valid = inserted == iterations;
    valid = valid && histogram.add(0, 0) == workers * iterations;
    for (unsigned worker = 0; worker < workers; ++worker)
        valid = valid && histogram.add(worker + 1, 0) == iterations;
    for (unsigned i = 0; i < iterations; ++i) valid = valid && seen.contains(i);
    if (!valid) std::cerr << "Concurrent histogram/set operations lost updates\n";
    return valid ? 0 : 1;
}

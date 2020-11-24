/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef SBUF_STREAM_H
#define SBUF_STREAM_H

/* required per C++ standard */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

using namespace std;

#include <stdlib.h>
#include <inttypes.h>
#include <string>
#include <sstream>
#include "sbuf.h"

/** \addtogroup bulk_extractor_APIs
 * @{
 */

/** \file */
/**
 * sbuf_stream provides the get services of sbuf_t but wrapped in a Stream interface.
 * Note that sbuf_stream is not particularly optimized; it is simply a wrapper.
 */
class sbuf_stream {
private:
    const sbuf_t sbuf;
    size_t offset;
public:
    sbuf_stream(const sbuf_t &sbuf_);
    ~sbuf_stream();
    void seek(size_t offset);
    size_t tell();

    /**
     * \name integer-based stream readers
     * @{ */
    uint8_t get8u();
    uint16_t get16u();
    uint32_t get32u();
    uint64_t get64u();

    uint8_t get8uBE();
    uint16_t get16uBE();
    uint32_t get32uBE();
    uint64_t get64uBE();

    uint8_t get8u(sbuf_t::byte_order_t bo);
    uint16_t get16u(sbuf_t::byte_order_t bo);
    uint32_t get32u(sbuf_t::byte_order_t bo);
    uint64_t get64u(sbuf_t::byte_order_t bo);

    int8_t get8i();
    int16_t get16i();
    int32_t get32i();
    int64_t get64i();

    int8_t get8iBE();
    int16_t get16iBE();
    int32_t get32iBE();
    int64_t get64iBE();

    int8_t get8i(sbuf_t::byte_order_t bo);
    int16_t get16i(sbuf_t::byte_order_t bo);
    int32_t get32i(sbuf_t::byte_order_t bo);
    int64_t get64i(sbuf_t::byte_order_t bo);
    /** @} */

    /**
     * \name string and wstring stream readers
     * @{ */
    void getUTF8(string &utf8_string);
    void getUTF8(size_t num_octets_requested, string &utf8_string);
    void getUTF16(wstring &utf16_string);
    void getUTF16(size_t num_code_units_requested, wstring &utf16_string);
    /** @} */
};

#endif

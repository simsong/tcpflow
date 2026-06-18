#ifndef SCAN_TLS_H
#define SCAN_TLS_H

#include <cstdint>
#include <string>
#include <vector>

// TLS content type
static const uint8_t TLS_CONTENT_HANDSHAKE = 0x16;

// Handshake message types
static const uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 1;
static const uint8_t TLS_HANDSHAKE_SERVER_HELLO = 2;

// Extension types relevant to JA3 and SNI
static const uint16_t TLS_EXT_SERVER_NAME        = 0x0000;
static const uint16_t TLS_EXT_SUPPORTED_GROUPS   = 0x000a;
static const uint16_t TLS_EXT_EC_POINT_FORMATS   = 0x000b;
static const uint16_t TLS_EXT_SUPPORTED_VERSIONS = 0x002b;

// TLS record header (5 bytes, all fields big-endian)
struct tls_record_hdr {
    uint8_t  content_type;  // 0x16 = Handshake
    uint8_t  version_major; // 0x03
    uint8_t  version_minor; // 0x01/0x03
    uint8_t  length_hi;
    uint8_t  length_lo;
};

// Handshake header (4 bytes)
struct tls_handshake_hdr {
    uint8_t  msg_type;      // 1=ClientHello, 2=ServerHello
    uint8_t  length[3];     // 24-bit big-endian body length
};

// Parsed ClientHello metadata
struct tls_client_hello {
    tls_client_hello() : legacy_version(0), sni(), tls_version(),
                         cipher_suites(), extensions(), elliptic_curves(),
                         ec_point_formats(), ja3(), ja3_hash() {}
    uint16_t              legacy_version;
    std::string           sni;
    std::string           tls_version;   // human-readable
    std::vector<uint16_t> cipher_suites; // excluding GREASE
    std::vector<uint16_t> extensions;    // excluding GREASE
    std::vector<uint16_t> elliptic_curves;
    std::vector<uint16_t> ec_point_formats;
    std::string           ja3;
    std::string           ja3_hash;
};

// Parsed ServerHello metadata
struct tls_server_hello {
    tls_server_hello() : negotiated_version(), selected_cipher() {}
    std::string negotiated_version;
    std::string selected_cipher;
};

#endif // SCAN_TLS_H

/**
 * scan_tls: TLS handshake metadata extractor for tcpflow.
 *
 * Parses ClientHello and ServerHello messages from reassembled TCP streams,
 * extracting SNI, cipher suites, TLS version and JA3 fingerprint.
 * Output is appended to tls_sni.json in the tcpflow output directory.
 *
 * References: RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), RFC 6066 (SNI),
 *             JA3 fingerprinting specification (github.com/salesforce/ja3).
 */

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"
#include "bulk_extractor_i.h"
#include "scan_tls.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <mutex>

#ifdef HAVE_OPENSSL_MD5_H
#include <openssl/evp.h>
#endif

// -----------------------------------------------------------------------
// Low-level helpers
// -----------------------------------------------------------------------

static inline uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t u24be(const uint8_t *p) {
    return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
}

// GREASE values (RFC 8701): high byte == low byte and (byte & 0x0f) == 0x0a
static bool is_grease(uint16_t v) {
    uint8_t hi = (v >> 8) & 0xff;
    uint8_t lo = v & 0xff;
    return hi == lo && (hi & 0x0f) == 0x0a;
}

static std::string join_u16(const std::vector<uint16_t> &v) {
    std::ostringstream ss;
    for (size_t i = 0; i < v.size(); i++) {
        if (i) ss << '-';
        ss << v[i];
    }
    return ss.str();
}

static std::string tls_version_str(uint16_t v) {
    switch (v) {
        case 0x0304: return "TLS 1.3";
        case 0x0303: return "TLS 1.2";
        case 0x0302: return "TLS 1.1";
        case 0x0301: return "TLS 1.0";
        default: {
            char buf[12];
            snprintf(buf, sizeof(buf), "0x%04x", v);
            return buf;
        }
    }
}

// Compute MD5 hex digest of a string using OpenSSL EVP API
static std::string md5_hexdigest(const std::string &s) {
#ifdef HAVE_EVP_GET_DIGESTBYNAME
    unsigned char digest[16];
    unsigned int  dlen = 0;
    EVP_MD_CTX   *ctx  = EVP_MD_CTX_new();
    if (!ctx) return "";
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, s.c_str(), s.size());
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    char hex[33];
    for (unsigned int i = 0; i < dlen; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    return std::string(hex);
#else
    return "md5_unavailable";
#endif
}

// -----------------------------------------------------------------------
// ClientHello parser
// -----------------------------------------------------------------------

static bool parse_client_hello(const uint8_t *buf, size_t len, size_t off,
                                tls_client_hello &ch) {
    // legacy_version (2) + random (32) + session_id_len (1) = 35 bytes minimum
    if (off + 35 > len) return false;

    ch.legacy_version = u16be(buf + off);
    off += 2 + 32; // skip random[32]

    // Session ID
    uint8_t sid_len = buf[off++];
    if (off + sid_len > len) return false;
    off += sid_len;

    // Cipher suites
    if (off + 2 > len) return false;
    uint16_t cs_bytes = u16be(buf + off); off += 2;
    if (off + cs_bytes > len) return false;
    for (uint16_t i = 0; i + 1 < cs_bytes; i += 2) {
        uint16_t cs = u16be(buf + off + i);
        if (!is_grease(cs)) ch.cipher_suites.push_back(cs);
    }
    off += cs_bytes;

    // Compression methods
    if (off + 1 > len) return false;
    uint8_t comp_len = buf[off++];
    if (off + comp_len > len) return false;
    off += comp_len;

    // Extensions (optional — absent in very old TLS)
    if (off + 2 > len) goto done;
    {
        uint16_t ext_total = u16be(buf + off); off += 2;
        size_t ext_end = off + ext_total;
        if (ext_end > len) ext_end = len;

        while (off + 4 <= ext_end) {
            uint16_t etype = u16be(buf + off); off += 2;
            uint16_t elen  = u16be(buf + off); off += 2;
            size_t   eend  = off + elen;
            if (eend > ext_end) break;

            if (!is_grease(etype)) {
                ch.extensions.push_back(etype);
            }

            switch (etype) {
            case TLS_EXT_SERVER_NAME:
                // server_name_list_len(2) | name_type(1) | name_len(2) | name
                if (ch.sni.empty() && off + 5 <= eend) {
                    uint8_t  name_type = buf[off + 2];
                    uint16_t name_len  = u16be(buf + off + 3);
                    if (name_type == 0 && off + 5 + name_len <= eend) {
                        ch.sni = std::string((const char *)(buf + off + 5), name_len);
                    }
                }
                break;

            case TLS_EXT_SUPPORTED_GROUPS:
                // curves_list_len(2) | uint16_t curves...
                if (off + 2 <= eend) {
                    uint16_t curves_bytes = u16be(buf + off);
                    for (uint16_t i = 2; i + 1 < curves_bytes + 2 && off + i + 2 <= eend; i += 2) {
                        uint16_t curve = u16be(buf + off + i);
                        if (!is_grease(curve)) ch.elliptic_curves.push_back(curve);
                    }
                }
                break;

            case TLS_EXT_EC_POINT_FORMATS:
                // formats_len(1) | uint8_t formats...
                if (off + 1 <= eend) {
                    uint8_t fmt_len = buf[off];
                    for (uint8_t i = 1; i <= fmt_len && off + i < eend; i++) {
                        ch.ec_point_formats.push_back(buf[off + i]);
                    }
                }
                break;

            case TLS_EXT_SUPPORTED_VERSIONS:
                // supported_versions_len(1) | uint16_t versions...
                // TLS 1.3 ClientHello lists 0x0304 here
                if (off + 1 <= eend) {
                    uint8_t sv_len = buf[off];
                    for (uint8_t i = 1; i + 1 < sv_len + 1 && off + i + 1 <= eend; i += 2) {
                        if (u16be(buf + off + i) == 0x0304) {
                            ch.legacy_version = 0x0304; // upgrade version for JA3
                            break;
                        }
                    }
                }
                break;

            default:
                break;
            }

            off = eend;
        }
    }

done:
    ch.tls_version = tls_version_str(ch.legacy_version);

    // Build JA3 string: Version,Ciphers,Extensions,EllipticCurves,ECPointFormats
    std::ostringstream ja3ss;
    ja3ss << ch.legacy_version << ","
          << join_u16(ch.cipher_suites) << ","
          << join_u16(ch.extensions) << ","
          << join_u16(ch.elliptic_curves) << ","
          << join_u16(ch.ec_point_formats);
    ch.ja3      = ja3ss.str();
    ch.ja3_hash = md5_hexdigest(ch.ja3);

    return true;
}

// -----------------------------------------------------------------------
// ServerHello parser
// -----------------------------------------------------------------------

static bool parse_server_hello(const uint8_t *buf, size_t len, size_t off,
                                tls_server_hello &sh) {
    // legacy_version(2) + random(32) + session_id_len(1) = 35 bytes
    if (off + 35 > len) return false;

    uint16_t server_version = u16be(buf + off); off += 2;
    off += 32; // random

    uint8_t sid_len = buf[off++];
    if (off + sid_len + 3 > len) return false;
    off += sid_len;

    uint16_t cipher = u16be(buf + off); off += 2;
    off++; // compression method

    uint16_t final_version = server_version;

    // Check supported_versions extension (TLS 1.3 ServerHello has 0x0304 here)
    if (off + 2 <= len) {
        uint16_t ext_total = u16be(buf + off); off += 2;
        size_t ext_end = off + ext_total;
        if (ext_end > len) ext_end = len;

        while (off + 4 <= ext_end) {
            uint16_t etype = u16be(buf + off); off += 2;
            uint16_t elen  = u16be(buf + off); off += 2;
            if (etype == TLS_EXT_SUPPORTED_VERSIONS && elen == 2 && off + 2 <= ext_end) {
                final_version = u16be(buf + off);
            }
            if (off + elen > ext_end) break;
            off += elen;
        }
    }

    sh.negotiated_version = tls_version_str(final_version);

    char cbuf[10];
    snprintf(cbuf, sizeof(cbuf), "0x%04x", cipher);
    sh.selected_cipher = cbuf;

    return true;
}

// -----------------------------------------------------------------------
// JSON output
// -----------------------------------------------------------------------

static std::mutex tls_output_mutex;

static void append_json(const std::string &flow_key,
                        const tls_client_hello *ch,
                        const tls_server_hello *sh) {
    std::string outpath = flow::outdir + "/tls_sni.json";

    time_t now = time(nullptr);
    char ts[32];
    struct tm *gmt = gmtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    std::lock_guard<std::mutex> lock(tls_output_mutex);
    std::ofstream f(outpath, std::ios::app);
    if (!f) return;

    f << '{';
    f << "\"flow\":\"" << flow_key << "\",";
    f << "\"timestamp\":\"" << ts << "\"";

    if (ch) {
        f << ",\"sni\":\"" << ch->sni << "\"";
        f << ",\"tls_version\":\"" << ch->tls_version << "\"";
        f << ",\"ja3\":\"" << ch->ja3 << "\"";
        f << ",\"ja3_hash\":\"" << ch->ja3_hash << "\"";
        f << ",\"cipher_suites_offered\":" << ch->cipher_suites.size();
    }

    if (sh) {
        f << ",\"negotiated_version\":\"" << sh->negotiated_version << "\"";
        f << ",\"selected_cipher\":\"" << sh->selected_cipher << "\"";
    }

    f << "}\n";
}

// -----------------------------------------------------------------------
// Scanner entry point
// -----------------------------------------------------------------------

extern "C"
void scan_tls(const class scanner_params &sp, const recursion_control_block &rcb) {
    if (sp.sp_version != scanner_params::CURRENT_SP_VERSION) {
        std::cerr << "scan_tls requires sp version "
                  << scanner_params::CURRENT_SP_VERSION
                  << "; got version " << sp.sp_version << "\n";
        exit(1);
    }

    if (sp.phase == scanner_params::PHASE_STARTUP) {
        sp.info->name   = "tls";
        sp.info->author = "tcpflow scan_tls";
        sp.info->flags  = scanner_info::SCANNER_DISABLED; // enable with -e tls
        return;
    }

    if (sp.phase != scanner_params::PHASE_SCAN) return;

    const uint8_t *data = sp.sbuf.buf;
    const size_t   len  = sp.sbuf.bufsize;

    // Minimum: TLS Record (5) + Handshake header (4)
    if (len < 9) return;

    // Must be a Handshake record with plausible TLS version
    if (data[0] != TLS_CONTENT_HANDSHAKE || data[1] != 0x03) return;

    uint16_t record_len = u16be(data + 3);
    if ((size_t)(5 + record_len) > len) return;

    uint8_t  msg_type = data[5];
    uint32_t msg_len  = u24be(data + 6);
    size_t   body_off = 9;

    if (body_off + msg_len > len) return;

    // Build a clean flow identifier from the sbuf path
    std::string flow_key = sp.sbuf.pos0.path;
    size_t slash = flow_key.rfind('/');
    if (slash != std::string::npos)
        flow_key = flow_key.substr(slash + 1);

    if (msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        tls_client_hello ch;
        if (parse_client_hello(data, len, body_off, ch)) {
            append_json(flow_key, &ch, nullptr);
        }
    } else if (msg_type == TLS_HANDSHAKE_SERVER_HELLO) {
        tls_server_hello sh;
        if (parse_server_hello(data, len, body_off, sh)) {
            append_json(flow_key, nullptr, &sh);
        }
    }
}

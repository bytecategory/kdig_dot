#include <winsock2.h>
#include <ws2tcpip.h>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

namespace {

struct Options {
    std::string server;
    std::string name;
    std::string type = "A";
    bool use_tls = false;
    std::string tls_host;
    std::string tls_sni;
    std::string ca_file;
    bool tls12_only = false;
    uint16_t port = 853;
};

constexpr const char* kForcedTlsSni = "gov.cn";

struct MbedTlsSession {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;

    MbedTlsSession() {
        mbedtls_net_init(&net);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&cacert);
    }

    ~MbedTlsSession() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_net_free(&net);
    }
};

[[noreturn]] void Fail(const std::string& message) {
    throw std::runtime_error(message);
}

void Require(bool condition, const std::string& message) {
    if (!condition) {
        Fail(message);
    }
}

std::string ToUpper(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return value;
}

uint16_t ReadBE16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t ReadBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void WriteBE16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

std::string MbedTlsError(int code) {
    char buffer[256]{};
    mbedtls_strerror(code, buffer, sizeof(buffer));
    std::ostringstream oss;
    oss << buffer << " (" << code << ")";
    return oss.str();
}

uint16_t ParseType(const std::string& value) {
    const std::string upper = ToUpper(value);
    if (upper == "A") return 1;
    if (upper == "AAAA") return 28;
    if (upper == "CNAME") return 5;
    if (upper == "TXT") return 16;
    Fail("unsupported query type: " + value);
}

std::string FormatType(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 5: return "CNAME";
        case 16: return "TXT";
        case 28: return "AAAA";
        default: {
            std::ostringstream oss;
            oss << "TYPE" << type;
            return oss.str();
        }
    }
}

Options ParseArgs(int argc, char** argv) {
    if (argc < 4) {
        Fail("usage: kdig_dot.exe @server name TYPE +tls +tls-host=host [+ca=file] [+port=853] [+tls12]");
    }

    Options opt;
    opt.server = argv[1];
    if (!opt.server.empty() && opt.server[0] == '@') {
        opt.server.erase(opt.server.begin());
    }
    opt.name = argv[2];
    opt.type = argv[3];

    for (int i = 4; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "+tls") {
            opt.use_tls = true;
        } else if (arg.rfind("+tls-host=", 0) == 0) {
            opt.tls_host = arg.substr(std::strlen("+tls-host="));
        } else if (arg.rfind("+ca=", 0) == 0) {
            opt.ca_file = arg.substr(std::strlen("+ca="));
        } else if (arg.rfind("+port=", 0) == 0) {
            opt.port = static_cast<uint16_t>(std::stoul(arg.substr(std::strlen("+port="))));
        } else if (arg == "+tls12") {
            opt.tls12_only = true;
        } else {
            Fail("unsupported argument: " + arg);
        }
    }

    Require(opt.use_tls, "only +tls mode is implemented");
    Require(!opt.tls_host.empty(), "+tls-host is required");
    opt.tls_sni = kForcedTlsSni;
    return opt;
}

std::vector<uint8_t> EncodeDnsName(const std::string& name) {
    std::vector<uint8_t> out;
    size_t start = 0;
    while (start < name.size()) {
        const size_t dot = name.find('.', start);
        const size_t end = (dot == std::string::npos) ? name.size() : dot;
        const size_t len = end - start;
        Require(len > 0 && len <= 63, "invalid DNS label in name: " + name);
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                   name.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    out.push_back(0);
    return out;
}

std::vector<uint8_t> BuildQuery(const std::string& name, uint16_t qtype, uint16_t id) {
    std::vector<uint8_t> msg;
    WriteBE16(msg, id);
    WriteBE16(msg, 0x0100);
    WriteBE16(msg, 1);
    WriteBE16(msg, 0);
    WriteBE16(msg, 0);
    WriteBE16(msg, 0);
    const auto encoded_name = EncodeDnsName(name);
    msg.insert(msg.end(), encoded_name.begin(), encoded_name.end());
    WriteBE16(msg, qtype);
    WriteBE16(msg, 1);

    std::vector<uint8_t> framed;
    framed.reserve(msg.size() + 2);
    WriteBE16(framed, static_cast<uint16_t>(msg.size()));
    framed.insert(framed.end(), msg.begin(), msg.end());
    return framed;
}

std::string ExpandName(const std::vector<uint8_t>& packet, size_t offset, size_t* consumed) {
    std::string name;
    size_t current = offset;
    size_t local_consumed = 0;
    bool jumped = false;
    int depth = 0;

    while (true) {
        Require(current < packet.size(), "DNS name out of bounds");
        const uint8_t len = packet[current];
        if ((len & 0xC0) == 0xC0) {
            Require(current + 1 < packet.size(), "truncated DNS compression pointer");
            const uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | packet[current + 1]);
            if (!jumped) {
                local_consumed += 2;
            }
            current = ptr;
            jumped = true;
            if (++depth > 16) {
                Fail("too many DNS compression jumps");
            }
            continue;
        }
        if (len == 0) {
            if (!jumped) {
                local_consumed += 1;
            }
            break;
        }
        Require((len & 0xC0) == 0, "invalid DNS label");
        Require(current + 1 + len <= packet.size(), "truncated DNS label");
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(reinterpret_cast<const char*>(packet.data() + current + 1), len);
        if (!jumped) {
            local_consumed += 1 + len;
        }
        current += 1 + len;
    }

    if (consumed != nullptr) {
        *consumed = local_consumed;
    }
    return name;
}

struct ParsedRecord {
    std::string owner;
    uint16_t type = 0;
    uint32_t ttl = 0;
    std::string value;
};

std::vector<ParsedRecord> ParseResponse(const std::vector<uint8_t>& packet, uint16_t expected_id) {
    Require(packet.size() >= 12, "short DNS response");
    Require(ReadBE16(packet.data()) == expected_id, "mismatched DNS transaction id");

    const uint16_t flags = ReadBE16(packet.data() + 2);
    const uint16_t qdcount = ReadBE16(packet.data() + 4);
    const uint16_t ancount = ReadBE16(packet.data() + 6);
    const uint16_t nscount = ReadBE16(packet.data() + 8);
    const uint16_t arcount = ReadBE16(packet.data() + 10);
    const uint16_t rcode = flags & 0x000f;
    Require(rcode == 0, "DNS server returned rcode=" + std::to_string(rcode));

    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        size_t consumed = 0;
        (void)ExpandName(packet, offset, &consumed);
        offset += consumed;
        Require(offset + 4 <= packet.size(), "truncated DNS question");
        offset += 4;
    }

    auto parse_rrs = [&](uint16_t count, std::vector<ParsedRecord>& out) {
        for (uint16_t i = 0; i < count; ++i) {
            size_t consumed = 0;
            const std::string owner = ExpandName(packet, offset, &consumed);
            offset += consumed;
            Require(offset + 10 <= packet.size(), "truncated DNS resource record header");
            const uint16_t type = ReadBE16(packet.data() + offset);
            const uint16_t klass = ReadBE16(packet.data() + offset + 2);
            const uint32_t ttl = ReadBE32(packet.data() + offset + 4);
            const uint16_t rdlength = ReadBE16(packet.data() + offset + 8);
            offset += 10;
            Require(offset + rdlength <= packet.size(), "truncated DNS rdata");

            ParsedRecord rr;
            rr.owner = owner;
            rr.type = type;
            rr.ttl = ttl;

            if (klass == 1 && type == 1 && rdlength == 4) {
                char text[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, packet.data() + offset, text, sizeof(text));
                rr.value = text;
            } else if (klass == 1 && type == 28 && rdlength == 16) {
                char text[INET6_ADDRSTRLEN]{};
                inet_ntop(AF_INET6, packet.data() + offset, text, sizeof(text));
                rr.value = text;
            } else if (klass == 1 && type == 5) {
                rr.value = ExpandName(packet, offset, nullptr);
            } else if (klass == 1 && type == 16) {
                std::ostringstream txt;
                size_t pos = offset;
                const size_t end = offset + rdlength;
                bool first = true;
                while (pos < end) {
                    const uint8_t len = packet[pos++];
                    Require(pos + len <= end, "truncated TXT record");
                    if (!first) {
                        txt << ' ';
                    }
                    txt << '"'
                        << std::string(reinterpret_cast<const char*>(packet.data() + pos), len)
                        << '"';
                    pos += len;
                    first = false;
                }
                rr.value = txt.str();
            } else {
                std::ostringstream raw;
                raw << "rdata[" << rdlength << " bytes]";
                rr.value = raw.str();
            }

            out.push_back(std::move(rr));
            offset += rdlength;
        }
    };

    std::vector<ParsedRecord> answers;
    answers.reserve(ancount);
    parse_rrs(ancount, answers);
    std::vector<ParsedRecord> ignore;
    parse_rrs(nscount, ignore);
    parse_rrs(arcount, ignore);
    return answers;
}

void PrintAnswer(const Options& opt, const std::vector<ParsedRecord>& answers) {
    const std::string wanted = ToUpper(opt.type);
    bool found = false;
    for (const auto& rr : answers) {
        if (FormatType(rr.type) == wanted) {
            std::cout << rr.owner << ".\t" << rr.ttl << "\tIN\t" << FormatType(rr.type) << "\t"
                      << rr.value << "\n";
            found = true;
        }
    }
    if (!found) {
        std::cout << "; no " << wanted << " answer records\n";
    }
}

std::vector<uint8_t> TlsReadFrame(mbedtls_ssl_context& ssl) {
    std::vector<uint8_t> frame(2);
    size_t offset = 0;
    while (offset < frame.size()) {
        const int rc = mbedtls_ssl_read(&ssl, frame.data() + offset, frame.size() - offset);
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (rc <= 0) {
            Fail("mbedtls_ssl_read failed: " + MbedTlsError(rc));
        }
        offset += static_cast<size_t>(rc);
    }

    const uint16_t dns_size = ReadBE16(frame.data());
    frame.resize(static_cast<size_t>(dns_size) + 2);
    while (offset < frame.size()) {
        const int rc = mbedtls_ssl_read(&ssl, frame.data() + offset, frame.size() - offset);
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (rc <= 0) {
            Fail("mbedtls_ssl_read failed: " + MbedTlsError(rc));
        }
        offset += static_cast<size_t>(rc);
    }
    return frame;
}

void TlsWriteAll(mbedtls_ssl_context& ssl, const std::vector<uint8_t>& data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const int rc = mbedtls_ssl_write(&ssl, data.data() + offset, data.size() - offset);
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (rc <= 0) {
            Fail("mbedtls_ssl_write failed: " + MbedTlsError(rc));
        }
        offset += static_cast<size_t>(rc);
    }
}

void VerifyPeerCertificate(const Options& opt, mbedtls_ssl_context& ssl, mbedtls_x509_crt& cacert) {
    if (opt.ca_file.empty()) {
        return;
    }

    const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer == nullptr) {
        Fail("no peer certificate received");
    }

    uint32_t flags = 0;
    const int rc = mbedtls_x509_crt_verify(const_cast<mbedtls_x509_crt*>(peer), &cacert, nullptr,
                                           opt.tls_host.c_str(), &flags, nullptr, nullptr);
    if (rc != 0 || flags != 0) {
        char buffer[512]{};
        mbedtls_x509_crt_verify_info(buffer, sizeof(buffer), "", flags);
        std::ostringstream oss;
        oss << "certificate verification failed for host '" << opt.tls_host << "'";
        if (flags != 0) {
            oss << ": " << buffer;
        } else {
            oss << ": " << MbedTlsError(rc);
        }
        Fail(oss.str());
    }
}

MbedTlsSession ConnectTls(const Options& opt, bool tls12_only) {
    MbedTlsSession session;
    static const char* kAlpn[] = {"dot", nullptr};
    const char* pers = "kdig-dot";

    int rc = mbedtls_ctr_drbg_seed(&session.ctr_drbg, mbedtls_entropy_func, &session.entropy,
                                   reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
    if (rc != 0) {
        Fail("mbedtls_ctr_drbg_seed failed: " + MbedTlsError(rc));
    }

    if (!opt.ca_file.empty()) {
        rc = mbedtls_x509_crt_parse_file(&session.cacert, opt.ca_file.c_str());
        if (rc < 0) {
            Fail("mbedtls_x509_crt_parse_file failed: " + MbedTlsError(rc));
        }
    }

    rc = mbedtls_ssl_config_defaults(&session.conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        Fail("mbedtls_ssl_config_defaults failed: " + MbedTlsError(rc));
    }

    mbedtls_ssl_conf_rng(&session.conf, mbedtls_ctr_drbg_random, &session.ctr_drbg);
    mbedtls_ssl_conf_alpn_protocols(&session.conf, kAlpn);
    mbedtls_ssl_conf_authmode(&session.conf, MBEDTLS_SSL_VERIFY_NONE);
    if (!opt.ca_file.empty()) {
        mbedtls_ssl_conf_ca_chain(&session.conf, &session.cacert, nullptr);
    }
    if (tls12_only) {
        mbedtls_ssl_conf_min_tls_version(&session.conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&session.conf, MBEDTLS_SSL_VERSION_TLS1_2);
    }

    rc = mbedtls_ssl_setup(&session.ssl, &session.conf);
    if (rc != 0) {
        Fail("mbedtls_ssl_setup failed: " + MbedTlsError(rc));
    }

    rc = mbedtls_ssl_set_hostname(&session.ssl, opt.tls_sni.c_str());
    if (rc != 0) {
        Fail("mbedtls_ssl_set_hostname failed: " + MbedTlsError(rc));
    }

    rc = mbedtls_net_connect(&session.net, opt.server.c_str(), std::to_string(opt.port).c_str(),
                             MBEDTLS_NET_PROTO_TCP);
    if (rc != 0) {
        Fail("mbedtls_net_connect failed: " + MbedTlsError(rc));
    }

    mbedtls_ssl_set_bio(&session.ssl, &session.net, mbedtls_net_send, mbedtls_net_recv, nullptr);

    while ((rc = mbedtls_ssl_handshake(&session.ssl)) != 0) {
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        Fail("mbedtls_ssl_handshake failed: " + MbedTlsError(rc));
    }
    VerifyPeerCertificate(opt, session.ssl, session.cacert);

    return session;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options opt = ParseArgs(argc, argv);
        const auto run_query = [&]() {
            auto query_once = [&](bool tls12_only) {
                MbedTlsSession session = ConnectTls(opt, tls12_only);
                std::random_device rd;
                const uint16_t id = static_cast<uint16_t>(rd());
                const std::vector<uint8_t> query = BuildQuery(opt.name, ParseType(opt.type), id);
                TlsWriteAll(session.ssl, query);

                const std::vector<uint8_t> frame = TlsReadFrame(session.ssl);
                const std::vector<uint8_t> packet(frame.begin() + 2, frame.end());
                const auto answers = ParseResponse(packet, id);
                PrintAnswer(opt, answers);
            };

            try {
                query_once(opt.tls12_only);
            } catch (const std::exception& ex) {
                const std::string message = ex.what();
                if (opt.tls12_only || message.find("mbedtls_ssl_handshake failed") == std::string::npos) {
                    throw;
                }
                query_once(true);
            }
        };

        run_query();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
}

// http.cpp — recon-grade HTTP engine. Win11 / MSVC. Winsock + WinHTTP.
// Features: full header capture, redirect chain, body cap, timing,
// leak-risk scoring (verbose errors, tech disclosure, cookies, JSON bodies).
#include "http.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

namespace {

constexpr size_t kBodyCap     = 65536;   // 64 KB body preview max
constexpr DWORD  kTimeoutMs   = 8000;

bool wsa_ready() {
    static bool init = [] {
        WSADATA d{};
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    return init;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(),
                        const_cast<wchar_t*>(w.data()), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    const wchar_t* src = w.c_str();
    int n = WideCharToMultiByte(CP_UTF8, 0, src, (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, src, (int)w.size(),
                        const_cast<char*>(s.data()), n, nullptr, nullptr);
    return s;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

std::string status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "";
    }
}

// -------- WinHTTP (TLS) path --------

HttpResponse winhttp_get(const std::string& host, int port, const std::string& path) {
    HttpResponse out;
    auto t0 = std::chrono::steady_clock::now();

    HINTERNET hSession = WinHttpOpen(L"leakhunter/0.3",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { out.error_code = -3; out.error_text = "WinHttpOpen failed"; return out; }

    WinHttpSetTimeouts(hSession, kTimeoutMs, kTimeoutMs, kTimeoutMs, kTimeoutMs);

    std::wstring whost = widen(host);
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        out.error_code = -4; out.error_text = "WinHttpConnect failed";
        return out;
    }

    std::wstring wpath = widen(path.empty() ? "/" : path);
    DWORD flags = (port == 443) ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        out.error_code = -5; out.error_text = "WinHttpOpenRequest failed";
        return out;
    }

    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY,
                     &redirect_policy, sizeof(redirect_policy));

    // Security: don't let a downgrade to plaintext happen silently
    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA  // lab; strip for prod
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &sec_flags, sizeof(sec_flags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DWORD e = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        out.error_code = -6;
        out.error_text = "send failed (err " + std::to_string(e) + ")";
        return out;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD e = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        out.error_code = -7;
        out.error_text = "recv failed (err " + std::to_string(e) + ")";
        return out;
    }

    DWORD status = 0, slen = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen,
                        WINHTTP_NO_HEADER_INDEX);
    out.status = (int)status;
    out.status_text = status_text(out.status);

    // Pull final URL (post-redirect) and store the chain by diffing host+path
       {
        DWORD len = 0;
        WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL,
                           static_cast<LPVOID>(nullptr), &len);
        if (len > 0) {
            std::wstring buf(len / sizeof(wchar_t) + 1, L'\0');
                        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL,
                                   const_cast<wchar_t*>(buf.data()), &len)) {
                out.final_url = narrow(buf.c_str());
                std::string requested = (port == 443 ? "https://" : "http://") +
                                        host + (port == 80 || port == 443 ? "" :
                                        ":" + std::to_string(port)) + path;
                if (out.final_url != requested)
                    out.redirect_chain.push_back(out.final_url);
            }
        }
    }

    // Headers — full dump
    {
        DWORD len = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            static_cast<LPVOID>(nullptr), &len,
                            WINHTTP_NO_HEADER_INDEX);
        if (len > 0) {
            std::wstring wbuf(len / sizeof(wchar_t) + 1, L'\0');
                        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    const_cast<wchar_t*>(wbuf.data()),
                                    &len, WINHTTP_NO_HEADER_INDEX)) {
                std::string raw = narrow(wbuf.c_str());
                std::istringstream hs(raw);
                std::string line;
                while (std::getline(hs, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    auto c = line.find(':');
                    if (c == std::string::npos) continue;
                    std::string k = lower(trim(line.substr(0, c)));
                    std::string v = trim(line.substr(c + 1));
                    if (!k.empty()) out.headers[k] = v;
                }
            }
        }
    }

    auto ct = out.headers.find("content-type");
    if (ct != out.headers.end()) out.content_type = ct->second;

    // Body — cap at kBodyCap
    std::string body;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;

        size_t old = body.size();
        size_t take = (std::min)((size_t)avail, kBodyCap - old);
        if (take == 0) { out.body_truncated = true; break; }

        body.resize(old + take);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &body[old], (DWORD)take, &read)) {
            body.resize(old);
            break;
        }
        body.resize(old + read);
        if (body.size() >= kBodyCap) { out.body_truncated = true; break; }
    }
    out.body = std::move(body);
    out.size = (long)out.body.size();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    auto t1 = std::chrono::steady_clock::now();
    out.elapsed_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    return out;
}

// -------- Winsock (plaintext) path --------

HttpResponse winsock_get(const std::string& host, int port, const std::string& path) {
    HttpResponse out;
    auto t0 = std::chrono::steady_clock::now();

    if (!wsa_ready()) { out.error_code = -2; out.error_text = "WSAStartup failed"; return out; }

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        out.error_code = -1; out.error_text = "DNS failed"; return out;
    }

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        DWORD tv = kTimeoutMs;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) {
        out.error_code = -1; out.error_text = "connect failed"; return out;
    }

    std::ostringstream req;
    req << "GET " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: leakhunter/0.3\r\n"
        << "Accept: */*\r\n"
        << "Accept-Encoding: identity\r\n"
        << "Connection: close\r\n\r\n";
    std::string r = req.str();
    send(s, r.data(), (int)r.size(), 0);

    std::string raw;
    char buf[8192];
    int n;
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0) {
        raw.append(buf, n);
        if (raw.size() > kBodyCap + 16384) break;   // headers + cap
    }
    closesocket(s);

    auto hdr_end = raw.find("\r\n\r\n");
    std::string head = (hdr_end == std::string::npos) ? raw : raw.substr(0, hdr_end);
    std::string body = (hdr_end == std::string::npos) ? "" : raw.substr(hdr_end + 4);
    if (body.size() > kBodyCap) { body.resize(kBodyCap); out.body_truncated = true; }

    std::istringstream hs(head);
    std::string line;
    bool first = true;
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) {
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                out.status = std::atoi(line.c_str() + sp + 1);
                out.status_text = trim(line.substr(sp + 1));
                auto sp2 = out.status_text.find(' ');
                if (sp2 != std::string::npos)
                    out.status_text = out.status_text.substr(0, sp2);
            }
            first = false;
            continue;
        }
        auto c = line.find(':');
        if (c == std::string::npos) continue;
        std::string k = lower(trim(line.substr(0, c)));
        std::string v = trim(line.substr(c + 1));
        if (!k.empty()) out.headers[k] = v;
    }

    out.body = std::move(body);
    out.size = (long)out.body.size();
    auto ct = out.headers.find("content-type");
    if (ct != out.headers.end()) out.content_type = ct->second;

    auto t1 = std::chrono::steady_clock::now();
    out.elapsed_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    return out;
}

} // namespace

HttpResponse http_get(const std::string& host, int port,
                      const std::string& path, bool tls) {
    return tls ? winhttp_get(host, port, path)
               : winsock_get(host, port, path);
}

void wsa_shutdown() { WSACleanup(); }

// -------- leak-risk scoring --------

int score_leak_risk(const HttpResponse& r) {
    int score = 0;
    if (r.status == 200 && r.size > 0)         score += 5;   // reachable content
    if (r.status == 500 || r.status == 502)    score += 25;  // verbose errors = stack traces often
    if (r.status == 403 && r.size > 500)       score += 15;  // forbidden w/ body = auth gate leaking
    if (r.body_truncated)                      score += 3;

    // tech disclosure
    for (const auto& key : {"server","x-powered-by","x-aspnet-version",
                            "x-generator","via","x-backend-server"}) {
        auto it = r.headers.find(key);
        if (it != r.headers.end() && !it->second.empty()) score += 8;
    }

    // cookie flags — missing HttpOnly/Secure is a leak signal
    auto ck = r.headers.find("set-cookie");
    if (ck != r.headers.end()) {
        score += 5;
        if (ck->second.find("HttpOnly") == std::string::npos) score += 5;
        if (ck->second.find("Secure")   == std::string::npos) score += 5;
    }

    // body heuristics
    const std::string& b = r.body;
    if (r.content_type.find("json") != std::string::npos) score += 10;
    for (const char* needle : {"password", "api_key", "apikey", "secret",
                               "token\":", "private_key", "authorization",
                               "stack trace", "stacktrace", "at line",
                               "SQLSTATE", "mysql_", "pg_query",
                               "SELECT ", "INSERT INTO",
                               "aws_access_key", "BEGIN RSA PRIVATE"}) {
        if (b.find(needle) != std::string::npos) { score += 20; break; }
    }

    // CORS wide-open
    auto acao = r.headers.find("access-control-allow-origin");
    if (acao != r.headers.end() &&
        (acao->second == "*" ||
         acao->second.find("null") != std::string::npos)) score += 10;

    // security headers absent = weaker target
    for (const char* h : {"strict-transport-security","content-security-policy",
                          "x-frame-options","x-content-type-options"}) {
        if (r.headers.find(h) == r.headers.end()) score += 2;
    }

    return (std::min)(score, 100);
}

std::string summarize(const HttpResponse& r) {
    std::ostringstream o;
    o << "[" << r.status;
    if (!r.status_text.empty()) o << " " << r.status_text;
    o << "] " << r.size << "B " << r.elapsed_ms << "ms";
    if (r.error_code) o << " err=" << r.error_text;
    int risk = score_leak_risk(r);
    if (risk >= 60)      o << "  RISK=" << risk << " HIGH";
    else if (risk >= 30) o << "  RISK=" << risk;
    if (!r.redirect_chain.empty()) o << "  -> " << r.final_url;
    return o.str();
}
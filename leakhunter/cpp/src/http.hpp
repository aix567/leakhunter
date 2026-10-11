// http.hpp
#pragma once
#include <string>
#include <map>
#include <vector>

struct HttpResponse {
    int         status      = 0;
    std::string status_text;            // "200 OK"
    long        size        = 0;
    std::string body;                   // capped to kBodyCap
    bool        body_truncated = false;
    std::map<std::string,std::string> headers;    // lowercase keys
    std::vector<std::string>          redirect_chain;
    std::string final_url;
    std::string content_type;
    long        elapsed_ms  = 0;
    int         error_code  = 0;        // 0 = clean, negative = transport error
    std::string error_text;
};

// tls=false → Winsock plaintext; tls=true → WinHTTP/SChannel
HttpResponse http_get(const std::string& host, int port,
                      const std::string& path, bool tls);

void wsa_shutdown();

// leak heuristics — call after http_get, returns 0..100 risk score
int  score_leak_risk(const HttpResponse& r);

// short one-line human summary for console output
std::string summarize(const HttpResponse& r);
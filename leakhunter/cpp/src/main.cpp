// main.cpp — recon prober. TLS via port 443 or `https` token.
// `--headers` dumps headers. Body preview capped.
#include "http.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <algorithm>
#include <cstdlib>
#include <cctype>

std::mutex g_mu;
bool g_show_headers = false;

void worker(const std::string& host, int port, const std::string& path, bool tls) {
    auto r = http_get(host, port, path, tls);
    std::lock_guard<std::mutex> lk(g_mu);

    std::cout << path << " -> " << summarize(r) << "\n";
    if (g_show_headers && !r.headers.empty()) {
        for (const auto& kv : r.headers)
            std::cout << "    " << kv.first << ": " << kv.second << "\n";
    }
    if (r.size > 0) {
        size_t n = (std::min)((size_t)200, r.body.size());
        std::string prev = r.body.substr(0, n);
        for (char& c : prev) if (c == '\n' || c == '\r') c = ' ';
        std::cout << "    | " << prev << (r.body.size() > n ? "..." : "") << "\n";
    }
    int risk = score_leak_risk(r);
    if (risk >= 60) std::cout << "    !! HIGH LEAK RISK (" << risk << ")\n";
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: leakhunter HOST PORT [paths...] [https] [--headers]\n";
        std::cerr << "       leakhunter roblox.com 443 / /robots.txt\n";
        std::cerr << "       leakhunter example.com 80 / --headers\n";
        return 1;
    }

    std::string host = argv[1];
    int port = std::atoi(argv[2]);
    if (port == 0) {
        std::cerr << "[!] port parse failed on '" << argv[2] << "'\n";
        return 1;
    }

    bool tls = (port == 443);
    std::vector<std::string> paths;
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        std::string low = a;
        std::transform(low.begin(), low.end(), low.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        if (low == "https" || low == "tls" || low == "--https") { tls = true; continue; }
        if (low == "--headers" || low == "-h") { g_show_headers = true; continue; }
        paths.push_back(a);
    }
    if (paths.empty()) paths = { "/" };

    std::vector<std::thread> ts;
    for (auto& p : paths)
        ts.emplace_back(worker, std::cref(host), port, std::cref(p), tls);
    for (auto& t : ts) t.join();

    wsa_shutdown();
    return 0;
}
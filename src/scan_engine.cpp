#include "scan_engine.hpp"
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cctype>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
    #include <poll.h>
#endif

static std::string getServiceName(int port, bool isUdp) {
    if (isUdp) {
        switch (port) {
            case 53: return "domain";
            case 67: return "dhcps";
            case 68: return "dhcpc";
            case 69: return "tftp";
            case 123: return "ntp";
            case 161: return "snmp";
            case 514: return "syslog";
            default: return "unknown";
        }
    }
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "domain";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "microsoft-ds";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 3306: return "mysql";
        case 3389: return "ms-wbt-server";
        case 5432: return "postgresql";
        case 8080: return "http-proxy";
        default: return "unknown";
    }
}

ScanEngine::ScanEngine(std::string targetIp, std::vector<int> ports, 
                       ScanType type, int timeoutMs, size_t threads, bool versionDet)
    : targetIp_(std::move(targetIp)), ports_(std::move(ports)), 
      scanType_(type), timeoutMs_(timeoutMs), threadCount_(threads), versionDetection_(versionDet) {}

void ScanEngine::setProgressCallback(ProgressCallback cb) {
    progressCb_ = std::move(cb);
}

std::vector<ScanResult> ScanEngine::scan() {
    std::vector<ScanResult> results;
    results.reserve(ports_.size());
    
    std::mutex mtx;
    std::mutex cbMtx;
    std::queue<int> q;
    for (int p : ports_) q.push(p);
    
    std::vector<std::thread> workers;
    size_t nThreads = std::min(threadCount_, ports_.size());
    
    for (size_t i = 0; i < nThreads; ++i) {
        workers.emplace_back([&]() {
            while (true) {
                int port = -1;
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    if (q.empty()) break;
                    port = q.front(); q.pop();
                }
                
                auto res = scanPort(port);
                
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    results.push_back(res);
                }
                
                if (progressCb_) {
                    std::lock_guard<std::mutex> lock(cbMtx);
                    progressCb_(res);
                }
            }
        });
    }
    
    for (auto& t : workers) t.join();
    
    std::sort(results.begin(), results.end(), 
              [](const auto& a, const auto& b) { return a.port < b.port; });
    
    return results;
}

ScanResult ScanEngine::scanPort(int port) const {
    ScanResult res;
    res.ip = targetIp_;
    res.port = port;
    res.scanType = scanType_;
    res.service = getServiceName(port, scanType_ == ScanType::UDP);
    
    switch (scanType_) {
        case ScanType::TCPConnect: return tcpConnectScan(port);
        case ScanType::TCPSyn: return tcpSynScan(port);
        case ScanType::UDP: return udpScan(port);
    }
    return res;
}

ScanResult ScanEngine::tcpConnectScan(int port) const {
    ScanResult res{targetIp_, targetIp_, port, PortState::Closed, 
                   getServiceName(port, false), "", ScanType::TCPConnect};
    
#ifdef _WIN32
    WSADATA wsaData;
    static bool wsaInit = false;
    if (!wsaInit) { WSAStartup(MAKEWORD(2,2), &wsaData); wsaInit = true; }
#endif

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) { res.state = PortState::Filtered; return res; }
    
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, targetIp_.c_str(), &addr.sin_addr);

    int conn = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    
    if (conn == 0) {
        res.state = PortState::Open;
    } else {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
        if (errno == EINPROGRESS)
#endif
        {
#ifdef _WIN32
            fd_set fdset; FD_ZERO(&fdset); FD_SET(sock, &fdset);
            timeval tv; tv.tv_sec = timeoutMs_ / 1000; tv.tv_usec = (timeoutMs_ % 1000) * 1000;
            if (select(0, nullptr, &fdset, nullptr, &tv) > 0) {
                int so_error; socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
                res.state = (so_error == 0) ? PortState::Open : PortState::Closed;
            } else {
                res.state = PortState::Filtered;
            }
#else
            pollfd pfd{sock, POLLOUT, 0};
            int ret = poll(&pfd, 1, timeoutMs_);
            if (ret > 0) {
                int so_error; socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                res.state = (so_error == 0) ? PortState::Open : PortState::Closed;
            } else if (ret == 0) {
                res.state = PortState::Filtered;
            }
#endif
        }
    }
    
    if (res.state == PortState::Open && versionDetection_) {
#ifdef _WIN32
        u_long mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        DWORD tv = 2000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        char buf[512] = {0};
        int len = recv(sock, buf, sizeof(buf) - 1, 0);
        if (len > 0) {
            std::string banner(buf, len);
            banner.erase(std::remove_if(banner.begin(), banner.end(), 
                [](unsigned char c){ return c != '\r' && c != '\n' && !std::isprint(c); }), banner.end());
            size_t start = banner.find_first_not_of(" \r\n\t");
            if (start != std::string::npos) {
                size_t end = banner.find_last_not_of(" \r\n\t");
                res.banner = banner.substr(start, end - start + 1);
            }
        }
    }
    
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return res;
}

ScanResult ScanEngine::tcpSynScan(int port) const {
    ScanResult res{targetIp_, targetIp_, port, PortState::Closed,
                   getServiceName(port, false), "", ScanType::TCPSyn};
    
#ifndef __linux__
    res = tcpConnectScan(port);
    res.scanType = ScanType::TCPSyn;
    return res;
#else
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        res.state = PortState::Filtered;
        return res;
    }
    
    close(sock);
    
    res = tcpConnectScan(port);
    res.scanType = ScanType::TCPSyn;
    return res;
#endif
}

ScanResult ScanEngine::udpScan(int port) const {
    ScanResult res{targetIp_, targetIp_, port, PortState::OpenFiltered,
                   getServiceName(port, true), "", ScanType::UDP};
    
#ifdef _WIN32
    WSADATA wsaData;
    static bool wsaInit = false;
    if (!wsaInit) { WSAStartup(MAKEWORD(2,2), &wsaData); wsaInit = true; }
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { res.state = PortState::Filtered; return res; }
    
#ifdef _WIN32
    DWORD tv = timeoutMs_;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeoutMs_ / 1000;
    tv.tv_usec = (timeoutMs_ % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, targetIp_.c_str(), &addr.sin_addr);
    
    char dummy = 0;
    sendto(sock, &dummy, 1, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    
    char buf[1024];
    sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    int recvLen = recvfrom(sock, buf, sizeof(buf), 0, 
                           reinterpret_cast<sockaddr*>(&from), &fromLen);
    
    if (recvLen >= 0) {
        res.state = PortState::Open;
    } else {
        res.state = PortState::OpenFiltered;
    }
    
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return res;
}

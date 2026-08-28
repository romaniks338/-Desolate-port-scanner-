#include "dns_resolver.hpp"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

HostInfo DnsResolver::resolve(const std::string& host) {
    HostInfo info;
    info.originalHost = host;
    
    // Check if already an IP
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, host.c_str(), &(sa.sin_addr)) == 1) {
        info.resolvedIp = host;
        info.isDomain = false;
        return info;
    }
    
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0) {
        char ipStr[INET_ADDRSTRLEN];
        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
        inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
        info.resolvedIp = ipStr;
        info.isDomain = true;
        freeaddrinfo(res);
    }
    
    return info;
}

#pragma once
#include <string>

struct HostInfo {
    std::string originalHost;
    std::string resolvedIp;
    bool isDomain = false;
};

class DnsResolver {
public:
    static HostInfo resolve(const std::string& host);
};

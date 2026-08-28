#include "port_range.hpp"
#include <sstream>
#include <algorithm>

std::vector<int> PortRange::parse(const std::string& input) {
    std::vector<int> ports;
    std::stringstream ss(input);
    std::string token;
    
    while (std::getline(ss, token, ',')) {
        token.erase(std::remove_if(token.begin(), token.end(), ::isspace), token.end());
        if (token.empty()) continue;
        
        auto dashPos = token.find('-');
        if (dashPos != std::string::npos) {
            int start = std::stoi(token.substr(0, dashPos));
            int end = std::stoi(token.substr(dashPos + 1));
            addRange(ports, start, end);
        } else {
            ports.push_back(std::stoi(token));
        }
    }
    
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

void PortRange::addRange(std::vector<int>& ports, int start, int end) {
    if (start > end) std::swap(start, end);
    if (start < 1) start = 1;
    if (end > 65535) end = 65535;
    for (int p = start; p <= end; ++p) {
        ports.push_back(p);
    }
}

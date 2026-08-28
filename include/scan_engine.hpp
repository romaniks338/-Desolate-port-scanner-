#pragma once
#include "result.hpp"
#include "scan_types.hpp"
#include <vector>
#include <string>
#include <functional>

class ScanEngine {
public:
    using ProgressCallback = std::function<void(const ScanResult&)>;
    
    ScanEngine(std::string targetIp, std::vector<int> ports, 
               ScanType type, int timeoutMs, size_t threads, bool versionDet);
    
    void setProgressCallback(ProgressCallback cb);
    std::vector<ScanResult> scan();
    
private:
    std::string targetIp_;
    std::vector<int> ports_;
    ScanType scanType_;
    int timeoutMs_;
    size_t threadCount_;
    bool versionDetection_;
    ProgressCallback progressCb_;
    
    ScanResult scanPort(int port) const;
    ScanResult tcpConnectScan(int port) const;
    ScanResult tcpSynScan(int port) const;
    ScanResult udpScan(int port) const;
};

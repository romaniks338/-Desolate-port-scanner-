#pragma once
#include <string>
#include "scan_types.hpp"

struct ScanOptions {
    std::string target;
    std::string portSpec = "1-1000";
    ScanType scanType = ScanType::TCPConnect;
    int timeoutMs = 1000;
    int maxRttTimeoutMs = 1000;
    size_t threadCount = 100;
    bool verbose = false;
    bool noPing = false;
    std::string outputFile;
    bool showAll = false;
    bool versionDetection = false;
};

class ArgParser {
public:
    static ScanOptions parse(int argc, char* argv[]);
    static void printUsage(const char* prog);
};

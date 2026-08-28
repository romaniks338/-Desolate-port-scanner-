#include "arg_parser.hpp"
#include <iostream>

void ArgParser::printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <target> [options]\n\n"
              << "TARGET SPECIFICATION:\n"
              << "  <target>              IP address or domain name\n\n"
              << "SCAN TECHNIQUES:\n"
              << "  -sT                   TCP connect scan (default)\n"
              << "  -sS                   TCP SYN stealth scan (Linux/root only)\n"
              << "  -sU                   UDP scan\n"
              << "  -sV                   Version detection (banner grab)\n\n"
              << "PORT SPECIFICATION:\n"
              << "  -p <ports>            Port ranges: 80, 1-1024, 22,80,443\n"
              << "  -p-                   Scan all 65535 ports\n\n"
              << "HOST DISCOVERY:\n"
              << "  -Pn                   Treat all hosts as online\n\n"
              << "TIMING AND PERFORMANCE:\n"
              << "  --max-rtt-timeout <ms>  Maximum RTT timeout (default: 1000)\n"
              << "  -j <n>                Number of threads (default: 100)\n\n"
              << "OUTPUT:\n"
              << "  -v                    Verbose mode\n"
              << "  --show-all            Show closed ports too\n"
              << "  -oN <file>            Save results to file\n\n"
              << "EXAMPLES:\n"
              << "  " << prog << " scanme.nmap.org -p 22,80,443\n"
              << "  " << prog << " 192.168.1.1 -p- -j 500\n"
              << "  " << prog << " example.com -sU -p 53,161 -v\n";
}

ScanOptions ArgParser::parse(int argc, char* argv[]) {
    ScanOptions opts;
    if (argc < 2) return opts;
    
    opts.target = argv[1];
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-sT") opts.scanType = ScanType::TCPConnect;
        else if (arg == "-sS") opts.scanType = ScanType::TCPSyn;
        else if (arg == "-sU") opts.scanType = ScanType::UDP;
        else if (arg == "-sV") opts.versionDetection = true;
        else if (arg == "-p" && i + 1 < argc) {
            std::string val = argv[++i];
            opts.portSpec = (val == "-") ? "1-65535" : val;
        }
        else if (arg == "-p-") opts.portSpec = "1-65535";
        else if (arg == "--max-rtt-timeout" && i + 1 < argc) opts.maxRttTimeoutMs = std::stoi(argv[++i]);
        else if (arg == "-j" && i + 1 < argc) opts.threadCount = std::stoul(argv[++i]);
        else if (arg == "-v") opts.verbose = true;
        else if (arg == "-Pn") opts.noPing = true;
        else if (arg == "--show-all") opts.showAll = true;
        else if (arg == "-oN" && i + 1 < argc) opts.outputFile = argv[++i];
    }
    
    opts.timeoutMs = opts.maxRttTimeoutMs;
    return opts;
}

#include <iostream>
#include <chrono>
#include <fstream>
#include <iomanip>
#include "arg_parser.hpp"
#include "dns_resolver.hpp"
#include "scan_engine.hpp"
#include "port_range.hpp"

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
        ArgParser::printUsage(argv[0]);
        return 1;
    }
    
    auto opts = ArgParser::parse(argc, argv);
    
    auto hostInfo = DnsResolver::resolve(opts.target);
    if (hostInfo.resolvedIp.empty()) {
        std::cerr << "[!] Failed to resolve " << opts.target << "\n";
        return 1;
    }
    
    std::cout << "[*] Target: " << hostInfo.originalHost;
    if (hostInfo.isDomain) {
        std::cout << " (" << hostInfo.resolvedIp << ")";
    }
    std::cout << "\n";
    
    std::vector<int> ports;
    try {
        ports = PortRange::parse(opts.portSpec);
    } catch (...) {
        std::cerr << "[!] Invalid port specification: " << opts.portSpec << "\n";
        return 1;
    }
    
    std::cout << "[*] Scan type: " << scanTypeToString(opts.scanType) << "\n";
    std::cout << "[*] Ports: " << ports.size() << "\n";
    std::cout << "[*] Threads: " << opts.threadCount << "\n";
    std::cout << "[*] Timeout: " << opts.timeoutMs << "ms\n";
    if (opts.versionDetection) std::cout << "[*] Version detection enabled\n";
    if (opts.verbose) std::cout << "[*] Verbose mode enabled\n";
    std::cout << "[*] Starting scan...\n\n";
    
    ScanEngine engine(hostInfo.resolvedIp, ports, opts.scanType, opts.timeoutMs, opts.threadCount, opts.versionDetection);
    
    engine.setProgressCallback([&](const ScanResult& r) {
        if (r.state == PortState::Open) {
            std::cout << "Discovered open port " << r.port << "/" 
                      << (r.scanType == ScanType::UDP ? "udp" : "tcp")
                      << " on " << r.ip;
            if (!r.banner.empty()) std::cout << "  [" << r.banner << "]";
            std::cout << "\n";
        } else if (opts.verbose && r.state != PortState::Closed) {
            std::cout << "Port " << r.port << " is " << stateToString(r.state) << "\n";
        }
    });
    
    auto start = std::chrono::steady_clock::now();
    auto results = engine.scan();
    auto end = std::chrono::steady_clock::now();
    
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    size_t open = 0, closed = 0, filtered = 0;
    for (const auto& r : results) {
        if (r.state == PortState::Open || r.state == PortState::OpenFiltered) open++;
        else if (r.state == PortState::Closed) closed++;
        else filtered++;
    }
    
    std::cout << "\n[*] Scan completed in " << dur / 1000.0 << " seconds\n";
    std::cout << "[*] " << open << " open, " << closed << " closed, " << filtered << " filtered\n\n";
    
    if (!results.empty()) {
        std::cout << "PORT     STATE         SERVICE\n";
        for (const auto& r : results) {
            if (!opts.showAll && r.state == PortState::Closed) continue;
            std::string proto = (r.scanType == ScanType::UDP) ? "udp" : "tcp";
            int spacing = 9 - (std::to_string(r.port).length() + 1 + proto.length());
            std::cout << r.port << "/" << proto 
                      << std::string(spacing < 0 ? 0 : spacing, ' ')
                      << std::left << std::setw(14) << stateToString(r.state)
                      << r.service;
            if (!r.banner.empty()) std::cout << "  " << r.banner;
            std::cout << "\n";
        }
    }
    
    if (!opts.outputFile.empty()) {
        std::ofstream out(opts.outputFile);
        out << "Host: " << hostInfo.originalHost << " (" << hostInfo.resolvedIp << ")\n";
        out << "PORT     STATE         SERVICE\n";
        for (const auto& r : results) {
            if (!opts.showAll && r.state == PortState::Closed) continue;
            std::string proto = (r.scanType == ScanType::UDP) ? "udp" : "tcp";
            out << r.port << "/" << proto << "  " 
                << stateToString(r.state) << "  " << r.service;
            if (!r.banner.empty()) out << "  " << r.banner;
            out << "\n";
        }
        std::cout << "\n[*] Results saved to " << opts.outputFile << "\n";
    }
    
    return 0;
}

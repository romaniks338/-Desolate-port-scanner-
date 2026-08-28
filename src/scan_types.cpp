#include "scan_types.hpp"

std::string scanTypeToString(ScanType type) {
    switch (type) {
        case ScanType::TCPConnect: return "TCP Connect";
        case ScanType::TCPSyn: return "TCP SYN Stealth";
        case ScanType::UDP: return "UDP";
    }
    return "Unknown";
}

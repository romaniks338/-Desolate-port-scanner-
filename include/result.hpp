#pragma once
#include <string>
#include "scan_types.hpp"

enum class PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered
};

struct ScanResult {
    std::string host;
    std::string ip;
    int port = 0;
    PortState state = PortState::Closed;
    std::string service;
    std::string banner;
    ScanType scanType = ScanType::TCPConnect;
};

std::string stateToString(PortState state);

#pragma once
#include <string>

enum class ScanType {
    TCPConnect,   
    TCPSyn,       
    UDP           
};

std::string scanTypeToString(ScanType type);

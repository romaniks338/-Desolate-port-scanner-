#pragma once
#include <vector>
#include <string>

class PortRange {
public:
    static std::vector<int> parse(const std::string& input);
private:
    static void addRange(std::vector<int>& ports, int start, int end);
};

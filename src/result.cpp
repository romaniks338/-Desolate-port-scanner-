#include "result.hpp"

std::string stateToString(PortState state) {
    switch (state) {
        case PortState::Open: return "open";
        case PortState::Closed: return "closed";
        case PortState::Filtered: return "filtered";
        case PortState::Unfiltered: return "unfiltered";
        case PortState::OpenFiltered: return "open|filtered";
    }
    return "unknown";
}

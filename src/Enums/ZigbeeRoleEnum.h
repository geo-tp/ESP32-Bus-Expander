#pragma once

#include <string>

enum class ZigbeeRoleEnum {
    Coordinator,
    Router,
    EndDevice,
};

class ZigbeeRoleEnumMapper {
public:
    static std::string toString(ZigbeeRoleEnum role) {
        switch (role) {
            case ZigbeeRoleEnum::Coordinator: return "COORDINATOR";
            case ZigbeeRoleEnum::Router:      return "ROUTER";
            case ZigbeeRoleEnum::EndDevice:   return "ENDDEVICE";
        }
        return "UNKNOWN";
    }

    static bool fromString(const std::string& name, ZigbeeRoleEnum& out) {
        if (name == "coordinator" || name == "zc" || name == "c") {
            out = ZigbeeRoleEnum::Coordinator;
            return true;
        }
        if (name == "router" || name == "zr" || name == "r") {
            out = ZigbeeRoleEnum::Router;
            return true;
        }
        if (name == "ed" || name == "enddevice" || name == "zed") {
            out = ZigbeeRoleEnum::EndDevice;
            return true;
        }
        return false;
    }

    // Zigbee channels range from 11 to 26 (2.4 GHz)
    static bool isValidChannel(int channel) {
        return channel >= 11 && channel <= 26;
    }
};

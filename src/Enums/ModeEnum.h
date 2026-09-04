#pragma once

#include <map>
#include <string>
#include <vector>
#include <algorithm>

enum class ModeEnum {
    None = -1,
    WiFi,
    Zigbee,
    COUNT
};

class ModeEnumMapper {
public:
    inline static const std::map<ModeEnum, std::string> map = {
        {ModeEnum::None,       "EXPANDER"},
        {ModeEnum::WiFi,       "WIFI (EXP)"},
        {ModeEnum::Zigbee,     "ZIGBEE"},

    };

    static std::string toString(ModeEnum proto) {

        auto it = map.find(proto);
        return it != map.end() ? it->second : "Unknown Protocol";
    }

    static std::vector<ModeEnum> getProtocols() {
        std::vector<ModeEnum> out;
        for (auto& kv : map) {
            if (kv.first != ModeEnum::None)
                out.push_back(kv.first);
        }
        return out;
    }

    static std::vector<std::string> getProtocolNames(const std::vector<ModeEnum>& protocols) {
        std::vector<std::string> names;
        for (const auto& proto : protocols) {
            names.push_back(toString(proto));
        }
        return names;
    }

    static std::string toUpper(std::string s) {
        for (char& c : s) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return s;
    }

    static ModeEnum fromString(const std::string& name) {
        std::string upper = toUpper(name);
        if (upper == "WIFI" || upper == "WIFI (EXP)" || upper == "C5 WIFI") return ModeEnum::WiFi;
        if (upper == "ZIGBEE") return ModeEnum::Zigbee;
        return ModeEnum::None;
    }
};

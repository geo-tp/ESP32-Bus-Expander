#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include "Enums/ModeEnum.h"
#include <array>

class GlobalState {
private:
    // Mode
    ModeEnum currentMode = ModeEnum::None;

    // Version
    const std::string version = "0.2";

    // NVS
    std::string nvsNamespace = "wifi_settings";
    std::string nvsSsidField = "ssid";
    std::string nvsPasswordField = "pass";

    // WiFi AP
    std::string apName = "ESP32BusExpanderAP";
    std::string apPassword = "expandthebuspirate";

public:
    GlobalState() = default;        
    GlobalState(const GlobalState&) = delete;
    GlobalState& operator=(const GlobalState&) = delete;

    static GlobalState& getInstance() {
        static GlobalState instance;
        return instance;
    }

    // Version
    const std::string& getVersion() const { return version; }

    // AP WiFi
    const std::string& getApName() const { return apName; }
    const std::string& getApPassword() const { return apPassword; }

    void setApName(const std::string& name) { apName = name; }
    void setApPassword(const std::string& pass) { apPassword = pass; }

    // Current Mode
    ModeEnum getCurrentMode() const { return currentMode; }
    void setCurrentMode(ModeEnum mode) { currentMode = mode; }

    // NVS
    const std::string& getNvsNamespace() const { return nvsNamespace; }
    const std::string& getNvsSsidField() const { return nvsSsidField; }
    const std::string& getNvsPasswordField() const { return nvsPasswordField; }
};

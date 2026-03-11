#pragma once
#include <string>
#include <vector>
#include <freertos/FreeRTOS.h>

enum phy_interface_t {
    phy_none,
    phy_wifi,
    phy_eth
};

enum ping_rc_t {
    ping_ok,
    ping_timeout,
    ping_resolve_fail,
    ping_session_fail,
    ping_error
};

class ICMPService {
public:
    ICMPService();
    ~ICMPService();

    // Normal ping
    void startPingTask(const std::string& host, int count = 5, int timeout_ms = 1000, int interval_ms = 200);
    // Discovery of devices
    void startDiscoveryTask(const std::string deviceIP, int timeout_ms = 200);
    static void discoveryTask(void* params);

    // Results
    bool isPingReady() const { return pingReady; }
    ping_rc_t lastRc() const { return pingRC; }
    int lastMedianMs() const { return pingMedianMs; }
    int lastSent() const { return pingTX; }
    int lastRecv() const { return pingRX; }
    const std::string& getReport() const { return report; }
    std::string getPingHelp() const;
    bool isDiscoveryReady() const { return discoveryReady; }

    // Task entry
    static void pingAPI(void *pvParams);

    // Responsive ICMP logging
    std::vector<std::string> fetchICMPLog();
    static void clearICMPLogging();
    static void stopICMPService();
    void clearDiscoveryFlag() { discoveryReady = false; }

private:
    bool pingReady = false;
    int  pingMedianMs = -1;
    int  pingTX = 0;
    int  pingRX = 0;
    std::string report;
    ping_rc_t pingRC = ping_rc_t::ping_error;
    bool discoveryReady = false;

    // Log buffer thread safe
    static portMUX_TYPE icmpMux;
    static std::vector<std::string> icmpLog;
    static constexpr size_t ICMP_LOG_MAX = 200;
    static bool stopICMPFlag;

    static void pushICMPLog(const std::string& line);
    static bool getICMPServiceStatus();
    // Clears non-static variables
    void cleanupICMPService();
};

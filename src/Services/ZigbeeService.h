#pragma once

#include "Interfaces/IZigbeeService.h"

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
#include <deque>
#include <memory>

// Endpoint classes from the Arduino Zigbee core; only forward-declared here,
// full definitions stay in ZigbeeService.cpp
class ZigbeeEP;
#endif

class ZigbeeService : public IZigbeeService {
public:
    // Members use std::unique_ptr to forward-declared endpoint classes;
    // deleting copy/move keeps those types incomplete in including TUs.
    // Construction/destruction are defined out-of-line for the same reason.
    ZigbeeService();
    ZigbeeService(const ZigbeeService&) = delete;
    ZigbeeService& operator=(const ZigbeeService&) = delete;
    ~ZigbeeService() override;

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    // Records a network event into the bounded event log. Public so the
    // file-local callback trampolines in ZigbeeService.cpp can reach it;
    // not part of IZigbeeService.
    void pushEvent_(const std::string& text);
#endif

    bool setChannel(uint8_t channel) override;
    bool setEndpoint(ZigbeeEndpointEnum endpoint) override;
    ZigbeeEndpointEnum getEndpoint() const override;
    bool start(ZigbeeRoleEnum role, uint8_t channel) override;
    void stop() override;
    bool permitJoining(uint8_t seconds) override;
    bool sendOn(bool state, uint16_t group) override;
    bool sendToggle(uint16_t group) override;
    bool sendLevel(uint8_t level, uint16_t group) override;
    bool sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group) override;
    bool setSensorTemperature(float celsius) override;
    bool setSensorHumidity(float percent) override;
    bool setOccupancyState(bool occupied) override;
    bool reportSensorValues() override;
    std::vector<std::string> takeEvents() override;
    std::vector<std::string> getBoundDeviceList() override;
    bool startScan(uint8_t duration) override;
    int16_t getScanStatus() override;
    std::vector<ZigbeeNetworkInfo> takeScanResults() override;
    bool factoryReset() override;
    ZigbeeNetworkStatus getStatus() override;
    bool isRoleSupported(ZigbeeRoleEnum role) const override;
    bool isSupported() const override;

private:
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    bool ensureStarted_();
    // Creates the endpoint object for the selected device type and registers
    // the event callbacks; returns nullptr for unsupported combinations
    ZigbeeEP* makeEndpoint_();
#endif

    bool started_ = false;
    ZigbeeRoleEnum role_ = ZigbeeRoleEnum::Coordinator;
    uint8_t channel_ = 15;
    ZigbeeEndpointEnum endpoint_ = ZigbeeEndpointEnum::None;

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    // Endpoint the running stack was actually started with (endpoint_ may
    // hold a pending change until the next start applies it)
    ZigbeeEndpointEnum activeEndpoint_ = ZigbeeEndpointEnum::None;
    // Active HA endpoint object exposed on EP 1 (any supported device type);
    // owned here, registered in the Zigbee core before begin()
    std::unique_ptr<ZigbeeEP> endpointObj_;
    // Events received from the network (hub commands, bound light reports),
    // capped to keep memory bounded
    std::deque<std::string> events_;
    // Active scan state (results live inside the Zigbee core until taken)
    bool scanning_ = false;
#endif
};

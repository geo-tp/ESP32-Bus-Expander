#pragma once

#include "Interfaces/IZigbeeService.h"

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
#include <deque>
#include <memory>
#include <map>

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
    bool permitJoining(uint8_t seconds) override;
    bool closeJoining() override;
    bool sendOn(bool state, uint16_t group) override;
    bool sendToggle(uint16_t group) override;
    bool sendLevel(uint8_t level, uint16_t group) override;
    bool sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group) override;
    bool setSensorTemperature(float celsius) override;
    bool setSensorHumidity(float percent) override;
    bool setOccupancyState(bool occupied) override;
    bool reportSensorValues() override;
    std::vector<std::string> takeEvents() override;
    std::vector<std::string> getRecentEvents() const override;
    std::vector<std::string> getBoundDeviceList() override;
    std::vector<ZigbeeNeighborInfo> getNeighborList() override;
    bool inspectDevice(uint16_t shortAddress, ZigbeeDeviceDescriptor& out, uint32_t timeoutMs = 4000) override;
    bool startScan(uint8_t duration) override;
    int16_t getScanStatus() override;
    std::vector<ZigbeeNetworkInfo> takeScanResults() override;
    bool beginSniff() override;
    bool setSniffChannel(uint8_t channel) override;
    ZigbeeSniffInfo getSniffInfo() override;
    std::vector<ZigbeeSniffFrame> takeSniffFrames() override;
    void endSniff() override;
    bool beginMonitor() override;
    std::vector<ZigbeeMonitorFrame> takeMonitorFrames() override;
    void endMonitor() override;
    ZigbeeNetworkStatus getStatus() override;
    std::string getLastError() const override;
    bool isRoleSupported(ZigbeeRoleEnum role) const override;
    bool isSupported() const override;

private:
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    bool ensureStarted_();
    void clearError_();
    bool fail_(const std::string& reason);
    // Creates the endpoint object for the selected device type and registers
    // the event callbacks; returns nullptr for unsupported combinations
    ZigbeeEP* makeEndpoint_();
#endif

    bool started_ = false;
    // Track initialization explicitly so begin() is called only once per boot
    // and role/channel/endpoint cannot be changed after the stack takes the radio.
    bool initialized_ = false;
    bool initFailed_ = false;
    ZigbeeRoleEnum role_ = ZigbeeRoleEnum::Coordinator;
    uint8_t channel_ = 15;
    uint16_t panId_ = 0;
    uint16_t shortAddress_ = 0xFFFF;
    bool permitJoining_ = false;
    uint64_t permitJoinDeadlineUs_ = 0;
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
    // Last-seen neighbor relationships let diagnostics surface joins/leaves
    // even though Arduino's global Zigbee signal handler is internal.
    std::map<uint16_t, uint8_t> observedNeighbors_;
    // Active scan state (results live inside the Zigbee core until taken)
    bool scanning_ = false;
    // Raw radio sniffer owns the 802.15.4 driver only before Zigbee.begin().
    bool sniffing_ = false;
    // APS monitor wraps Arduino's own APS handler while the stack is running.
    bool monitoring_ = false;
#endif

    std::string lastError_;
};

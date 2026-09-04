#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "Interfaces/IZigbeeService.h"

class FakeZigbeeService final : public IZigbeeService {
public:
    // Configurable results
    bool startResult = true;
    bool permitResult = true;
    bool resetResult = true;
    bool setChannelResult = true;
    bool setEndpointResult = true;
    bool sendResult = true;
    bool sensorResult = true;
    bool startScanResult = true;
    bool supportedFlag = true;
    bool coordinatorSupported = true;
    bool routerSupported = true;
    bool endDeviceSupported = true;

    // Configurable reported status
    ZigbeeNetworkStatus status;

    // Configurable device list / scan data / event log
    std::vector<std::string> boundList;
    std::vector<int16_t> scanStatusQueue; // one entry per getScanStatus() call
    std::vector<ZigbeeNetworkInfo> scanResults;
    std::vector<std::string> eventLog;

    // Recorded calls
    uint32_t startCalls = 0;
    uint32_t stopCalls = 0;
    uint32_t permitCalls = 0;
    uint32_t resetCalls = 0;
    uint32_t setChannelCalls = 0;
    uint32_t setEndpointCalls = 0;
    uint32_t sendOnCalls = 0;
    uint32_t toggleCalls = 0;
    uint32_t sendLevelCalls = 0;
    uint32_t sendColorCalls = 0;
    uint32_t setTempCalls = 0;
    uint32_t setHumCalls = 0;
    uint32_t setOccCalls = 0;
    uint32_t reportCalls = 0;
    uint32_t takeEventsCalls = 0;
    uint32_t getBoundListCalls = 0;
    uint32_t startScanCalls = 0;
    uint32_t getScanStatusCalls = 0;
    uint32_t takeScanResultsCalls = 0;

    std::vector<ZigbeeRoleEnum> startRoles;
    std::vector<uint8_t> startChannels;
    std::vector<uint8_t> permitSeconds;
    std::vector<uint8_t> channelsSet;
    std::vector<ZigbeeEndpointEnum> endpointsSet;
    std::vector<bool> onStates;
    std::vector<uint16_t> onGroups;
    std::vector<uint16_t> toggleGroups;
    std::vector<uint8_t> levelsSent;
    std::vector<uint16_t> levelGroups;
    std::vector<uint8_t> colorReds;
    std::vector<uint8_t> colorGreens;
    std::vector<uint8_t> colorBlues;
    std::vector<uint16_t> colorGroups;
    std::vector<float> tempValues;
    std::vector<float> humValues;
    std::vector<bool> occStates;
    std::vector<uint8_t> startScanDurations;

    ZigbeeEndpointEnum endpointState = ZigbeeEndpointEnum::None;

    FakeZigbeeService() { status.supported = true; }

    bool setChannel(uint8_t channel) override {
        ++setChannelCalls;
        channelsSet.push_back(channel);
        if (setChannelResult) status.channel = channel;
        return setChannelResult;
    }

    bool setEndpoint(ZigbeeEndpointEnum endpoint) override {
        ++setEndpointCalls;
        endpointsSet.push_back(endpoint);
        if (setEndpointResult) endpointState = endpoint;
        return setEndpointResult;
    }

    ZigbeeEndpointEnum getEndpoint() const override { return endpointState; }

    bool start(ZigbeeRoleEnum role, uint8_t channel) override {
        ++startCalls;
        startRoles.push_back(role);
        startChannels.push_back(channel);
        if (startResult) {
            status.started = true;
            status.role = role;
            status.channel = channel;
        }
        return startResult;
    }

    void stop() override {
        ++stopCalls;
        status.started = false;
        status.connected = false;
    }

    bool permitJoining(uint8_t seconds) override {
        ++permitCalls;
        permitSeconds.push_back(seconds);
        return permitResult;
    }

    bool sendOn(bool state, uint16_t group) override {
        ++sendOnCalls;
        onStates.push_back(state);
        onGroups.push_back(group);
        return sendResult;
    }

    bool sendToggle(uint16_t group) override {
        ++toggleCalls;
        toggleGroups.push_back(group);
        return sendResult;
    }

    bool sendLevel(uint8_t level, uint16_t group) override {
        ++sendLevelCalls;
        levelsSent.push_back(level);
        levelGroups.push_back(group);
        return sendResult;
    }

    bool sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group) override {
        ++sendColorCalls;
        colorReds.push_back(red);
        colorGreens.push_back(green);
        colorBlues.push_back(blue);
        colorGroups.push_back(group);
        return sendResult;
    }

    bool setSensorTemperature(float celsius) override {
        ++setTempCalls;
        tempValues.push_back(celsius);
        return sensorResult;
    }

    bool setSensorHumidity(float percent) override {
        ++setHumCalls;
        humValues.push_back(percent);
        return sensorResult;
    }

    bool setOccupancyState(bool occupied) override {
        ++setOccCalls;
        occStates.push_back(occupied);
        return sensorResult;
    }

    bool reportSensorValues() override {
        ++reportCalls;
        return sensorResult;
    }

    std::vector<std::string> takeEvents() override {
        ++takeEventsCalls;
        std::vector<std::string> drained = std::move(eventLog);
        eventLog.clear();
        return drained;
    }

    std::vector<std::string> getBoundDeviceList() override {
        ++getBoundListCalls;
        return boundList;
    }

    bool startScan(uint8_t duration) override {
        ++startScanCalls;
        startScanDurations.push_back(duration);
        return startScanResult;
    }

    int16_t getScanStatus() override {
        ++getScanStatusCalls;
        if (scanStatusQueue.empty()) return -1;
        const int16_t value = scanStatusQueue.front();
        scanStatusQueue.erase(scanStatusQueue.begin());
        return value;
    }

    std::vector<ZigbeeNetworkInfo> takeScanResults() override {
        ++takeScanResultsCalls;
        return scanResults;
    }

    bool factoryReset() override {
        ++resetCalls;
        return resetResult;
    }

    ZigbeeNetworkStatus getStatus() override { return status; }

    bool isRoleSupported(ZigbeeRoleEnum role) const override {
        if (!supportedFlag) return false;
        if (role == ZigbeeRoleEnum::Coordinator) return coordinatorSupported;
        if (role == ZigbeeRoleEnum::Router) return routerSupported;
        return endDeviceSupported;
    }

    bool isSupported() const override { return supportedFlag; }
};

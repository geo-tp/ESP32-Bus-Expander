#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Interfaces/IZigbeeService.h"
#include "Transformers/ArgTransformer.h"

class ZigbeeTransformer {
public:
    explicit ZigbeeTransformer(ArgTransformer& argTransformer);

    std::string endpointToString(ZigbeeEndpointEnum endpoint) const;
    bool endpointFromString(const std::string& name, ZigbeeEndpointEnum& endpoint) const;
    std::string endpointConfiguredMessage(ZigbeeEndpointEnum endpoint) const;

    std::string neighborTypeToString(uint8_t type) const;
    std::string relationshipToString(uint8_t relationship) const;
    std::string deviceHintToString(const ZigbeeNeighborInfo& device) const;
    uint16_t channelFrequencyMHz(uint8_t channel) const;
    std::string clusterToString(uint16_t cluster) const;
    std::string zclCommandToString(uint16_t cluster, uint8_t frameType, uint8_t command) const;

    void hsvToRgb(int h, int s, int v, uint8_t& r, uint8_t& g, uint8_t& b) const;

    std::vector<std::string> quickStartLines() const;
    std::vector<std::string> helpLines() const;
    std::vector<std::string> runtimeStatusLines(
        const ZigbeeNetworkStatus& status,
        ZigbeeEndpointEnum endpoint,
        const std::vector<ZigbeeNeighborInfo>& devices,
        const std::vector<std::string>& recent,
        const std::string& lastError,
        bool showHeader = true
    ) const;
    std::vector<std::string> deviceTableLines(const std::vector<ZigbeeNeighborInfo>& devices) const;
    std::vector<std::string> deviceSelectionLines(const std::vector<ZigbeeNeighborInfo>& devices) const;
    std::vector<std::string> networkLines(const ZigbeeNetworkInfo& network) const;
    std::vector<std::string> newDeviceLines(const ZigbeeNeighborInfo& device) const;
    std::vector<std::string> deviceDescriptorLines(const ZigbeeDeviceDescriptor& info) const;
    std::vector<std::string> monitorFrameLines(const ZigbeeMonitorFrame& frame) const;
    std::vector<std::string> sniffInfoLines(const ZigbeeSniffInfo& info, bool compact = false) const;
    std::vector<std::string> sniffFrameLines(const ZigbeeSniffFrame& frame) const;

private:
    ArgTransformer& argTransformer;
};

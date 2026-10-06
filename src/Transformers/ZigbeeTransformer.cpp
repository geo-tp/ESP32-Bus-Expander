#include "ZigbeeTransformer.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

ZigbeeTransformer::ZigbeeTransformer(ArgTransformer& argTransformer)
    : argTransformer(argTransformer) {}

std::string ZigbeeTransformer::endpointToString(ZigbeeEndpointEnum endpoint) const {
    switch (endpoint) {
        case ZigbeeEndpointEnum::Light:           return "LIGHT";
        case ZigbeeEndpointEnum::DimmableLight:   return "DIMMABLE_LIGHT";
        case ZigbeeEndpointEnum::ColorLight:      return "COLOR_LIGHT";
        case ZigbeeEndpointEnum::Switch:          return "SWITCH";
        case ZigbeeEndpointEnum::TempSensor:      return "TEMP_SENSOR";
        case ZigbeeEndpointEnum::OccupancySensor: return "OCCUPANCY_SENSOR";
        case ZigbeeEndpointEnum::Fan:             return "FAN";
        case ZigbeeEndpointEnum::Outlet:          return "OUTLET";
        case ZigbeeEndpointEnum::RangeExtender:   return "RANGE_EXTENDER";
        default:                                  return "NONE";
    }
}

bool ZigbeeTransformer::endpointFromString(const std::string& name, ZigbeeEndpointEnum& endpoint) const {
    if (name == "light") endpoint = ZigbeeEndpointEnum::Light;
    else if (name == "dimlight" || name == "dimmer") endpoint = ZigbeeEndpointEnum::DimmableLight;
    else if (name == "colorlight" || name == "color") endpoint = ZigbeeEndpointEnum::ColorLight;
    else if (name == "switch") endpoint = ZigbeeEndpointEnum::Switch;
    else if (name == "tempsensor" || name == "temp") endpoint = ZigbeeEndpointEnum::TempSensor;
    else if (name == "occupancy" || name == "occ") endpoint = ZigbeeEndpointEnum::OccupancySensor;
    else if (name == "fan") endpoint = ZigbeeEndpointEnum::Fan;
    else if (name == "outlet" || name == "plug") endpoint = ZigbeeEndpointEnum::Outlet;
    else if (name == "rangeextender" || name == "repeater") endpoint = ZigbeeEndpointEnum::RangeExtender;
    else if (name == "none") endpoint = ZigbeeEndpointEnum::None;
    else return false;
    return true;
}

std::string ZigbeeTransformer::endpointConfiguredMessage(ZigbeeEndpointEnum endpoint) const {
    switch (endpoint) {
        case ZigbeeEndpointEnum::Light:           return "Tool will act as On/Off Light after 'start'.";
        case ZigbeeEndpointEnum::DimmableLight:   return "Tool will act as Dimmable Light after 'start'.";
        case ZigbeeEndpointEnum::ColorLight:      return "Tool will act as Color Dimmable Light after 'start'.";
        case ZigbeeEndpointEnum::Switch:          return "Tool will act as On/Off Switch after 'start'.";
        case ZigbeeEndpointEnum::TempSensor:      return "Tool will act as Temperature/Humidity Sensor after 'start'.";
        case ZigbeeEndpointEnum::OccupancySensor: return "Tool will act as Occupancy Sensor after 'start'.";
        case ZigbeeEndpointEnum::Fan:             return "Tool will act as Fan Control after 'start'.";
        case ZigbeeEndpointEnum::Outlet:          return "Tool will act as Power Outlet after 'start'.";
        case ZigbeeEndpointEnum::RangeExtender:   return "Tool will act as Range Extender after 'start'.";
        default:                                  return "Tool will expose no endpoint.";
    }
}

std::string ZigbeeTransformer::neighborTypeToString(uint8_t type) const {
    switch (type) {
        case 0: return "coordinator";
        case 1: return "router";
        case 2: return "end-device";
        default: return "unknown(" + std::to_string(type) + ")";
    }
}

std::string ZigbeeTransformer::relationshipToString(uint8_t relationship) const {
    switch (relationship) {
        case 0: return "parent";
        case 1: return "child";
        case 2: return "sibling";
        case 3: return "unknown";
        case 4: return "prev-child";
        case 5: return "joining";
        default: return "rel(" + std::to_string(relationship) + ")";
    }
}

std::string ZigbeeTransformer::deviceHintToString(const ZigbeeNeighborInfo& device) const {
    if (device.relationship == 5) return "PAIRING/JOINING";
    if (device.deviceType == 2) {
        return device.rxOnWhenIdle ? "end-device / always-on" : "sleepy / sensor-like";
    }
    if (device.deviceType == 1) return "mains/router likely";
    if (device.deviceType == 0) return "coordinator";
    return device.rxOnWhenIdle ? "RX on when idle" : "RX off when idle";
}

uint16_t ZigbeeTransformer::channelFrequencyMHz(uint8_t channel) const {
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) return 0;
    return static_cast<uint16_t>(2405 + (channel - 11) * 5);
}

std::string ZigbeeTransformer::clusterToString(uint16_t cluster) const {
    switch (cluster) {
        case 0x0000: return "Basic";
        case 0x0001: return "Power Config";
        case 0x0003: return "Identify";
        case 0x0004: return "Groups";
        case 0x0005: return "Scenes";
        case 0x0006: return "On/Off";
        case 0x0008: return "Level Control";
        case 0x0019: return "OTA Upgrade";
        case 0x0020: return "Poll Control";
        case 0x0300: return "Color Control";
        case 0x0400: return "Illuminance";
        case 0x0402: return "Temperature";
        case 0x0403: return "Pressure";
        case 0x0405: return "Humidity";
        case 0x0406: return "Occupancy";
        case 0x0500: return "IAS Zone";
        case 0x0702: return "Metering";
        case 0x0B04: return "Electrical";
        case 0x0B05: return "Diagnostics";
        default: return "";
    }
}

std::string ZigbeeTransformer::zclCommandToString(uint16_t cluster, uint8_t frameType, uint8_t command) const {
    if (frameType == 0) {
        switch (command) {
            case 0x00: return "Read Attributes";
            case 0x01: return "Read Attributes Response";
            case 0x02: return "Write Attributes";
            case 0x04: return "Write Attributes Response";
            case 0x06: return "Configure Reporting";
            case 0x07: return "Configure Reporting Response";
            case 0x0A: return "Report Attributes";
            case 0x0B: return "Default Response";
            case 0x0C: return "Discover Attributes";
            case 0x0D: return "Discover Attributes Response";
            default: return "";
        }
    }
    if (cluster == 0x0006) {
        switch (command) {
            case 0x00: return "Off";
            case 0x01: return "On";
            case 0x02: return "Toggle";
            default: break;
        }
    } else if (cluster == 0x0008) {
        switch (command) {
            case 0x00: return "Move to Level";
            case 0x01: return "Move";
            case 0x02: return "Step";
            case 0x03: return "Stop";
            case 0x04: return "Move to Level + On/Off";
            case 0x05: return "Move + On/Off";
            case 0x06: return "Step + On/Off";
            case 0x07: return "Stop + On/Off";
            default: break;
        }
    } else if (cluster == 0x0005) {
        switch (command) {
            case 0x00: return "Add Scene";
            case 0x01: return "View Scene";
            case 0x02: return "Remove Scene";
            case 0x03: return "Remove All Scenes";
            case 0x04: return "Store Scene";
            case 0x05: return "Recall Scene";
            case 0x06: return "Scene Membership";
            default: break;
        }
    } else if (cluster == 0x0500 && command == 0x00) {
        return "Zone Status Change";
    }
    return "";
}

void ZigbeeTransformer::hsvToRgb(int h, int s, int v, uint8_t& r, uint8_t& g, uint8_t& b) const {
    const float sat = s / 255.0f;
    const float val = v / 255.0f;
    const float c = val * sat;
    const float hp = (h % 360) / 60.0f;
    const float x = c * (1.0f - std::fabs(std::fmod(hp, 2.0f) - 1.0f));
    float rf = 0, gf = 0, bf = 0;
    if (hp < 1)      { rf = c; gf = x; }
    else if (hp < 2) { rf = x; gf = c; }
    else if (hp < 3) { gf = c; bf = x; }
    else if (hp < 4) { gf = x; bf = c; }
    else if (hp < 5) { rf = x; bf = c; }
    else             { rf = c; bf = x; }
    const float m = val - c;
    r = static_cast<uint8_t>((rf + m) * 255.0f + 0.5f);
    g = static_cast<uint8_t>((gf + m) * 255.0f + 0.5f);
    b = static_cast<uint8_t>((bf + m) * 255.0f + 0.5f);
}

std::vector<std::string> ZigbeeTransformer::quickStartLines() const {
    std::vector<std::string> out;
    out.push_back("");
    out.push_back("Zigbee mode - IEEE 802.15.4 / 2.4 GHz.");
    out.push_back("Quick start:");
    out.push_back("  sniff   - Raw / live traffic");
#if defined(ZIGBEE_MODE_ED)
    out.push_back("  device <type>          Select endpoint");
    out.push_back("  start   - Choose channel / join");
#else
    out.push_back("  start   - Choose role/channel");
    out.push_back("  scan   or   pair");
#endif
    out.push_back("Use 'status' for network diagnostics.");
    out.push_back("Type 'help' for commands.\n");
    return out;
}

std::vector<std::string> ZigbeeTransformer::helpLines() const {
    std::vector<std::string> out;
    out.push_back("");
    out.push_back("Zigbee commands");
    out.push_back("");
    out.push_back("  sniff [ch]          Raw / live traffic");
#if defined(ZIGBEE_MODE_ED)
    out.push_back("  start [ch]          Start/join network");
#else
    out.push_back("  start [role] [ch]   Start network");
    out.push_back("    coordinator | router");
#endif
    out.push_back("  monitor             Live paired traffic");
    out.push_back("  scan [1-30]         Find PANs/devices");
    out.push_back("  status              Network/status");
    out.push_back("  setchannel <11-26>  Channel pre-start");
    out.push_back("  events              Event log");
    out.push_back("  reboot              Restart the expander");
#if defined(ZIGBEE_MODE_ZCZR)
    out.push_back("  pair [5-255]        Pair one device");
    out.push_back("  permit <sec|off>    Join window duration");
    out.push_back("  devices             List paired devices");
#elif defined(ZIGBEE_MODE_ED)
    out.push_back("");
    out.push_back("Device:");
    out.push_back("  device <type>       Select endpoint");
    out.push_back("    none | light | dimlight");
    out.push_back("    colorlight | switch | tempsensor");
    out.push_back("    occupancy | fan | outlet");
    out.push_back("    rangeextender");
    out.push_back("  bindings            Bound devices");
    out.push_back("  on|off|toggle [g]   Light control");
    out.push_back("  dim <value> [g]     Brightness");
    out.push_back("  color rgb|hsv ...   Color");
    out.push_back("  settemp <C>         Fake temperature");
    out.push_back("  sethum <%>          Fake humidity");
    out.push_back("  setocc <0|1>        Fake occupancy");
    out.push_back("  report              Send sensor report");
#endif
    out.push_back("");
    out.push_back("Type 'exit' to return to Bit Pirate.");
    out.push_back("");
    return out;
}

std::vector<std::string> ZigbeeTransformer::runtimeStatusLines(
    const ZigbeeNetworkStatus& status,
    ZigbeeEndpointEnum endpoint,
    const std::vector<ZigbeeNeighborInfo>& devices,
    const std::vector<std::string>& recent,
    const std::string& lastError,
    bool showHeader
) const {
    std::vector<std::string> out;
    if (showHeader) out.push_back("=== Zigbee status ===");
    out.push_back(std::string("Radio    : ") + (status.supported ? "802.15.4 supported" : "unsupported"));
    const char* stackState = status.initFailed ? "ERROR / REBOOT REQUIRED"
        : (status.started ? "RUNNING" : (status.initialized ? "INITIALIZED" : "NOT INITIALIZED"));
    out.push_back(std::string("Stack    : ") + stackState);
#if defined(ZIGBEE_MODE_ED)
    out.push_back("Build    : ENDDEVICE");
#else
    out.push_back("Build    : COORDINATOR / ROUTER");
#endif
    out.push_back("Role     : " + ZigbeeRoleEnumMapper::toString(status.role));
    out.push_back("Channel  : " + std::to_string(status.channel) + " / "
                  + std::to_string(channelFrequencyMHz(status.channel)) + " MHz");
#if defined(ZIGBEE_MODE_ED)
    out.push_back("Endpoint : " + endpointToString(endpoint));
#else
    (void)endpoint;
#endif
    out.push_back(std::string("Lock     : ") + (status.initialized ? "yes" : "no"));

    std::string networkState;
    if (!status.started) networkState = status.initialized ? "initialized / inactive" : "not started";
    else if (status.role == ZigbeeRoleEnum::Coordinator) networkState = status.connected ? "formed / active" : "forming";
    else networkState = status.connected ? "joined" : "not joined";
    out.push_back("Network  : " + networkState);

    if (status.started) {
        if (status.panId != 0) out.push_back("PAN      : 0x" + argTransformer.toHex(status.panId, 4));
        if (status.shortAddress != 0xFFFF) out.push_back("Address  : 0x" + argTransformer.toHex(status.shortAddress, 4));
        if (status.role != ZigbeeRoleEnum::EndDevice) {
            out.push_back(std::string("Joining  : ")
                + (status.permitJoining
                    ? ("OPEN ~" + std::to_string(status.permitJoinSecondsRemaining) + "s")
                    : "closed"));
        }

        size_t joining = 0;
        size_t sleepy = 0;
        int strongest = -128;
        int weakest = 0;
        bool haveSignal = false;
        for (const auto& dev : devices) {
            if (dev.relationship == 5) ++joining;
            if (dev.deviceType == 2 && !dev.rxOnWhenIdle) ++sleepy;
            if (dev.rssi <= 0 && dev.rssi > -128) {
                if (!haveSignal || dev.rssi > strongest) strongest = dev.rssi;
                if (!haveSignal || dev.rssi < weakest) weakest = dev.rssi;
                haveSignal = true;
            }
        }
        out.push_back("Devices  : " + std::to_string(devices.size())
                      + " | joining " + std::to_string(joining)
                      + " | sleepy " + std::to_string(sleepy));
        if (haveSignal) {
            out.push_back("Signal   : " + std::to_string(weakest)
                          + ".." + std::to_string(strongest) + " dBm");
        } else if (!devices.empty()) {
            out.push_back("Signal   : n/a");
        }
    }

    if (!recent.empty()) {
        out.push_back("Recent:");
        const size_t first = recent.size() > 3 ? recent.size() - 3 : 0;
        for (size_t i = first; i < recent.size(); ++i) out.push_back("  " + recent[i]);
    }
    if (!lastError.empty()) out.push_back("Last err : " + lastError);
    return out;
}

std::vector<std::string> ZigbeeTransformer::deviceTableLines(const std::vector<ZigbeeNeighborInfo>& devices) const {
    std::vector<std::string> out;
    if (devices.empty()) {
        out.push_back("  No Zigbee neighbor/device known.\n");
        return out;
    }
    for (const auto& device : devices) {
        out.push_back("  [0x" + argTransformer.toHex(device.shortAddress, 4) + "] "
                      + neighborTypeToString(device.deviceType) + " / "
                      + relationshipToString(device.relationship));
        std::string signal = "    Signal : LQI " + std::to_string(device.lqi) + " | RSSI ";
        signal += (device.rssi <= 0 && device.rssi > -128)
            ? (std::to_string(device.rssi) + " dBm") : "n/a";
        out.push_back(signal);
        out.push_back("    Mode   : " + deviceHintToString(device));
        out.push_back("    Depth  : " + std::to_string(device.depth));
        out.push_back("    IEEE   : " + device.ieeeAddress);
    }
    return out;
}

std::vector<std::string> ZigbeeTransformer::deviceSelectionLines(const std::vector<ZigbeeNeighborInfo>& devices) const {
    std::vector<std::string> out;
    for (size_t i = 0; i < devices.size(); ++i) {
        const auto& device = devices[i];
        out.push_back("  [" + std::to_string(i + 1) + "] 0x"
                      + argTransformer.toHex(device.shortAddress, 4) + " "
                      + neighborTypeToString(device.deviceType));
        std::string signal = "      LQI " + std::to_string(device.lqi) + " | RSSI ";
        signal += (device.rssi <= 0 && device.rssi > -128)
            ? (std::to_string(device.rssi) + " dBm") : "n/a";
        out.push_back(signal);
    }
    return out;
}

std::vector<std::string> ZigbeeTransformer::networkLines(const ZigbeeNetworkInfo& network) const {
    return {
        "  PAN  : 0x" + argTransformer.toHex(network.panId, 4),
        "  CH   : " + std::to_string(network.channel) + " / "
            + std::to_string(channelFrequencyMHz(network.channel)) + " MHz",
        std::string("  Join : ") + (network.permitJoining ? "open" : "closed")
            + " | Router " + (network.routerCapacity ? "yes" : "no")
            + " | End-dev " + (network.endDeviceCapacity ? "yes" : "no"),
        "  EXT  : " + network.extendedPanId,
        ""
    };
}

std::vector<std::string> ZigbeeTransformer::newDeviceLines(const ZigbeeNeighborInfo& device) const {
    std::vector<std::string> out;
    out.push_back("[DEVICE] 0x" + argTransformer.toHex(device.shortAddress, 4)
                  + " " + neighborTypeToString(device.deviceType)
                  + " / " + relationshipToString(device.relationship));
    std::string signal = "  Signal: LQI " + std::to_string(device.lqi) + " | RSSI ";
    signal += (device.rssi <= 0 && device.rssi > -128)
        ? (std::to_string(device.rssi) + " dBm") : "n/a";
    out.push_back(signal);
    out.push_back("  Mode  : " + deviceHintToString(device));
    out.push_back("  IEEE  : " + device.ieeeAddress);
    return out;
}

std::vector<std::string> ZigbeeTransformer::deviceDescriptorLines(const ZigbeeDeviceDescriptor& info) const {
    std::vector<std::string> out;
    out.push_back("Device 0x" + argTransformer.toHex(info.shortAddress, 4));
    out.push_back("Endpoints: " + std::to_string(info.endpoints.size()));
    for (const auto& ep : info.endpoints) {
        out.push_back("");
        out.push_back("EP " + std::to_string(ep.endpoint));
        out.push_back("  Profile : 0x" + argTransformer.toHex(ep.profileId, 4));
        out.push_back("  Device  : 0x" + argTransformer.toHex(ep.deviceId, 4)
                      + " v" + std::to_string(ep.deviceVersion));
        if (!ep.inputClusters.empty()) {
            out.push_back("  Input clusters:");
            for (uint16_t cluster : ep.inputClusters) {
                const std::string name = clusterToString(cluster);
                out.push_back("    0x" + argTransformer.toHex(cluster, 4)
                              + (name.empty() ? "" : (" " + name)));
            }
        }
        if (!ep.outputClusters.empty()) {
            out.push_back("  Output clusters:");
            for (uint16_t cluster : ep.outputClusters) {
                const std::string name = clusterToString(cluster);
                out.push_back("    0x" + argTransformer.toHex(cluster, 4)
                              + (name.empty() ? "" : (" " + name)));
            }
        }
    }
    return out;
}

std::vector<std::string> ZigbeeTransformer::monitorFrameLines(const ZigbeeMonitorFrame& frame) const {
    std::vector<std::string> out;
    out.push_back("[RX] 0x" + argTransformer.toHex(frame.source, 4)
                  + " -> 0x" + argTransformer.toHex(frame.destination, 4));
    out.push_back("  EP    : " + std::to_string(frame.sourceEndpoint)
                  + " -> " + std::to_string(frame.destinationEndpoint));
    const std::string clusterName = clusterToString(frame.clusterId);
    out.push_back("  Clust : 0x" + argTransformer.toHex(frame.clusterId, 4)
                  + (clusterName.empty() ? "" : (" " + clusterName)));
    out.push_back("  Prof  : 0x" + argTransformer.toHex(frame.profileId, 4)
                  + " | LQI " + std::to_string(frame.lqi));

    const auto& p = frame.payload;
    size_t off = 0;
    bool parsedZcl = false;
    uint8_t frameType = 0;
    uint8_t command = 0;
    if (frame.profileId != 0x0000 && p.size() >= 3) {
        const uint8_t fc = p[off++];
        frameType = static_cast<uint8_t>(fc & 0x03);
        const bool manufacturer = (fc & 0x04) != 0;
        if (manufacturer) {
            if (p.size() < off + 2 + 2) off = p.size();
            else off += 2;
        }
        if (off + 2 <= p.size()) {
            const uint8_t sequence = p[off++];
            command = p[off++];
            const std::string commandName = zclCommandToString(frame.clusterId, frameType, command);
            out.push_back("  ZCL   : 0x" + argTransformer.toHex(command, 2)
                          + (commandName.empty() ? "" : (" " + commandName))
                          + " | seq " + std::to_string(sequence));
            parsedZcl = true;
        }
    }

    if (parsedZcl && frameType == 0 && command == 0x0A && off + 3 <= p.size()) {
        const uint16_t attr = static_cast<uint16_t>(p[off])
            | (static_cast<uint16_t>(p[off + 1]) << 8);
        const uint8_t type = p[off + 2];
        const size_t valueOff = off + 3;
        if (frame.clusterId == 0x0402 && attr == 0x0000 && type == 0x29 && valueOff + 2 <= p.size()) {
            const int16_t raw = static_cast<int16_t>(static_cast<uint16_t>(p[valueOff])
                | (static_cast<uint16_t>(p[valueOff + 1]) << 8));
            std::ostringstream value;
            value << std::fixed << std::setprecision(2) << (raw / 100.0f) << " C";
            out.push_back("  Value : " + value.str());
        } else if (frame.clusterId == 0x0405 && attr == 0x0000 && type == 0x21 && valueOff + 2 <= p.size()) {
            const uint16_t raw = static_cast<uint16_t>(p[valueOff])
                | (static_cast<uint16_t>(p[valueOff + 1]) << 8);
            std::ostringstream value;
            value << std::fixed << std::setprecision(2) << (raw / 100.0f) << " %RH";
            out.push_back("  Value : " + value.str());
        } else if (frame.clusterId == 0x0406 && attr == 0x0000 && valueOff < p.size()) {
            out.push_back(std::string("  Value : occupancy ") + (p[valueOff] ? "ON" : "OFF"));
        } else if (frame.clusterId == 0x0001 && attr == 0x0021 && valueOff < p.size()) {
            std::ostringstream value;
            value << std::fixed << std::setprecision(1) << (p[valueOff] / 2.0f) << " % battery";
            out.push_back("  Value : " + value.str());
        }
    }

    if (!p.empty()) {
        std::string raw = "  Raw   :";
        const size_t shown = std::min<size_t>(p.size(), 20);
        for (size_t i = 0; i < shown; ++i) raw += " " + argTransformer.toHex(p[i], 2);
        if (p.size() > shown) raw += " ...";
        out.push_back(raw);
    }
    out.push_back("");
    return out;
}

std::vector<std::string> ZigbeeTransformer::sniffInfoLines(const ZigbeeSniffInfo& info, bool compact) const {
    std::vector<std::string> out;
    if (compact) {
        out.push_back("CH" + std::to_string(info.channel) + " / "
                      + std::to_string(channelFrequencyMHz(info.channel)) + " MHz"
                      + " | PHY " + std::to_string(info.phyHits)
                      + " | valid " + std::to_string(info.frames));
        if (info.frames > 0) {
            out.push_back("  Signal: " + std::to_string(info.averageRssi)
                          + " avg | " + std::to_string(info.strongestRssi) + " peak dBm");
        }
        if (info.probableZigbeeBeacons || info.probableZigbeeNwkFrames) {
            out.push_back("  Zigbee?: beacon " + std::to_string(info.probableZigbeeBeacons)
                          + " | NWK " + std::to_string(info.probableZigbeeNwkFrames));
            if (info.hasLastNwkAddresses) {
                out.push_back("  NWK   : 0x" + argTransformer.toHex(info.lastNwkSource, 4)
                              + " -> 0x" + argTransformer.toHex(info.lastNwkDestination, 4));
            }
        }
        if (info.associationRequests || info.associationResponses || info.beaconRequests
            || info.orphanNotifications || info.zigbeeRejoinRequests || info.zigbeeRejoinResponses) {
            out.push_back("  Join? : assoc " + std::to_string(info.associationRequests)
                          + "/" + std::to_string(info.associationResponses)
                          + " | beacon " + std::to_string(info.beaconRequests));
            if (info.zigbeeRejoinRequests || info.zigbeeRejoinResponses || info.orphanNotifications) {
                out.push_back("          rejoin " + std::to_string(info.zigbeeRejoinRequests)
                              + "/" + std::to_string(info.zigbeeRejoinResponses)
                              + " | orphan " + std::to_string(info.orphanNotifications));
            }
        }
        if (!info.panIds.empty()) {
            std::string line = "  PAN   :";
            for (const uint16_t pan : info.panIds) {
                const std::string token = " 0x" + argTransformer.toHex(pan, 4);
                if (line.size() + token.size() > 42) {
                    out.push_back(line);
                    line = "          " + token.substr(1);
                } else {
                    line += token;
                }
            }
            out.push_back(line);
        }
        for (const auto& ieee : info.joiningIeeeAddresses) out.push_back("  IEEE? : " + ieee);
        return out;
    }

    out.push_back("CH" + std::to_string(info.channel) + " / "
                  + std::to_string(channelFrequencyMHz(info.channel)) + " MHz");
    out.push_back("  PHY    : " + std::to_string(info.phyHits));
    out.push_back("  Valid  : " + std::to_string(info.frames));
    if (info.frames == 0) return out;
    out.push_back("  Signal : " + std::to_string(info.averageRssi)
                  + " avg | " + std::to_string(info.strongestRssi) + " peak dBm");
    out.push_back("  LQI    : " + std::to_string(info.averageLqi)
                  + " avg | " + std::to_string(info.strongestLqi) + " peak");
    out.push_back("  Zigbee?: beacon " + std::to_string(info.probableZigbeeBeacons)
                  + " | NWK " + std::to_string(info.probableZigbeeNwkFrames)
                  + " | cmd " + std::to_string(info.probableZigbeeNwkCommands));
    return out;
}

std::vector<std::string> ZigbeeTransformer::sniffFrameLines(const ZigbeeSniffFrame& frame) const {
    std::vector<std::string> out;
    const bool joinMac = frame.hasMacCommand
        && (frame.macCommandId == 0x01 || frame.macCommandId == 0x02
            || frame.macCommandId == 0x06 || frame.macCommandId == 0x07);
    const bool zigbeeLike = frame.probableZigbeeBeacon || frame.probableZigbeeNwk
        || frame.probableZigbeeInterPan;

    const std::string tag = zigbeeLike ? "[ZIGBEE?]" : (joinMac ? "[JOIN?]" : "[802.15.4]");
    out.push_back(tag + " CH" + std::to_string(frame.channel)
                  + " / " + std::to_string(channelFrequencyMHz(frame.channel)) + " MHz"
                  + (frame.rssi > -128 ? (" | " + std::to_string(frame.rssi) + " dBm") : ""));

    if (frame.probableZigbeeInterPan) out.push_back("  Type  : Zigbee Inter-PAN");
    else if (frame.probableZigbeeBeacon) out.push_back("  Type  : Zigbee beacon");
    else if (frame.probableZigbeeNwk) out.push_back(std::string("  Type  : Zigbee NWK ") + (frame.nwkCommand ? "command" : "data"));
    else {
        const char* macType = frame.macType == 0 ? "Beacon"
            : (frame.macType == 1 ? "Data" : (frame.macType == 3 ? "MAC command" : "Other"));
        out.push_back(std::string("  Type  : IEEE 802.15.4 ") + macType);
    }

    if (frame.hasPanId) out.push_back("  PAN   : 0x" + argTransformer.toHex(frame.panId, 4));
    if (frame.hasNwkAddresses) {
        out.push_back("  NWK   : 0x" + argTransformer.toHex(frame.nwkSource, 4)
                      + " -> 0x" + argTransformer.toHex(frame.nwkDestination, 4));
    } else if (frame.hasMacSource || frame.hasMacDestination) {
        std::string line = "  MAC   : ";
        line += frame.hasMacSource ? ("0x" + argTransformer.toHex(frame.macSource, 4)) : "?";
        line += " -> ";
        line += frame.hasMacDestination ? ("0x" + argTransformer.toHex(frame.macDestination, 4)) : "?";
        out.push_back(line);
    }
    if (!frame.sourceIeee.empty()) out.push_back("  IEEE  : " + frame.sourceIeee);

    if (frame.hasMacCommand) {
        std::string name;
        switch (frame.macCommandId) {
            case 0x01: name = "Association Request"; break;
            case 0x02: name = "Association Response"; break;
            case 0x03: name = "Disassociation"; break;
            case 0x04: name = "Data Request"; break;
            case 0x06: name = "Orphan Notification"; break;
            case 0x07: name = "Beacon Request"; break;
            case 0x08: name = "Coordinator Realignment"; break;
            default: break;
        }
        out.push_back("  MACCmd: 0x" + argTransformer.toHex(frame.macCommandId, 2)
                      + (name.empty() ? "" : (" " + name)));
    }

    if (frame.hasNwkCommand) {
        std::string name;
        switch (frame.nwkCommandId) {
            case 0x01: name = "Route Request"; break;
            case 0x02: name = "Route Reply"; break;
            case 0x03: name = "Network Status"; break;
            case 0x04: name = "Leave"; break;
            case 0x05: name = "Route Record"; break;
            case 0x06: name = "Rejoin Request"; break;
            case 0x07: name = "Rejoin Response"; break;
            case 0x08: name = "Link Status"; break;
            case 0x09: name = "Network Report"; break;
            case 0x0A: name = "Network Update"; break;
            default: break;
        }
        out.push_back("  NWKCmd: 0x" + argTransformer.toHex(frame.nwkCommandId, 2)
                      + (name.empty() ? "" : (" " + name)));
    }

    if (frame.nwkSecurity) out.push_back("  Sec   : NWK encrypted");
    else if (frame.hasAps && frame.apsSecurity) out.push_back("  Sec   : APS encrypted");
    else if (frame.macSecurity) out.push_back("  Sec   : MAC encrypted");
    else if (frame.probableZigbeeNwk) out.push_back("  Sec   : none visible");

    if (frame.hasAps) {
        out.push_back("  APS   : EP" + std::to_string(frame.sourceEndpoint)
                      + " -> EP" + std::to_string(frame.destinationEndpoint));
        const std::string clusterName = clusterToString(frame.clusterId);
        out.push_back("  Clust : 0x" + argTransformer.toHex(frame.clusterId, 4)
                      + (clusterName.empty() ? "" : (" " + clusterName)));
        out.push_back("  Prof  : 0x" + argTransformer.toHex(frame.profileId, 4));
    }

    if (frame.hasZcl) {
        const std::string commandName = zclCommandToString(frame.clusterId, frame.zclFrameType, frame.zclCommand);
        out.push_back("  ZCL   : 0x" + argTransformer.toHex(frame.zclCommand, 2)
                      + (commandName.empty() ? "" : (" " + commandName))
                      + " | seq " + std::to_string(frame.zclSequence));
    }

    if (!frame.payload.empty() && !frame.nwkSecurity && !frame.apsSecurity) {
        std::string raw = "  Raw   :";
        const size_t shown = std::min<size_t>(frame.payload.size(), 20);
        for (size_t i = 0; i < shown; ++i) raw += " " + argTransformer.toHex(frame.payload[i], 2);
        if (frame.payload.size() > shown) raw += " ...";
        out.push_back(raw);
    }
    out.push_back("");
    return out;
}

#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Role of the node inside a Zigbee network
#include "Enums/ZigbeeRoleEnum.h"

// Optional device endpoint the tool exposes on the network
enum class ZigbeeEndpointEnum {
    None,
    Light,           // On/Off Light: hubs can control this tool
    DimmableLight,   // On/Off + Level Control light
    ColorLight,      // On/Off + Level + Color Control light
    Switch,          // Color Dimmer Switch: this tool controls paired lights
    TempSensor,      // Temperature (+humidity) sensor with injectable readings
    OccupancySensor, // Occupancy sensor with injectable state
    Fan,             // Fan Control: hubs set the fan mode
    Outlet,          // On/Off Power Outlet
    RangeExtender,   // Range Extender identity for router role
};

struct ZigbeeNetworkStatus {
    bool initialized = false;
    bool initFailed = false;
    bool started = false;
    bool supported = false;
    bool connected = false;
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
    uint8_t channel = 15;
    uint16_t panId = 0;
    uint16_t shortAddress = 0xFFFF;
    bool permitJoining = false;
    uint8_t permitJoinSecondsRemaining = 0;
};

struct ZigbeeNetworkInfo {
    uint16_t panId = 0;
    std::string extendedPanId;
    uint8_t channel = 0;
    bool permitJoining = false;
    bool routerCapacity = false;
    bool endDeviceCapacity = false;
};

struct ZigbeeNeighborInfo {
    std::string ieeeAddress;
    uint16_t shortAddress = 0xFFFF;
    uint8_t deviceType = 0;
    uint8_t relationship = 0;
    uint8_t depth = 0;
    uint8_t lqi = 0;
    int8_t rssi = -128;
    bool rxOnWhenIdle = false;
};

// Aggregate captured from the raw IEEE 802.15.4 radio in promiscuous mode.
// This is intentionally MAC-level: traffic can be Zigbee, Thread, Matter over
// Thread, or another 802.15.4 protocol.

struct ZigbeeEndpointDescriptor {
    uint8_t endpoint = 0;
    uint16_t profileId = 0;
    uint16_t deviceId = 0;
    uint8_t deviceVersion = 0;
    std::vector<uint16_t> inputClusters;
    std::vector<uint16_t> outputClusters;
};

struct ZigbeeDeviceDescriptor {
    uint16_t shortAddress = 0xFFFF;
    std::vector<ZigbeeEndpointDescriptor> endpoints;
};


struct ZigbeeMonitorFrame {
    uint16_t source = 0xFFFF;
    uint16_t destination = 0xFFFF;
    uint8_t sourceEndpoint = 0;
    uint8_t destinationEndpoint = 0;
    uint16_t profileId = 0;
    uint16_t clusterId = 0;
    uint8_t destinationAddressMode = 0;
    uint8_t securityStatus = 0;
    int lqi = 0;
    std::vector<uint8_t> payload;
};

// One valid IEEE 802.15.4 frame captured by the raw pre-start sniffer.
// Upper-layer fields are best-effort: encrypted Zigbee traffic can expose
// MAC/NWK metadata while APS/ZCL remains unavailable without the network key.
struct ZigbeeSniffFrame {
    uint8_t channel = 0;
    int8_t rssi = -128;
    uint8_t lqi = 0;
    uint8_t macType = 7;
    bool macSecurity = false;
    bool hasPanId = false;
    uint16_t panId = 0xFFFF;
    bool hasMacSource = false;
    uint16_t macSource = 0xFFFF;
    bool hasMacDestination = false;
    uint16_t macDestination = 0xFFFF;
    std::string sourceIeee;
    bool probableZigbeeBeacon = false;
    bool probableZigbeeNwk = false;
    bool probableZigbeeInterPan = false;
    bool nwkSecurity = false;
    bool nwkCommand = false;
    bool hasNwkAddresses = false;
    uint16_t nwkSource = 0xFFFF;
    uint16_t nwkDestination = 0xFFFF;
    bool hasNwkCommand = false;
    uint8_t nwkCommandId = 0;
    bool hasMacCommand = false;
    uint8_t macCommandId = 0;
    bool hasAps = false;
    bool apsSecurity = false;
    uint8_t sourceEndpoint = 0;
    uint8_t destinationEndpoint = 0;
    uint16_t clusterId = 0;
    uint16_t profileId = 0;
    bool hasZcl = false;
    uint8_t zclFrameType = 0;
    uint8_t zclSequence = 0;
    uint8_t zclCommand = 0;
    std::vector<uint8_t> payload;
};

struct ZigbeeSniffInfo {
    uint8_t channel = 0;
    uint32_t frames = 0;
    uint32_t beacons = 0;
    uint32_t dataFrames = 0;
    uint32_t ackFrames = 0;
    uint32_t commandFrames = 0;
    uint32_t otherFrames = 0;
    uint32_t associationRequests = 0;
    uint32_t associationResponses = 0;
    uint32_t beaconRequests = 0;
    uint32_t orphanNotifications = 0;
    // PHY sync detections include weak/corrupt 802.15.4 candidates that did
    // not make it through FCS validation. Valid frames are counted above.
    uint32_t phyHits = 0;
    // Best-effort Zigbee classification from beacon/NWK headers. These are
    // intentionally labelled as probable because the radio is sniffing raw
    // IEEE 802.15.4 traffic and cannot guarantee the upper-layer protocol.
    uint32_t probableZigbeeBeacons = 0;
    uint32_t probableZigbeeNwkFrames = 0;
    uint32_t probableZigbeeNwkCommands = 0;
    uint32_t zigbeeRejoinRequests = 0;
    uint32_t zigbeeRejoinResponses = 0;
    uint32_t zigbeeLeaveCommands = 0;
    bool hasLastNwkAddresses = false;
    uint16_t lastNwkSource = 0xFFFF;
    uint16_t lastNwkDestination = 0xFFFF;
    int8_t weakestRssi = -128;
    int8_t strongestRssi = -128;
    int16_t averageRssi = -128;
    uint8_t strongestLqi = 0;
    uint8_t averageLqi = 0;
    std::vector<uint16_t> panIds;
    std::vector<std::string> joiningIeeeAddresses;
};

class IZigbeeService {
public:
    virtual ~IZigbeeService() = default;

    // Sets the primary channel used at next start (11..26)
    virtual bool setChannel(uint8_t channel) = 0;

    // Selects the device endpoint exposed after the next start
    virtual bool setEndpoint(ZigbeeEndpointEnum endpoint) = 0;
    virtual ZigbeeEndpointEnum getEndpoint() const = 0;

    // Starts the stack in the given role on the given channel (11..26).
    // EndDevice role requires firmware built with ZIGBEE_MODE_ED.
    virtual bool start(ZigbeeRoleEnum role, uint8_t channel) = 0;

    // Opens the network for new devices to join (coordinator/router)
    virtual bool permitJoining(uint8_t seconds) = 0;
    virtual bool closeJoining() = 0;

    // Sends On/Off commands to bound lights (Switch endpoint only).
    // group != 0 targets a Zigbee group instead of the bound devices.
    virtual bool sendOn(bool state, uint16_t group = 0) = 0;
    virtual bool sendToggle(uint16_t group = 0) = 0;

    // Sends Level Control (brightness 0-255) to bound lights or a group
    virtual bool sendLevel(uint8_t level, uint16_t group = 0) = 0;

    // Sends color as RGB (converted to XY by the stack) to bound lights or a group
    virtual bool sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group = 0) = 0;

    // Sensor endpoints: inject fake readings before reporting them
    virtual bool setSensorTemperature(float celsius) = 0;
    virtual bool setSensorHumidity(float percent) = 0;
    virtual bool setOccupancyState(bool occupied) = 0;
    virtual bool reportSensorValues() = 0;

    // Human-readable events received from the network. takeEvents() drains
    // the log; getRecentEvents() is a non-destructive diagnostic snapshot.
    virtual std::vector<std::string> takeEvents() = 0;
    virtual std::vector<std::string> getRecentEvents() const = 0;

    // Short addresses of devices bound to the current endpoint
    virtual std::vector<std::string> getBoundDeviceList() = 0;

    // Actual Zigbee neighbor table. This is independent from endpoint binding
    // and is the useful view for joined children/routers and RF link quality.
    virtual std::vector<ZigbeeNeighborInfo> getNeighborList() = 0;

    // Query a joined device using ZDO Active_EP + Simple_Desc requests.
    // This works without knowing its application type in advance.
    virtual bool inspectDevice(uint16_t shortAddress, ZigbeeDeviceDescriptor& out, uint32_t timeoutMs = 4000) = 0;

    // Active scan: start, poll status (-2 fail/not started, -1 running,
    // >=0 number of networks), then take results
    virtual bool startScan(uint8_t duration) = 0;
    virtual int16_t getScanStatus() = 0;
    virtual std::vector<ZigbeeNetworkInfo> takeScanResults() = 0;

    // Raw IEEE 802.15.4 promiscuous sniffer. It is intentionally available
    // only before the Arduino Zigbee stack has been initialized, because both
    // users need exclusive ownership of the same 802.15.4 radio.
    virtual bool beginSniff() = 0;
    virtual bool setSniffChannel(uint8_t channel) = 0;
    virtual ZigbeeSniffInfo getSniffInfo() = 0;
    virtual std::vector<ZigbeeSniffFrame> takeSniffFrames() = 0;
    virtual void endSniff() = 0;

    // Runtime APS monitor. Unlike sniff(), this runs while the Zigbee stack
    // owns the radio and observes traffic delivered to the local node.
    virtual bool beginMonitor() = 0;
    virtual std::vector<ZigbeeMonitorFrame> takeMonitorFrames() = 0;
    virtual void endMonitor() = 0;

    virtual ZigbeeNetworkStatus getStatus() = 0;

    // Specific explanation for the last failed operation, intended for CLI UX
    virtual std::string getLastError() const = 0;

    virtual bool isRoleSupported(ZigbeeRoleEnum role) const = 0;

    // False when the running chip has no 802.15.4 radio or the build
    // does not include the Zigbee libraries
    virtual bool isSupported() const = 0;
};

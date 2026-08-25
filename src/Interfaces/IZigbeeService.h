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
    bool started = false;
    bool supported = false;
    bool connected = false;
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
    uint8_t channel = 15;
    uint16_t panId = 0;
};

struct ZigbeeNetworkInfo {
    uint16_t panId = 0;
    uint8_t channel = 0;
    bool permitJoining = false;
    bool routerCapacity = false;
    bool endDeviceCapacity = false;
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

    // Stops the stack and releases the radio
    virtual void stop() = 0;

    // Opens the network for new devices to join (coordinator/router)
    virtual bool permitJoining(uint8_t seconds) = 0;

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

    // Human-readable events received from the network since the last call
    // (hub commands on emulated endpoints, reports from bound lights)
    virtual std::vector<std::string> takeEvents() = 0;

    // Short addresses of devices bound to the current endpoint
    virtual std::vector<std::string> getBoundDeviceList() = 0;

    // Active scan: start, poll status (-2 fail/not started, -1 running,
    // >=0 number of networks), then take results
    virtual bool startScan(uint8_t duration) = 0;
    virtual int16_t getScanStatus() = 0;
    virtual std::vector<ZigbeeNetworkInfo> takeScanResults() = 0;

    // Erases network state and reboots
    virtual bool factoryReset() = 0;

    virtual ZigbeeNetworkStatus getStatus() = 0;

    // False when the running chip has no 802.15.4 radio or the build
    // does not include the Zigbee libraries
    virtual bool isSupported() const = 0;
};

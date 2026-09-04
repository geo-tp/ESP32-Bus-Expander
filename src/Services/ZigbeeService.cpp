#include "Services/ZigbeeService.h"

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "Zigbee.h"
#include "esp_zigbee_core.h"

namespace {

// The Zigbee core invokes plain function pointers, so a file-local self
// pointer routes the callbacks back into the single service instance.
// pushEvent_ is public on ZigbeeService for exactly this reason.
ZigbeeService* g_self = nullptr;

constexpr size_t kMaxEvents = 32;

const char* onOffName(bool state) {
    return state ? "ON" : "OFF";
}

std::string miredsToKelvinSuffix(uint16_t mireds) {
    if (mireds == 0) {
        return "?K";
    }
    char buf[16];
    snprintf(buf, sizeof(buf), "%uK", static_cast<unsigned>((1000000UL + mireds / 2) / mireds));
    return buf;
}

void trampLightState(bool state) {
    if (g_self) g_self->pushEvent_(std::string("light: state=") + onOffName(state));
}

void trampDimmableState(bool state, uint8_t level) {
    if (g_self) {
        g_self->pushEvent_("dimlight: state=" + std::string(onOffName(state))
                           + " level=" + std::to_string(level));
    }
}

void trampColorRgb(bool state, uint8_t r, uint8_t g, uint8_t b, uint8_t level) {
    if (g_self) {
        char buf[64];
        snprintf(buf, sizeof(buf), "colorlight: state=%s rgb=(%u,%u,%u) level=%u",
                 onOffName(state), r, g, b, level);
        g_self->pushEvent_(buf);
    }
}

void trampColorHsv(bool state, uint8_t h, uint8_t s, uint8_t v) {
    if (g_self) {
        g_self->pushEvent_("colorlight: state=" + std::string(onOffName(state))
                           + " hsv=(" + std::to_string(h) + "," + std::to_string(s)
                           + "," + std::to_string(v) + ")");
    }
}

void trampColorTemp(bool state, uint8_t level, uint16_t mireds) {
    if (g_self) {
        g_self->pushEvent_("colorlight: state=" + std::string(onOffName(state))
                           + " level=" + std::to_string(level)
                           + " temp=" + std::to_string(mireds) + "m("
                           + miredsToKelvinSuffix(mireds) + ")");
    }
}

void trampSwitchState(bool state) {
    if (g_self) {
        g_self->pushEvent_("switch: bound light state=" + std::string(onOffName(state)));
    }
}

void trampSwitchLevel(uint8_t level) {
    if (g_self) {
        g_self->pushEvent_("switch: bound light level=" + std::to_string(level));
    }
}

void trampSwitchColor(uint8_t r, uint8_t g, uint8_t b) {
    if (g_self) {
        char buf[48];
        snprintf(buf, sizeof(buf), "switch: bound light rgb=(%u,%u,%u)", r, g, b);
        g_self->pushEvent_(buf);
    }
}

void trampFanMode(ZigbeeFanMode mode) {
    const char* name = "UNKNOWN";
    switch (mode) {
        case FAN_MODE_OFF:    name = "OFF"; break;
        case FAN_MODE_LOW:    name = "LOW"; break;
        case FAN_MODE_MEDIUM: name = "MEDIUM"; break;
        case FAN_MODE_HIGH:   name = "HIGH"; break;
        case FAN_MODE_ON:     name = "ON"; break;
        case FAN_MODE_AUTO:   name = "AUTO"; break;
        case FAN_MODE_SMART:  name = "SMART"; break;
        default: break;
    }
    if (g_self) g_self->pushEvent_(std::string("fan: mode=") + name);
}

void trampOutletState(bool state) {
    if (g_self) {
        g_self->pushEvent_(std::string("outlet: state=") + onOffName(state));
    }
}

}  // namespace

#endif  // ZIGBEE_MODE_ED || ZIGBEE_MODE_ZCZR â€” the remaining functions are
        // guarded individually so non-Zigbee targets still get their stubs

// Out-of-line so the unique_ptr member can hold a forward-declared endpoint
// type (complete types are visible above in Zigbee builds)
ZigbeeService::ZigbeeService() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    g_self = this;
#endif
}

ZigbeeService::~ZigbeeService() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (g_self == this) {
        g_self = nullptr;
    }
#endif
}

bool ZigbeeService::isSupported() const {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    return true;
#else
    return false;
#endif
}

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
void ZigbeeService::pushEvent_(const std::string& text) {
    if (events_.size() >= kMaxEvents) {
        events_.pop_front();
    }
    events_.push_back(text);
}

ZigbeeEP* ZigbeeService::makeEndpoint_() {
    switch (endpoint_) {
        case ZigbeeEndpointEnum::Light: {
            auto* ep = new ZigbeeLight(1);
            ep->onLightChange(trampLightState);
            return ep;
        }
        case ZigbeeEndpointEnum::DimmableLight: {
            auto* ep = new ZigbeeDimmableLight(1);
            ep->onLightChange(trampDimmableState);
            return ep;
        }
        case ZigbeeEndpointEnum::ColorLight: {
            auto* ep = new ZigbeeColorDimmableLight(1);
            // Advertise hue/saturation, XY and color temperature support
            ep->setLightColorCapabilities(
                ZIGBEE_COLOR_CAPABILITY_HUE_SATURATION | ZIGBEE_COLOR_CAPABILITY_X_Y
                | ZIGBEE_COLOR_CAPABILITY_COLOR_TEMP);
            ep->onLightChangeRgb(trampColorRgb);
            ep->onLightChangeHsv(trampColorHsv);
            ep->onLightChangeTemp(trampColorTemp);
            return ep;
        }
        case ZigbeeEndpointEnum::Switch: {
            auto* ep = new ZigbeeColorDimmerSwitch(1);
            ep->onLightStateChange(trampSwitchState);
            ep->onLightLevelChange(trampSwitchLevel);
            ep->onLightColorChange(trampSwitchColor);
            return ep;
        }
        case ZigbeeEndpointEnum::TempSensor: {
            auto* ep = new ZigbeeTempSensor(1);
            // Humidity cluster plus periodic reporting so hubs see updates
            ep->addHumiditySensor();
            ep->setReporting(30, 3600, 0.5f);
            ep->setHumidityReporting(30, 3600, 1.0f);
            return ep;
        }
        case ZigbeeEndpointEnum::OccupancySensor:
            return new ZigbeeOccupancySensor(1);
        case ZigbeeEndpointEnum::Fan: {
            auto* ep = new ZigbeeFanControl(1);
            ep->onFanModeChange(trampFanMode);
            return ep;
        }
        case ZigbeeEndpointEnum::Outlet: {
            auto* ep = new ZigbeePowerOutlet(1);
            ep->onPowerOutletChange(trampOutletState);
            return ep;
        }
        case ZigbeeEndpointEnum::RangeExtender:
            return new ZigbeeRangeExtender(1);
        default:
            return nullptr;
    }
}

bool ZigbeeService::ensureStarted_() {
    if (started_) {
        return true;
    }
    // Single-channel mask for the configured primary channel (11..26)
    Zigbee.setPrimaryChannelMask(1UL << channel_);
    // Create the selected HA endpoint on EP 1 before begin(); the object must
    // stay alive while the stack runs. An endpoint swap releases the previous
    // object here.
    if (!endpointObj_ || activeEndpoint_ != endpoint_) {
        endpointObj_.reset(makeEndpoint_());
        activeEndpoint_ = endpoint_;
        if (endpointObj_) {
            Zigbee.addEndpoint(endpointObj_.get());
        }
    }
#if defined(ZIGBEE_MODE_ED)
    // End-device firmware only supports the sleepy end-device role
    if (role_ != ZigbeeRoleEnum::EndDevice) {
        return false;
    }
    const zigbee_role_t target = ZIGBEE_END_DEVICE;
#elif defined(ZIGBEE_MODE_ZCZR)
    // Coordinator/router firmware cannot run as an end device
    if (role_ == ZigbeeRoleEnum::EndDevice) {
        return false;
    }
    const zigbee_role_t target =
        (role_ == ZigbeeRoleEnum::Coordinator) ? ZIGBEE_COORDINATOR : ZIGBEE_ROUTER;
#endif
    if (!Zigbee.begin(target)) {
        return false;
    }
    started_ = true;
    return true;
}
#endif

bool ZigbeeService::setChannel(uint8_t channel) {
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        return false;
    }
    channel_ = channel;
    return true;
}

bool ZigbeeService::setEndpoint(ZigbeeEndpointEnum endpoint) {
    endpoint_ = endpoint;
    return true;
}

ZigbeeEndpointEnum ZigbeeService::getEndpoint() const {
    return endpoint_;
}

bool ZigbeeService::start(ZigbeeRoleEnum role, uint8_t channel) {
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        return false;
    }
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (started_ && (role != role_ || channel != channel_ || endpoint_ != activeEndpoint_)) {
        // Role/channel/endpoint changes require a stack restart
        stop();
    }
    role_ = role;
    channel_ = channel;
    return ensureStarted_();
#else
    (void)role;
    (void)channel;
    return false;
#endif
}

void ZigbeeService::stop() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (started_) {
        Zigbee.stop();
        started_ = false;
    }
    scanning_ = false;
#endif
}

bool ZigbeeService::permitJoining(uint8_t seconds) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        return false;
    }
    Zigbee.openNetwork(seconds);
    return true;
#else
    (void)seconds;
    return false;
#endif
}

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
static ZigbeeColorDimmerSwitch* asSwitch_(const std::unique_ptr<ZigbeeEP>& obj, bool started) {
    if (!started || !obj) {
        return nullptr;
    }
    return static_cast<ZigbeeColorDimmerSwitch*>(obj.get());
}
#endif

bool ZigbeeService::sendOn(bool state, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    if (group != 0) {
        state ? sw->lightOn(group) : sw->lightOff(group);
    } else {
        state ? sw->lightOn() : sw->lightOff();
    }
    return true;
#else
    (void)state;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendToggle(uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->lightToggle(group) : sw->lightToggle();
    return true;
#else
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendLevel(uint8_t level, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->setLightLevel(level, group) : sw->setLightLevel(level);
    return true;
#else
    (void)level;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->setLightColor(red, green, blue, group) : sw->setLightColor(red, green, blue);
    return true;
#else
    (void)red;
    (void)green;
    (void)blue;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::setSensorTemperature(float celsius) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::TempSensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->setTemperature(celsius);
#else
    (void)celsius;
    return false;
#endif
}

bool ZigbeeService::setSensorHumidity(float percent) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::TempSensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->setHumidity(percent);
#else
    (void)percent;
    return false;
#endif
}

bool ZigbeeService::setOccupancyState(bool occupied) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::OccupancySensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeOccupancySensor*>(endpointObj_.get())->setOccupancy(occupied);
#else
    (void)occupied;
    return false;
#endif
}

bool ZigbeeService::reportSensorValues() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || !endpointObj_) {
        return false;
    }
    if (endpoint_ == ZigbeeEndpointEnum::TempSensor) {
        return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->report();
    }
    if (endpoint_ == ZigbeeEndpointEnum::OccupancySensor) {
        return static_cast<ZigbeeOccupancySensor*>(endpointObj_.get())->report();
    }
    return false;
#else
    return false;
#endif
}

std::vector<std::string> ZigbeeService::takeEvents() {
    std::vector<std::string> drained;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    drained.reserve(events_.size());
    while (!events_.empty()) {
        drained.push_back(events_.front());
        events_.pop_front();
    }
#endif
    return drained;
}

std::vector<std::string> ZigbeeService::getBoundDeviceList() {
    std::vector<std::string> devices;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!endpointObj_) {
        return devices;
    }
    char addr[8];
    for (const zb_device_params_t* device : endpointObj_->getBoundDevices()) {
        snprintf(addr, sizeof(addr), "0x%04X", static_cast<unsigned>(device->short_addr));
        devices.emplace_back(addr);
    }
#endif
    return devices;
}

bool ZigbeeService::startScan(uint8_t duration) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || scanning_ || duration < 1 || duration > 4) {
        return false;
    }
    Zigbee.scanNetworks(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK, duration);
    scanning_ = true;
    return true;
#else
    (void)duration;
    return false;
#endif
}

int16_t ZigbeeService::getScanStatus() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    // Core reports -2 when no scan was ever started, -1 while running,
    // otherwise the number of networks found
    return Zigbee.scanComplete();
#else
    return -2;
#endif
}

std::vector<ZigbeeNetworkInfo> ZigbeeService::takeScanResults() {
    std::vector<ZigbeeNetworkInfo> networks;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    const int16_t status = Zigbee.scanComplete();
    const zigbee_scan_result_t* results = (status > 0) ? Zigbee.getScanResult() : nullptr;
    if (results != nullptr) {
        networks.reserve(static_cast<size_t>(status));
        for (int16_t i = 0; i < status; ++i) {
            const zigbee_scan_result_t& net = results[i];
            ZigbeeNetworkInfo info;
            info.panId = net.short_pan_id;
            info.channel = net.logic_channel;
            info.permitJoining = net.permit_joining;
            info.routerCapacity = net.router_capacity;
            info.endDeviceCapacity = net.end_device_capacity;
            networks.push_back(info);
        }
    }
    // Scan cycle is over either way: allow a new startScan()
    scanning_ = false;
#endif
    return networks;
}

bool ZigbeeService::factoryReset() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    stop();
    Zigbee.factoryReset();
    return true;
#else
    return false;
#endif
}

ZigbeeNetworkStatus ZigbeeService::getStatus() {
    ZigbeeNetworkStatus status;
    status.supported = isSupported();
    status.started = started_;
    status.role = role_;
    status.channel = channel_;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    status.connected = started_ ? Zigbee.connected() : false;
    if (status.connected) {
        status.panId = static_cast<uint16_t>(esp_zb_get_pan_id());
    }
#endif
    return status;
}

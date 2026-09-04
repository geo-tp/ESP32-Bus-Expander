#include "ZigbeeController.h"
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <cmath>
#include <iomanip>
#include <sstream>

namespace {

// Standard HSV (h 0-360, s/v 0-255) to RGB conversion, used to send HSV
// colors over the RGB-only switch API
void hsvToRgb(int h, int s, int v, uint8_t& r, uint8_t& g, uint8_t& b) {
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

}  // namespace

/*
Constructor
*/
ZigbeeController::ZigbeeController(
    ITerminalView& terminalView,
    IInput& terminalInput,
    IZigbeeService& zigbeeService,
    ArgTransformer& argTransformer,
    UserInputManager& userInputManager
)
    : terminalView(terminalView),
      terminalInput(terminalInput),
      zigbeeService(zigbeeService),
      argTransformer(argTransformer),
      userInputManager(userInputManager)
{}

/*
Entry point for zigbee command
*/
void ZigbeeController::handleCommand(const TerminalCommand& cmd) {
    const auto& root = cmd.getRoot();

    if (root == "start") handleStart(cmd);
    else if (root == "stop") handleStop();
    else if (root == "status") handleStatus();
    else if (root == "channel") handleChannel(cmd);
    else if (root == "permit") handlePermit(cmd);
    else if (root == "device") handleDevice(cmd);
    else if (root == "on" || root == "off" || root == "toggle") handleOnOff(cmd);
    else if (root == "dim") handleDim(cmd);
    else if (root == "color") handleColor(cmd);
    else if (root == "settemp" || root == "sethum" || root == "setocc" || root == "report") handleSensor(cmd);
    else if (root == "events") handleEvents();
    else if (root == "devices") handleDevices();
    else if (root == "scan") handleScan(cmd);
    else if (root == "reset") handleReset();
    else if (root == "config") handleConfig();
    else handleHelp();
}

/*
Ensure configured
*/
void ZigbeeController::ensureConfigured() {
    if (!configured) {
        configured = true;
        if (!zigbeeService.isSupported()) {
            terminalView.println("Zigbee requires an 802.15.4 radio (ESP32-C6/H2/C5).");
            terminalView.println("This chip has no Zigbee radio. Build for a supported target.");
            return;
        }
        terminalView.println("Zigbee mode. Type 'help' to list commands.");
    }
}

/*
Ensure released
*/
void ZigbeeController::ensureReleased() {
    if (zigbeeService.isSupported()) {
        zigbeeService.stop();
    }
    configured = false;
}

/*
Ensure ready for radio commands
*/
bool ZigbeeController::ensureReadyForRadio_() {
    ensureConfigured();
    return zigbeeService.isSupported();
}

/*
Handle start command: start [coordinator|router|enddevice]
*/
void ZigbeeController::handleStart(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string roleRaw = argTransformer.toLower(cmd.getSubcommand());
#if defined(ZIGBEE_MODE_ED)
    ZigbeeRoleEnum role = ZigbeeRoleEnum::EndDevice;
#else
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
#endif
    if (!roleRaw.empty() && !ZigbeeRoleEnumMapper::fromString(roleRaw, role)) {
        terminalView.println("Unknown role. Usage: start [coordinator|router|enddevice]");
        return;
    }
    if (!zigbeeService.isRoleSupported(role)) {
        terminalView.println("Unsupported Zigbee role for this build.");
        return;
    }

    const uint8_t channel = zigbeeService.getStatus().channel;
    terminalView.print("Starting Zigbee as " + ZigbeeRoleEnumMapper::toString(role));
    terminalView.println(" on channel " + std::to_string(channel) + "...");

    if (!zigbeeService.start(role, channel)) {
        terminalView.println("Failed to start the Zigbee stack.");
        // EndDevice mode is only compiled into the dedicated ED image
        if (role == ZigbeeRoleEnum::EndDevice) {
            terminalView.println("EndDevice role requires the c6-devkit-ed firmware.");
        }
        return;
    }

    // Coordinator opens the network briefly by default; keep it open
    if (role == ZigbeeRoleEnum::Coordinator) {
        zigbeeService.permitJoining(180);
    }
    printStatusLine();
}

/*
Handle stop command
*/
void ZigbeeController::handleStop() {
    if (!ensureReadyForRadio_()) {
        return;
    }
    zigbeeService.stop();
    terminalView.println("Zigbee stack stopped.");
}

/*
Handle status command
*/
void ZigbeeController::handleStatus() {
    ensureConfigured();
    printStatusLine();
}

/*
Handle channel command: channel <11..26>
*/
void ZigbeeController::handleChannel(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    int channel = -1;
    if (!argTransformer.parseInt(cmd.getSubcommand(), channel)) {
        terminalView.println("Usage: channel <11-26>");
        return;
    }
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        terminalView.println("Invalid channel. Valid range is 11..26.");
        return;
    }

    const auto status = zigbeeService.getStatus();
    if (status.started && status.channel != static_cast<uint8_t>(channel)) {
        terminalView.println("Channel applies after 'stop' + 'start'.");
    }
    zigbeeService.setChannel(static_cast<uint8_t>(channel));
    terminalView.println("Primary channel set to " + std::to_string(channel) + ".");
}

/*
Handle permit command: permit [seconds]
*/
void ZigbeeController::handlePermit(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    int seconds = 60;
    const auto status = zigbeeService.getStatus();
    if (!argTransformer.parseInt(cmd.getSubcommand(), seconds) || seconds <= 0) {
        seconds = 60;
    }

    if (!zigbeeService.permitJoining(static_cast<uint8_t>(seconds))) {
        terminalView.println("Cannot open network. Is the stack started in coordinator/router mode?");
        return;
    }
    terminalView.println("Network open for joining devices for " + std::to_string(seconds) + "s.");
}

/*
Handle device command: device <none|light|dimlight|colorlight|switch|tempsensor|occupancy|fan|outlet|rangeextender>
*/
void ZigbeeController::handleDevice(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string name = argTransformer.toLower(cmd.getSubcommand());
    ZigbeeEndpointEnum endpoint;
    if (name == "light") {
        endpoint = ZigbeeEndpointEnum::Light;
    } else if (name == "dimlight" || name == "dimmer") {
        endpoint = ZigbeeEndpointEnum::DimmableLight;
    } else if (name == "colorlight" || name == "color") {
        endpoint = ZigbeeEndpointEnum::ColorLight;
    } else if (name == "switch") {
        endpoint = ZigbeeEndpointEnum::Switch;
    } else if (name == "tempsensor" || name == "temp") {
        endpoint = ZigbeeEndpointEnum::TempSensor;
    } else if (name == "occupancy" || name == "occ") {
        endpoint = ZigbeeEndpointEnum::OccupancySensor;
    } else if (name == "fan") {
        endpoint = ZigbeeEndpointEnum::Fan;
    } else if (name == "outlet" || name == "plug") {
        endpoint = ZigbeeEndpointEnum::Outlet;
    } else if (name == "rangeextender" || name == "repeater") {
        endpoint = ZigbeeEndpointEnum::RangeExtender;
    } else if (name == "none") {
        endpoint = ZigbeeEndpointEnum::None;
    } else {
        terminalView.println("Usage: device <none|light|dimlight|colorlight|switch|tempsensor|occupancy|fan|outlet|rangeextender>");
        return;
    }

    const auto status = zigbeeService.getStatus();
    if (status.started && zigbeeService.getEndpoint() != endpoint) {
        terminalView.println("Endpoint applies after 'stop' + 'start'.");
    }
    zigbeeService.setEndpoint(endpoint);

    switch (endpoint) {
        case ZigbeeEndpointEnum::Light:
            terminalView.println("Tool will act as On/Off Light after 'start'.");
            break;
        case ZigbeeEndpointEnum::DimmableLight:
            terminalView.println("Tool will act as Dimmable Light after 'start'.");
            break;
        case ZigbeeEndpointEnum::ColorLight:
            terminalView.println("Tool will act as Color Dimmable Light after 'start'.");
            break;
        case ZigbeeEndpointEnum::Switch:
            terminalView.println("Tool will act as On/Off Switch after 'start'.");
            break;
        case ZigbeeEndpointEnum::TempSensor:
            terminalView.println("Tool will act as Temperature/Humidity Sensor after 'start'.");
            break;
        case ZigbeeEndpointEnum::OccupancySensor:
            terminalView.println("Tool will act as Occupancy Sensor after 'start'.");
            break;
        case ZigbeeEndpointEnum::Fan:
            terminalView.println("Tool will act as Fan Control after 'start'.");
            break;
        case ZigbeeEndpointEnum::Outlet:
            terminalView.println("Tool will act as Power Outlet after 'start'.");
            break;
        case ZigbeeEndpointEnum::RangeExtender:
            terminalView.println("Tool will act as Range Extender after 'start'.");
            break;
        default:
            terminalView.println("Tool will expose no endpoint.");
            break;
    }
}

/*
Handle on/off/toggle commands: control lights bound to the switch endpoint,
optionally targeting a group address
*/
void ZigbeeController::handleOnOff(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string action = cmd.getRoot();
    const uint16_t group = cmd.getSubcommand().empty()
        ? 0 : argTransformer.parseHexOrDec16(cmd.getSubcommand());
    bool sent = false;
    std::string confirmation;
    if (action == "on") {
        sent = zigbeeService.sendOn(true, group);
        confirmation = "Bound lights turned on.";
    } else if (action == "off") {
        sent = zigbeeService.sendOn(false, group);
        confirmation = "Bound lights turned off.";
    } else {
        sent = zigbeeService.sendToggle(group);
        confirmation = "Toggled bound lights.";
    }

    if (!sent) {
        terminalView.println("Failed to send command. Requires running switch endpoint with paired lights.");
        return;
    }
    if (group != 0) {
        confirmation += " Group: 0x" + argTransformer.toHex(group, 4) + ".";
    }
    terminalView.println(confirmation);
}

/*
Handle dim command: dim <0-255 | 0-100%> [group]
Percent suffix scales to the 0-255 level; raw values pass through
*/
void ZigbeeController::handleDim(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string valueRaw = argTransformer.toLower(cmd.getSubcommand());
    if (valueRaw.empty()) {
        terminalView.println("Usage: dim <0-255 | 0-100%> [group]");
        return;
    }

    int value = 0;
    uint8_t level = 0;
    if (!valueRaw.empty() && valueRaw.back() == '%') {
        if (!argTransformer.parseInt(valueRaw.substr(0, valueRaw.size() - 1), value)
            || value < 0 || value > 100) {
            terminalView.println("Invalid percent. Usage: dim <0-255 | 0-100%> [group]");
            return;
        }
        level = static_cast<uint8_t>((value * 255 + 50) / 100);
    } else {
        if (!argTransformer.parseInt(valueRaw, value) || value < 0 || value > 255) {
            terminalView.println("Invalid level. Usage: dim <0-255 | 0-100%> [group]");
            return;
        }
        level = static_cast<uint8_t>(value);
    }

    // Remaining args token may hold a group address
    std::istringstream args(cmd.getArgs());
    std::string groupToken;
    args >> groupToken;
    const uint16_t group = groupToken.empty() ? 0 : argTransformer.parseHexOrDec16(groupToken);

    if (!zigbeeService.sendLevel(level, group)) {
        terminalView.println("Failed to send command. Requires running switch endpoint with paired lights.");
        return;
    }
    terminalView.println("Brightness set to level " + std::to_string(level) + ".");
}

/*
Handle color command: color rgb <r g b> [group] | color hsv <h s v> [group]
*/
void ZigbeeController::handleColor(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string format = argTransformer.toLower(cmd.getSubcommand());
    if (format != "rgb" && format != "hsv") {
        terminalView.println("Usage: color rgb <r> <g> <b> [group] | color hsv <h> <s> <v> [group]");
        return;
    }

    std::istringstream args(cmd.getArgs());
    int v1 = 0, v2 = 0, v3 = 0;
    std::string groupToken;
    if (!(args >> v1 >> v2 >> v3)) {
        terminalView.println("Usage: color rgb <r> <g> <b> [group] | color hsv <h> <s> <v> [group]");
        return;
    }
    args >> groupToken;
    const uint16_t group = groupToken.empty() ? 0 : argTransformer.parseHexOrDec16(groupToken);

    uint8_t r = 0, g = 0, b = 0;
    if (format == "rgb") {
        if (v1 < 0 || v1 > 255 || v2 < 0 || v2 > 255 || v3 < 0 || v3 > 255) {
            terminalView.println("Invalid RGB. Components must be 0..255.");
            return;
        }
        r = static_cast<uint8_t>(v1);
        g = static_cast<uint8_t>(v2);
        b = static_cast<uint8_t>(v3);
    } else {
        if (v1 < 0 || v1 > 360 || v2 < 0 || v2 > 255 || v3 < 0 || v3 > 255) {
            terminalView.println("Invalid HSV. Hue must be 0..360, saturation/value 0..255.");
            return;
        }
        hsvToRgb(v1, v2, v3, r, g, b);
    }

    if (!zigbeeService.sendColorRgb(r, g, b, group)) {
        terminalView.println("Failed to send command. Requires running switch endpoint with paired lights.");
        return;
    }
    std::ostringstream confirm;
    confirm << "Color sent rgb(" << static_cast<int>(r) << "," << static_cast<int>(g)
            << "," << static_cast<int>(b) << ").";
    terminalView.println(confirm.str());
}

/*
Handle sensor commands: settemp <celsius> | sethum <percent> | setocc <0|1> | report
*/
void ZigbeeController::handleSensor(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string root = cmd.getRoot();
    const std::string valueRaw = cmd.getSubcommand();

    if (root == "settemp") {
        if (valueRaw.empty() || !argTransformer.isValidFloat(valueRaw)) {
            terminalView.println("Usage: settemp <-40..85>");
            return;
        }
        if (zigbeeService.setSensorTemperature(std::stof(valueRaw))) {
            terminalView.println("Temperature reading set to " + valueRaw + " C.");
        } else {
            terminalView.println("Failed. Requires running tempsensor endpoint.");
        }
    } else if (root == "sethum") {
        if (valueRaw.empty() || !argTransformer.isValidFloat(valueRaw)) {
            terminalView.println("Usage: sethum <0-100>");
            return;
        }
        if (zigbeeService.setSensorHumidity(std::stof(valueRaw))) {
            terminalView.println("Humidity reading set to " + valueRaw + "%.");
        } else {
            terminalView.println("Failed. Requires running tempsensor endpoint.");
        }
    } else if (root == "setocc") {
        int state = -1;
        if (!argTransformer.parseInt(valueRaw, state) || state < 0 || state > 1) {
            terminalView.println("Usage: setocc <0|1>");
            return;
        }
        if (zigbeeService.setOccupancyState(state == 1)) {
            terminalView.println(state == 1 ? "Occupancy set to occupied." : "Occupancy cleared.");
        } else {
            terminalView.println("Failed. Requires running occupancy endpoint.");
        }
    } else {  // report
        if (zigbeeService.reportSensorValues()) {
            terminalView.println("Sensor readings reported.");
        } else {
            terminalView.println("Failed. Requires running tempsensor or occupancy endpoint.");
        }
    }
}

/*
Handle events command: show network events received since last call
*/
void ZigbeeController::handleEvents() {
    ensureConfigured();

    const std::vector<std::string> events = zigbeeService.takeEvents();
    if (events.empty()) {
        terminalView.println("No Zigbee events.");
        return;
    }
    terminalView.println(std::to_string(events.size()) + " event(s):");
    for (const auto& event : events) {
        terminalView.println("  " + event);
    }
}

/*
Handle devices command: list devices bound to the current endpoint
*/
void ZigbeeController::handleDevices() {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::vector<std::string> devices = zigbeeService.getBoundDeviceList();
    if (devices.empty()) {
        terminalView.println("No devices bound to this endpoint.");
        return;
    }

    terminalView.println(std::to_string(devices.size()) + " bound device(s):");
    for (const auto& address : devices) {
        terminalView.println("  " + address);
    }
}

/*
Handle scan command: scan [1-4], poll until done (~15s cap)
*/
void ZigbeeController::handleScan(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    int duration = 2;
    if (!cmd.getSubcommand().empty()
        && (!argTransformer.parseInt(cmd.getSubcommand(), duration) || duration < 1 || duration > 4)) {
        terminalView.println("Invalid scan duration. Usage: scan [1-4]");
        return;
    }

    if (!zigbeeService.startScan(static_cast<uint8_t>(duration))) {
        terminalView.println("Scan failed.");
        return;
    }
    terminalView.println("Scanning for networks (" + std::to_string(duration) + "s)...");

    // Poll until the scan completes (-1 = still running), at most 30 x 500ms
    int16_t status = -1;
    int polls = 0;
    while ((status = zigbeeService.getScanStatus()) == -1 && polls < 30) {
#ifdef ARDUINO
        delay(500);
#endif
        polls++;
    }
    if (status < 0) {
        terminalView.println("Scan failed.");
        return;
    }

    const auto networks = zigbeeService.takeScanResults();
    if (networks.empty()) {
        terminalView.println("No networks found.");
        return;
    }

    terminalView.println(std::to_string(networks.size()) + " network(s) found:");
    terminalView.println("PAN  CH JOIN ROUTER ED");
    for (const auto& network : networks) {
        std::ostringstream row;
        row << argTransformer.toHex(network.panId, 4) << " "
            << std::setw(2) << static_cast<int>(network.channel) << " "
            << std::left
            << std::setw(4) << (network.permitJoining ? "yes" : "no") << " "
            << std::setw(6) << (network.routerCapacity ? "yes" : "no") << " "
            << (network.endDeviceCapacity ? "yes" : "no");
        terminalView.println(row.str());
    }
}

/*
Handle reset command (factory reset network state)
*/
void ZigbeeController::handleReset() {
    if (!ensureReadyForRadio_()) {
        return;
    }
    if (!zigbeeService.factoryReset()) {
        terminalView.println("Factory reset failed.");
        return;
    }
    terminalView.println("Zigbee network state erased.");
}

/*
Handle config command
*/
void ZigbeeController::handleConfig() {
    ensureConfigured();
    printStatusLine();
}

/*
Handle help command
*/
void ZigbeeController::handleHelp() {
    terminalView.println("Zigbee commands:");
    terminalView.println("  start [coordinator|router|enddevice]  Start the stack in the given role");
    terminalView.println("  stop                                  Stop the stack");
    terminalView.println("  status                                Show network status");
    terminalView.println("  channel <11-26>                       Set primary channel (before start)");
    terminalView.println("  permit [seconds]                      Open network for joining");
    terminalView.println("  device <type>                         Endpoint exposed after 'start'");
    terminalView.println("     types: none light dimlight colorlight switch");
    terminalView.println("            tempsensor occupancy fan outlet rangeextender");
    terminalView.println("  on | off | toggle [group]             Control bound lights or a group");
    terminalView.println("  dim <0-255 | 0-100%> [group]          Set brightness of bound lights");
    terminalView.println("  color rgb|hsv <v v v> [group]         Set color of bound lights");
    terminalView.println("  settemp <celsius>                     Fake temperature (tempsensor)");
    terminalView.println("  sethum <percent>                      Fake humidity (tempsensor)");
    terminalView.println("  setocc <0|1>                          Fake occupancy state (occupancy)");
    terminalView.println("  report                                Report sensor readings now");
    terminalView.println("  events                                Show events received from the network");
    terminalView.println("  devices                               List devices bound to this endpoint");
    terminalView.println("  scan [1-4]                            Scan for nearby networks");
    terminalView.println("  reset                                 Factory reset network state");
    terminalView.println("  config                                Show current configuration");
    terminalView.println("  exit                                  Return to Bit Pirate CLI");
}

std::string ZigbeeController::endpointToString(ZigbeeEndpointEnum endpoint) const {
    switch (endpoint) {
        case ZigbeeEndpointEnum::Light:          return "LIGHT";
        case ZigbeeEndpointEnum::DimmableLight:  return "DIMMABLE_LIGHT";
        case ZigbeeEndpointEnum::ColorLight:     return "COLOR_LIGHT";
        case ZigbeeEndpointEnum::Switch:         return "SWITCH";
        case ZigbeeEndpointEnum::TempSensor:     return "TEMP_SENSOR";
        case ZigbeeEndpointEnum::OccupancySensor:return "OCCUPANCY_SENSOR";
        case ZigbeeEndpointEnum::Fan:            return "FAN";
        case ZigbeeEndpointEnum::Outlet:         return "OUTLET";
        case ZigbeeEndpointEnum::RangeExtender:  return "RANGE_EXTENDER";
        default:                                 return "NONE";
    }
}

void ZigbeeController::printStatusLine() {
    const auto status = zigbeeService.getStatus();
    std::ostringstream line;
    line << "zigbee{"
         << "supported=" << (status.supported ? "true" : "false")
         << ", started=" << (status.started ? "true" : "false")
         << ", connected=" << (status.connected ? "true" : "false")
         << ", role=" << ZigbeeRoleEnumMapper::toString(status.role)
         << ", endpoint=" << endpointToString(zigbeeService.getEndpoint())
         << ", channel=" << static_cast<int>(status.channel)
         << "}";
    terminalView.println(line.str());
}

#include "ZigbeeController.h"
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <set>
#include <sstream>



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
      userInputManager(userInputManager),
      zigbeeTransformer(argTransformer)
{}

/*
Entry point for zigbee command
*/
void ZigbeeController::handleCommand(const TerminalCommand& cmd) {
    const auto& root = cmd.getRoot();

    if (root == "start") handleStart(cmd);
    else if (root == "status") handleStatus();
    else if (root == "setchannel") handleSetChannel(cmd);
    else if (root == "events") handleEvents();
    else if (root == "scan") handleScan(cmd);
    else if (root == "sniff") handleSniff(cmd);
    else if (root == "monitor") handleMonitor(cmd);
#if defined(ZIGBEE_MODE_ZCZR)
    else if (root == "permit") handlePermit(cmd);
    else if (root == "pair" || root == "join") handlePair(cmd);
    else if (root == "devices") handleDevices(cmd);
#elif defined(ZIGBEE_MODE_ED)
    else if (root == "device") handleDevice(cmd);
    else if (root == "on" || root == "off" || root == "toggle") handleOnOff(cmd);
    else if (root == "dim") handleDim(cmd);
    else if (root == "color") handleColor(cmd);
    else if (root == "settemp" || root == "sethum" || root == "setocc" || root == "report") handleSensor(cmd);
    else if (root == "bindings") handleBindings();
#endif
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
        printLines(zigbeeTransformer.quickStartLines());
    }
}

/*
Ensure released
*/
void ZigbeeController::ensureReleased() {
    if (zigbeeService.isSupported()) {
        zigbeeService.endSniff();
        zigbeeService.endMonitor();
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
Handle start command. The firmware build fixes the broad Zigbee mode:
ZC/ZR images expose coordinator/router; ED images expose end-device only.
*/
void ZigbeeController::handleStart(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    uint8_t channel = zigbeeService.getStatus().channel;
    const bool interactive = cmd.getSubcommand().empty() && cmd.getArgs().empty();

#if defined(ZIGBEE_MODE_ED)
    const ZigbeeRoleEnum role = ZigbeeRoleEnum::EndDevice;

    if (interactive) {
        terminalView.println("");
        channel = userInputManager.readValidatedUint8("Channel", 15, 11, 26);
        if (!zigbeeService.setChannel(channel)) {
            printServiceError("Cannot set channel.");
            return;
        }
    } else {
        if (!cmd.getArgs().empty()) {
            terminalView.println("Usage: start [11-26]");
            return;
        }
        if (!cmd.getSubcommand().empty()) {
            int parsedChannel = -1;
            if (!argTransformer.parseInt(cmd.getSubcommand(), parsedChannel)
                || !ZigbeeRoleEnumMapper::isValidChannel(parsedChannel)) {
                terminalView.println("Usage: start [11-26]");
                return;
            }
            if (!zigbeeService.setChannel(static_cast<uint8_t>(parsedChannel))) {
                printServiceError("Cannot set channel.");
                return;
            }
            channel = static_cast<uint8_t>(parsedChannel);
        }
    }
#else
    const auto currentStatus = zigbeeService.getStatus();
    ZigbeeRoleEnum role = currentStatus.initialized
        ? currentStatus.role : ZigbeeRoleEnum::Coordinator;

    if (interactive) {
        terminalView.println("");
        while (true) {
            const std::string roleInput = argTransformer.toLower(
                userInputManager.readString("Role", "coordinator")
            );
            ZigbeeRoleEnum parsedRole = ZigbeeRoleEnum::Coordinator;
            if (ZigbeeRoleEnumMapper::fromString(roleInput, parsedRole)
                && zigbeeService.isRoleSupported(parsedRole)) {
                role = parsedRole;
                break;
            }
            terminalView.println("Invalid role. Use coordinator or router.");
        }

        channel = userInputManager.readValidatedUint8("Channel", 15, 11, 26);
        if (!zigbeeService.setChannel(channel)) {
            printServiceError("Cannot set channel.");
            return;
        }
    } else {
        const std::string first = argTransformer.toLower(cmd.getSubcommand());
        bool firstIsRole = false;
        if (!first.empty()) {
            ZigbeeRoleEnum parsedRole = role;
            if (ZigbeeRoleEnumMapper::fromString(first, parsedRole)) {
                if (!zigbeeService.isRoleSupported(parsedRole)) {
                    terminalView.println("This build supports coordinator/router only.");
                    return;
                }
                role = parsedRole;
                firstIsRole = true;
            } else {
                int parsedChannel = -1;
                if (!argTransformer.parseInt(first, parsedChannel)
                    || !ZigbeeRoleEnumMapper::isValidChannel(parsedChannel)
                    || !cmd.getArgs().empty()) {
                    terminalView.println("Usage: start [coordinator|router] [11-26]");
                    return;
                }
                if (!zigbeeService.setChannel(static_cast<uint8_t>(parsedChannel))) {
                    printServiceError("Cannot set channel.");
                    return;
                }
                channel = static_cast<uint8_t>(parsedChannel);
            }
        }

        if (firstIsRole && !cmd.getArgs().empty()) {
            std::istringstream args(cmd.getArgs());
            int parsedChannel = -1;
            std::string extra;
            if (!(args >> parsedChannel)
                || (args >> extra)
                || !ZigbeeRoleEnumMapper::isValidChannel(parsedChannel)) {
                terminalView.println("Usage: start [coordinator|router] [11-26]");
                return;
            }
            if (!zigbeeService.setChannel(static_cast<uint8_t>(parsedChannel))) {
                printServiceError("Cannot set channel.");
                return;
            }
            channel = static_cast<uint8_t>(parsedChannel);
        }
    }
#endif

    terminalView.println("");
    terminalView.print("Starting Zigbee as " + ZigbeeRoleEnumMapper::toString(role));
    terminalView.println(" on channel " + std::to_string(channel) + " ("
                         + std::to_string(zigbeeTransformer.channelFrequencyMHz(channel)) + " MHz)...");

    if (!zigbeeService.start(role, channel)) {
        printServiceError("Failed to start the Zigbee stack.");
        return;
    }

#if defined(ZIGBEE_MODE_ZCZR)
    if (role == ZigbeeRoleEnum::Coordinator) {
        zigbeeService.permitJoining(180);
        terminalView.println("Join window: OPEN (180s)");
        terminalView.println("Put the target in pairing mode.");
    }
#endif
    terminalView.println("RF mode locked to Zigbee. Use 'reboot' for WiFi.");
    terminalView.println("");
    printLines(zigbeeTransformer.runtimeStatusLines(
        zigbeeService.getStatus(),
        zigbeeService.getEndpoint(),
        zigbeeService.getNeighborList(),
        zigbeeService.getRecentEvents(),
        zigbeeService.getLastError()
    ));
    terminalView.println("");
}

/*
Handle status command
*/
void ZigbeeController::handleStatus() {
    ensureConfigured();
    terminalView.println("");
    printLines(zigbeeTransformer.runtimeStatusLines(
        zigbeeService.getStatus(),
        zigbeeService.getEndpoint(),
        zigbeeService.getNeighborList(),
        zigbeeService.getRecentEvents(),
        zigbeeService.getLastError()
    ));
    terminalView.println("");
}

/*
Handle setchannel command: setchannel <11..26>
*/
void ZigbeeController::handleSetChannel(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    if (cmd.getSubcommand().empty()) {
        const auto status = zigbeeService.getStatus();
        terminalView.println("Channel: " + std::to_string(status.channel) + " ("
                             + std::to_string(zigbeeTransformer.channelFrequencyMHz(status.channel)) + " MHz)");
        return;
    }

    int channel = -1;
    if (!argTransformer.parseInt(cmd.getSubcommand(), channel)) {
        terminalView.println("Usage: setchannel <11-26>");
        return;
    }
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        terminalView.println("Invalid channel. Valid range is 11..26.");
        return;
    }

    if (!zigbeeService.setChannel(static_cast<uint8_t>(channel))) {
        printServiceError("Cannot change Zigbee channel.");
        return;
    }
    terminalView.println("Primary channel set to " + std::to_string(channel) + " ("
                         + std::to_string(zigbeeTransformer.channelFrequencyMHz(static_cast<uint8_t>(channel)))
                         + " MHz). It will be used on first start.");
}

/*
Handle permit command: permit [seconds]
*/
void ZigbeeController::handlePermit(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::string value = argTransformer.toLower(cmd.getSubcommand());
    if (value == "off" || value == "close" || value == "0") {
        if (!zigbeeService.closeJoining()) {
            printServiceError("Cannot close permit joining.");
            return;
        }
        terminalView.println("Permit joining closed.");
        return;
    }

    int seconds = 60;
    if (!value.empty() && (!argTransformer.parseInt(value, seconds) || seconds < 1 || seconds > 255)) {
        terminalView.println("Usage: permit [1-255|off]");
        return;
    }

    if (!zigbeeService.permitJoining(static_cast<uint8_t>(seconds))) {
        printServiceError("Cannot open network for joining.");
        return;
    }
    terminalView.println("Network open for joining devices for " + std::to_string(seconds) + "s.");
}

/*
Guided pairing mode: opens permit-join and watches the neighbor table for
new devices. This remains the focused one-device workflow; scan is broader.
*/
void ZigbeeController::handlePair(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    terminalView.println("");
    int seconds = 60;
    if (!cmd.getSubcommand().empty()
        && (!argTransformer.parseInt(cmd.getSubcommand(), seconds) || seconds < 5 || seconds > 255)) {
        terminalView.println("Usage: pair [5-255]");
        return;
    }

    auto status = zigbeeService.getStatus();
    if (!status.started) {
        terminalView.println("Start coordinator/router mode first.");
        terminalView.println("Example: start coordinator 15");
        return;
    }
    if (status.role == ZigbeeRoleEnum::EndDevice) {
        terminalView.println("Pairing requires coordinator/router mode.");
        return;
    }

    std::set<uint16_t> known;
    for (const auto& device : zigbeeService.getNeighborList()) {
        known.insert(device.shortAddress);
    }

    // start coordinator already opens a 180 s join window. Do not reopen it
    // from the CLI unless it is closed or would expire before this pairing
    // attempt. Besides being redundant, the Arduino wrapper calls the BDB
    // API without the Zigbee task lock on some core versions.
    status = zigbeeService.getStatus();
    if (!status.permitJoining || status.permitJoinSecondsRemaining < seconds) {
        if (!zigbeeService.permitJoining(static_cast<uint8_t>(seconds))) {
            printServiceError("Cannot open pairing window.");
            return;
        }
        terminalView.println("Pairing window OPEN for " + std::to_string(seconds) + "s.");
    } else {
        terminalView.println("Pairing window already OPEN (~"
                             + std::to_string(status.permitJoinSecondsRemaining) + "s).");
    }

    terminalView.println("Put one device in pairing mode.");
    terminalView.println("Waiting for a new device... ENTER to cancel.");

    uint16_t pairedAddress = 0xFFFF;
    const int found = watchForNewDevices(seconds, known, true, true, &pairedAddress);

    // Pair is a one-device workflow: close the join window as soon as the
    // target has joined (or the attempt ends) instead of leaving the PAN open.
    if (!zigbeeService.closeJoining()) {
        printServiceError("Warning: could not close joining.");
    }

    if (found > 0) {
        terminalView.println("");
        terminalView.println("Pairing successful.");
        if (pairedAddress != 0xFFFF) {
            terminalView.println("Device : 0x" + argTransformer.toHex(pairedAddress, 4));
            terminalView.println("Next   : devices\n\r");
        }
        return;
    }

    terminalView.println("");
    terminalView.println("Pairing stopped: no new device joined.\n\r");
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
    if (!zigbeeTransformer.endpointFromString(name, endpoint)) {
        terminalView.println("Usage: device <none|light|dimlight|colorlight|switch|tempsensor|occupancy|fan|outlet|rangeextender>");
        return;
    }

    if (!zigbeeService.setEndpoint(endpoint)) {
        printServiceError("Cannot change emulated endpoint.");
        return;
    }

    terminalView.println(zigbeeTransformer.endpointConfiguredMessage(endpoint));
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
        zigbeeTransformer.hsvToRgb(v1, v2, v3, r, g, b);
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
        terminalView.println("No Zigbee events.\n");
        return;
    }
    terminalView.println(std::to_string(events.size()) + " event(s):");
    for (const auto& event : events) {
        terminalView.println("  " + event);
    }

    terminalView.println("");
}

/*
List joined Zigbee neighbors, then optionally probe one of them with standard
ZDO Active_EP + Simple_Desc discovery. This keeps discovery and inspection in
one user-facing command instead of a separate "info" command.
*/
void ZigbeeController::handleDevices(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }
    if (!cmd.getSubcommand().empty() || !cmd.getArgs().empty()) {
        terminalView.println("Usage: devices");
        return;
    }

    const auto status = zigbeeService.getStatus();
    if (!status.started) {
        terminalView.println("Start Zigbee first.");
        return;
    }

    const auto devices = zigbeeService.getNeighborList();
    if (devices.empty()) {
        const std::string error = zigbeeService.getLastError();
        if (!error.empty()) {
            terminalView.println("Error: " + error);
            return;
        }
        terminalView.println("");
        terminalView.println("No Zigbee device known.");
        terminalView.println("Use 'scan' or 'pair' first.");
        terminalView.println("");
        return;
    }

    terminalView.println("");
    terminalView.println("Zigbee devices:");
    printLines(zigbeeTransformer.deviceSelectionLines(devices));

    terminalView.println("");
    terminalView.println("Select an index to probe endpoints/clusters.");
    terminalView.println("ENTER returns. Wake sleepy devices first.");
    terminalView.print("Probe index: ");
    const std::string selection = userInputManager.getLine(true);
    if (selection.empty()) {
        terminalView.println("");
        return;
    }

    int index = 0;
    if (!argTransformer.parseInt(selection, index)
        || index < 1 || static_cast<size_t>(index) > devices.size()) {
        terminalView.println("Invalid selection.");
        terminalView.println("");
        return;
    }

    const uint16_t address = devices[static_cast<size_t>(index - 1)].shortAddress;
    terminalView.println("");
    terminalView.println("Probing 0x" + argTransformer.toHex(address, 4) + "...");
    terminalView.println("Wake sleepy sensors if needed.");

    ZigbeeDeviceDescriptor info;
    if (!zigbeeService.inspectDevice(address, info, 5000)) {
        printServiceError("Device probe failed.");
        terminalView.println("");
        return;
    }
    printLines(zigbeeTransformer.deviceDescriptorLines(info));
    terminalView.println("");
}

/*
Old 'devices' behavior, kept explicitly as bindings so the two concepts are
not confused anymore.
*/
void ZigbeeController::handleBindings() {
    if (!ensureReadyForRadio_()) {
        return;
    }

    const std::vector<std::string> devices = zigbeeService.getBoundDeviceList();
    if (devices.empty()) {
        terminalView.println("No devices bound to the current emulated endpoint.");
        return;
    }

    terminalView.println(std::to_string(devices.size()) + " bound device(s):");
    for (const auto& address : devices) {
        terminalView.println("  " + address);
    }
}

bool ZigbeeController::runNetworkScan(uint8_t duration) {
    if (!zigbeeService.startScan(duration)) {
        printServiceError("PAN scan failed.");
        return false;
    }
    terminalView.println("Scanning Zigbee PANs on channels 11-26...");

    int16_t status = -1;
    int polls = 0;
    while ((status = zigbeeService.getScanStatus()) == -1 && polls < 40) {
#ifdef ARDUINO
        delay(500);
#endif
        polls++;
    }
    if (status < 0) {
        terminalView.println("PAN scan timed out or failed.");
        return false;
    }

    const auto networks = zigbeeService.takeScanResults();
    if (networks.empty()) {
        terminalView.println("No active Zigbee PAN found.");
        return true;
    }

    terminalView.println(std::to_string(networks.size()) + " Zigbee network(s) found:");
    for (const auto& network : networks) {
        printLines(zigbeeTransformer.networkLines(network));
    }
    return true;
}

/*
Raw IEEE 802.15.4 sniffer. With no arguments it hops channels 11..26 and
reports PHY activity, valid MAC frames and likely Zigbee beacon/NWK traffic.
A fixed channel may be selected with: sniff <11-26>.

This deliberately runs only before Zigbee.begin(): the raw driver and the
Arduino Zigbee stack must never own the 802.15.4 radio at the same time.
*/
void ZigbeeController::handleSniff(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) return;

    const auto status = zigbeeService.getStatus();
    if (status.started) {
        // UX shortcut: once the Zigbee stack owns the radio, "sniff" becomes
        // the live APS/ZCL monitor instead of failing on raw-radio ownership.
        handleMonitor(TerminalCommand("monitor"));
        return;
    }

    terminalView.println("");
    if (status.initialized) {
        terminalView.println("Zigbee stack already owns the radio.");
        terminalView.println("Raw sniff is available only before the first start.");
        terminalView.println("");
        return;
    }

    const std::string target = argTransformer.toLower(cmd.getSubcommand());
    const bool sweep = target.empty() || target == "all";
    int channel = 0;

    if (!sweep) {
        if (!argTransformer.parseInt(target, channel)
            || !ZigbeeRoleEnumMapper::isValidChannel(channel)
            || !cmd.getArgs().empty()) {
            terminalView.println("Usage: sniff [11-26]");
            terminalView.println("  sniff     Hop CH11-26");
            terminalView.println("  sniff 15  Stay on CH15");
            return;
        }
    } else if (!cmd.getArgs().empty()) {
        terminalView.println("Usage: sniff [11-26]");
        return;
    }

    if (!zigbeeService.beginSniff()) {
        printServiceError("Could not start raw sniffer.");
        return;
    }

    terminalView.println("802.15.4 / Zigbee sniff - ENTER to stop");
    if (sweep) {
        terminalView.println("Hopping CH11-26 continuously...");
    } else {
        terminalView.println("CH" + std::to_string(channel) + " / "
                             + std::to_string(zigbeeTransformer.channelFrequencyMHz(static_cast<uint8_t>(channel)))
                             + " MHz");
    }
    terminalView.println("");

    bool stopped = false;

    if (sweep) {
        while (!stopped) {
            for (int ch = 11; ch <= 26 && !stopped; ++ch) {
                if (!zigbeeService.setSniffChannel(static_cast<uint8_t>(ch))) {
                    printServiceError("Could not tune sniffer.");
                    stopped = true;
                    break;
                }

                bool interesting = false;
                for (int tick = 0; tick < 2 && !stopped; ++tick) {
                    const char key = terminalInput.readChar();
                    if (key == '\r' || key == '\n') {
                        stopped = true;
                        break;
                    }
#ifdef ARDUINO
                    delay(100);
#endif
                    const auto frames = zigbeeService.takeSniffFrames();
                    for (const auto& frame : frames) {
                        // ACKs have no upper-layer identity and quickly make a
                        // busy channel unreadable. They remain counted by the
                        // PHY/MAC stats, while every other valid frame is shown.
                        if (frame.macType == 2) continue;
                        printLines(zigbeeTransformer.sniffFrameLines(frame));
                        if (frame.probableZigbeeBeacon || frame.probableZigbeeNwk
                            || frame.probableZigbeeInterPan || frame.hasMacCommand) {
                            interesting = true;
                        }
                    }
                }

                if (stopped) break;

                // Once a Zigbee-like burst is seen, linger briefly on the same
                // channel instead of hopping away in the middle of the exchange.
                if (interesting) {
                    for (int tick = 0; tick < 5 && !stopped; ++tick) {
                        const char key = terminalInput.readChar();
                        if (key == '\r' || key == '\n') {
                            stopped = true;
                            break;
                        }
#ifdef ARDUINO
                        delay(100);
#endif
                        const auto frames = zigbeeService.takeSniffFrames();
                        for (const auto& frame : frames) {
                            if (frame.macType != 2) printLines(zigbeeTransformer.sniffFrameLines(frame));
                        }
                    }
                }

                // Weak/corrupt candidates do not reach receive_done(). Report
                // them only when there was no valid frame to keep output useful.
                const auto sample = zigbeeService.getSniffInfo();
                if (!interesting && sample.frames == 0 && sample.phyHits > 0) {
                    terminalView.println("[PHY] CH" + std::to_string(ch)
                                         + " sync " + std::to_string(sample.phyHits)
                                         + " | no valid FCS");
                }
            }
        }
    } else {
        if (!zigbeeService.setSniffChannel(static_cast<uint8_t>(channel))) {
            printServiceError("Could not tune sniffer.");
            zigbeeService.endSniff();
            return;
        }

        uint32_t lastPhy = 0;
        uint32_t lastFrames = 0;
        int quietTicks = 0;
        while (!stopped) {
            const char key = terminalInput.readChar();
            if (key == '\r' || key == '\n') {
                stopped = true;
                break;
            }
#ifdef ARDUINO
            delay(40);
#endif
            const auto frames = zigbeeService.takeSniffFrames();
            for (const auto& frame : frames) {
                if (frame.macType != 2) printLines(zigbeeTransformer.sniffFrameLines(frame));
            }

            // Occasionally surface PHY-only hits so a weak signal is visible
            // even when no frame survives FCS validation.
            if (++quietTicks >= 25) {
                quietTicks = 0;
                const auto sample = zigbeeService.getSniffInfo();
                if (sample.frames == lastFrames && sample.phyHits > lastPhy) {
                    terminalView.println("[PHY] CH" + std::to_string(channel)
                                         + " +" + std::to_string(sample.phyHits - lastPhy)
                                         + " sync | no valid FCS");
                }
                lastPhy = sample.phyHits;
                lastFrames = sample.frames;
            }
        }
    }

    // Flush frames that arrived at the same moment as ENTER.
    const auto remaining = zigbeeService.takeSniffFrames();
    for (const auto& frame : remaining) {
        if (frame.macType != 2) printLines(zigbeeTransformer.sniffFrameLines(frame));
    }

    zigbeeService.endSniff();
    terminalView.println("");
    terminalView.println("Sniff stopped.");
    terminalView.println("");
}

/*
Versatile discovery: scan PANs first, then inspect/observe network devices.
In coordinator/router mode a short temporary join window is opened when one
is not already active, so devices currently in pairing mode can actually join
and become identifiable.
*/
void ZigbeeController::handleScan(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) {
        return;
    }

    terminalView.println("");
    int seconds = 5;
    if (!cmd.getSubcommand().empty()
        && (!argTransformer.parseInt(cmd.getSubcommand(), seconds) || seconds < 1 || seconds > 30)) {
        terminalView.println("Usage: scan [1-30]  (seconds to watch for devices)");
        return;
    }

    const auto initialStatus = zigbeeService.getStatus();
    if (!initialStatus.started) {
        terminalView.println("Zigbee stack is not running.");
        terminalView.println("Try: start coordinator 15");
        return;
    }

    terminalView.println("=== Zigbee discovery ===");
    runNetworkScan(2);

    auto initialDevices = zigbeeService.getNeighborList();
    std::set<uint16_t> known;
    for (const auto& device : initialDevices) {
        known.insert(device.shortAddress);
    }

    const bool canAcceptJoins = initialStatus.role != ZigbeeRoleEnum::EndDevice;
    bool openedTemporaryWindow = false;
    if (canAcceptJoins) {
        const auto joinStatus = zigbeeService.getStatus();
        if (!joinStatus.permitJoining) {
            if (zigbeeService.permitJoining(static_cast<uint8_t>(seconds))) {
                openedTemporaryWindow = true;
                terminalView.println("Join window: OPEN for "
                                     + std::to_string(seconds) + "s");
            } else {
                printServiceError("Could not open a temporary join window.");
            }
        } else {
            terminalView.println("Join window already OPEN");
            terminalView.println("  ~" + std::to_string(joinStatus.permitJoinSecondsRemaining)
                                 + "s remaining");
        }

        terminalView.println("Put sensors/buttons in pairing mode.");
        terminalView.println("Watching for joins...");
        const int found = watchForNewDevices(seconds, known, false);
        if (openedTemporaryWindow) {
            zigbeeService.closeJoining();
            terminalView.println("Join window: closed");
        }
        if (found == 0) {
            terminalView.println("No new device detected.");
        }
    } else {
        terminalView.println("End-device build:");
        terminalView.println("  PANs + current neighbors only.");
    }

    terminalView.println("");
    terminalView.println("Known / discovered devices:");
    printLines(zigbeeTransformer.deviceTableLines(zigbeeService.getNeighborList()));
    terminalView.println("");
}


/*
Live Zigbee monitor. This observes APS frames delivered to the running Zigbee
stack, so it complements raw sniff(): sniff is pre-start RF discovery, while
monitor is for paired devices after start/pairing.
*/
void ZigbeeController::handleMonitor(const TerminalCommand& cmd) {
    if (!ensureReadyForRadio_()) return;
    if (!cmd.getSubcommand().empty() || !cmd.getArgs().empty()) {
        terminalView.println("Usage: monitor");
        return;
    }

    const auto status = zigbeeService.getStatus();
    if (!status.started) {
        terminalView.println("Start Zigbee first, then use monitor.");
        return;
    }
    if (!zigbeeService.beginMonitor()) {
        printServiceError("Could not start Zigbee monitor.");
        return;
    }

    terminalView.println("");
    terminalView.println("Monitoring paired Zigbee traffic... Press [ENTER] to stop");
    terminalView.println("Press paired devices/buttons to see traffic.");
    terminalView.println("");

    bool stopped = false;
    while (!stopped) {
        const char key = terminalInput.readChar();
        if (key == '\r' || key == '\n') {
            stopped = true;
        }

        const auto frames = zigbeeService.takeMonitorFrames();
        for (const auto& frame : frames) {
            printLines(zigbeeTransformer.monitorFrameLines(frame));
        }
#ifdef ARDUINO
        delay(40);
#endif
    }

    // Flush anything that arrived at the same time as ENTER before restoring
    // Arduino's original APS handler.
    const auto remaining = zigbeeService.takeMonitorFrames();
    for (const auto& frame : remaining) {
        printLines(zigbeeTransformer.monitorFrameLines(frame));
    }
    zigbeeService.endMonitor();
    terminalView.println("Monitor stopped.");
    terminalView.println("");
}


/*
Handle help command
*/
void ZigbeeController::handleHelp() {
    printLines(zigbeeTransformer.helpLines());
}

void ZigbeeController::printServiceError(const std::string& fallback) {
    const std::string error = zigbeeService.getLastError();
    terminalView.println(error.empty() ? fallback : (fallback + " " + error));
}

void ZigbeeController::printLines(const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        terminalView.println(line);
    }
}

int ZigbeeController::watchForNewDevices(int seconds, std::set<uint16_t>& known, bool allowAbort,
                                                bool stopAfterFirst, uint16_t* firstFound) {
    int found = 0;
    for (int tick = 0; tick < seconds * 4; ++tick) {
        const auto devices = zigbeeService.getNeighborList();
        for (const auto& device : devices) {
            if (known.insert(device.shortAddress).second) {
                ++found;
                printLines(zigbeeTransformer.newDeviceLines(device));
                if (firstFound != nullptr && *firstFound == 0xFFFF) {
                    *firstFound = device.shortAddress;
                }
                if (stopAfterFirst) {
                    return found;
                }
            }
        }

        if (allowAbort) {
            const char key = terminalInput.readChar();
            if (key == '\r' || key == '\n') {
                break;
            }
        }
#ifdef ARDUINO
        delay(250);
#endif
    }
    return found;
}

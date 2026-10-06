#pragma once
#include <string>
#include <set>
#include <vector>
#include "Models/TerminalCommand.h"
#include "Interfaces/ITerminalView.h"
#include "Interfaces/IInput.h"
#include "Interfaces/IZigbeeService.h"
#include "Enums/ZigbeeRoleEnum.h"
#include "Transformers/ArgTransformer.h"
#include "Transformers/ZigbeeTransformer.h"
#include "Managers/UserInputManager.h"

class ZigbeeController {
public:
    ZigbeeController(
        ITerminalView& terminalView,
        IInput& terminalInput,
        IZigbeeService& zigbeeService,
        ArgTransformer& argTransformer,
        UserInputManager& userInputManager
    );

    // Entry point for zigbee command
    void handleCommand(const TerminalCommand& cmd);

    void ensureConfigured();
    void ensureReleased();

private:
    void handleStart(const TerminalCommand& cmd);
    void handleStatus();
    void handleSetChannel(const TerminalCommand& cmd);
    void handlePermit(const TerminalCommand& cmd);
    void handlePair(const TerminalCommand& cmd);
    void handleDevice(const TerminalCommand& cmd);
    void handleOnOff(const TerminalCommand& cmd);
    void handleDim(const TerminalCommand& cmd);
    void handleColor(const TerminalCommand& cmd);
    void handleSensor(const TerminalCommand& cmd);
    void handleEvents();
    void handleDevices(const TerminalCommand& cmd);
    void handleBindings();
    void handleScan(const TerminalCommand& cmd);
    void handleSniff(const TerminalCommand& cmd);
    void handleMonitor(const TerminalCommand& cmd);
    void handleHelp();

    void printServiceError(const std::string& fallback);
    void printLines(const std::vector<std::string>& lines);
    int watchForNewDevices(int seconds, std::set<uint16_t>& known, bool allowAbort,
                           bool stopAfterFirst = false, uint16_t* firstFound = nullptr);
    bool runNetworkScan(uint8_t duration);

    // Runs ensureConfigured() and reports whether the chip can do Zigbee.
    // When false, the radio commands must not reach the service.
    bool ensureReadyForRadio_();

private:
    ITerminalView& terminalView;
    IInput& terminalInput;
    IZigbeeService& zigbeeService;
    ArgTransformer& argTransformer;
    UserInputManager& userInputManager;
    ZigbeeTransformer zigbeeTransformer;

    bool configured = false;
};

#pragma once
#include <string>
#include "Models/TerminalCommand.h"
#include "Interfaces/ITerminalView.h"
#include "Interfaces/IInput.h"
#include "Interfaces/IZigbeeService.h"
#include "Enums/ZigbeeRoleEnum.h"
#include "Transformers/ArgTransformer.h"
#include "Managers/UserInputManager.h"
#include "States/GlobalState.h"

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
    void handleStop();
    void handleStatus();
    void handleChannel(const TerminalCommand& cmd);
    void handlePermit(const TerminalCommand& cmd);
    void handleDevice(const TerminalCommand& cmd);
    void handleOnOff(const TerminalCommand& cmd);
    void handleDim(const TerminalCommand& cmd);
    void handleColor(const TerminalCommand& cmd);
    void handleSensor(const TerminalCommand& cmd);
    void handleEvents();
    void handleDevices();
    void handleScan(const TerminalCommand& cmd);
    void handleReset();
    void handleConfig();
    void handleHelp();

    std::string endpointToString(ZigbeeEndpointEnum endpoint) const;
    void printStatusLine();

    // Runs ensureConfigured() and reports whether the chip can do Zigbee.
    // When false, the radio commands must not reach the service.
    bool ensureReadyForRadio_();

private:
    ITerminalView& terminalView;
    IInput& terminalInput;
    IZigbeeService& zigbeeService;
    ArgTransformer& argTransformer;
    UserInputManager& userInputManager;
    GlobalState& state = GlobalState::getInstance();

    bool configured = false;
};

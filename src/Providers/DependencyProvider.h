#pragma once

/*
The DependencyProvider is responsible for creating, holding,
and injecting shared instances of core components
(such as services, controllers, etc) throughout the application.
*/

#include "Services/WifiService.h"
#include "Services/WifiOpenScannerService.h"
#include "Services/LittleFsService.h"
#include "Services/NvsService.h"
#include "Services/NmapService.h"
#include "Services/ICMPService.h"
#include "Services/HttpService.h"
#include "Services/ModbusService.h"
#include "Services/ZigbeeService.h"
#include "Transformers/JsonTransformer.h"
#include "Shells/ModbusShell.h"
#include "Transformers/ArgTransformer.h"
#include "Transformers/TerminalCommandTransformer.h"
#include "Managers/UserInputManager.h"
#include "Managers/CommandHistoryManager.h"
#include "Controllers/WifiController.h"
#include "Controllers/ZigbeeController.h"


class DependencyProvider
{
public:
    DependencyProvider(ITerminalView& terminalView, IInput& terminalInput);

    // Core
    ITerminalView& getTerminalView();
    IInput& getTerminalInput();

    // Services
    WifiService &getWifiService();
    WifiOpenScannerService &getWifiOpenScannerService();
    ZigbeeService &getZigbeeService();

    // Controllers
    WifiController &getWifiController();
    ZigbeeController &getZigbeeController();

    // Transformers
    ArgTransformer &getArgTransformer();
    TerminalCommandTransformer &getCommandTransformer();

    // Managers
    UserInputManager &getUserInputManager();
    CommandHistoryManager &getCommandHistoryManager();

    // Disable
    void disableAllProtocols();

private:
    // Core components
    ITerminalView& terminalView;
    IInput& terminalInput;

    // Services
    WifiService wifiService;
    WifiOpenScannerService wifiOpenScannerService;
    LittleFsService littleFsService;
    NvsService nvsService;
    NmapService nmapService;
    ICMPService icmpService;
    HttpService httpService;
    ModbusService modbusService;
    ZigbeeService zigbeeService;

    // Shells
    ModbusShell modbusShell;
    
    // Controllers
    WifiController wifiController;
    ZigbeeController zigbeeController;
    
    // Transformers
    JsonTransformer jsonTransformer;
    ArgTransformer argTransformer;
    TerminalCommandTransformer commandTransformer;

    // Managers
    CommandHistoryManager commandHistoryManager;
    UserInputManager userInputManager;
};
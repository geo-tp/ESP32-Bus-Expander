#include "ANetworkController.h"

ANetworkController::ANetworkController(
    ITerminalView& terminalView,
    IInput& terminalInput,
    WifiService& wifiService,
    WifiOpenScannerService& wifiOpenScannerService,
    LittleFsService& littleFsService,
    NvsService& nvsService,
    ArgTransformer& argTransformer,
    UserInputManager& userInputManager,
    NmapService& nmapService,
    ICMPService& icmpService,
    HttpService& httpService,
    JsonTransformer& jsonTransformer,
    ModbusShell& modbusShell
)
: terminalView(terminalView),
  terminalInput(terminalInput),
  wifiService(wifiService),
  wifiOpenScannerService(wifiOpenScannerService),
  littleFsService(littleFsService),
  nvsService(nvsService),
  argTransformer(argTransformer),
  userInputManager(userInputManager),
  nmapService(nmapService),
  icmpService(icmpService),
  httpService(httpService),
  jsonTransformer(jsonTransformer),
  modbusShell(modbusShell)
{
}

/*
ICMP Ping
*/
void ANetworkController::handlePing(const TerminalCommand &cmd)
{
    if (!wifiService.isConnected()) {
        terminalView.println("Ping: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    const std::string host = cmd.getSubcommand();
    if (host.empty() || host == "-h" || host == "--help") {
        terminalView.println(icmpService.getPingHelp());
        return;
    }   
    
    auto args = argTransformer.splitArgs(cmd.getArgs());
    int pingCount = 5, pingTimeout = 1000, pingInterval = 200;

    for (int i=0;i<args.size();i++) {
        if (args[i].empty()) continue; // Skip empty args
        auto argument = args[i];
        if (argument == "-h" || argument == "--help") {
            terminalView.println(icmpService.getPingHelp());
            return;
        } else if (argument == "-c") {
            if (++i < args.size()) {
                if (!argTransformer.parseInt(args[i], pingCount) || args[i].empty()) {
                    terminalView.println("Invalid count value.");
                    return;
                }
            }
        } else if (argument == "-t") {
            if (++i < args.size()) {
                if (!argTransformer.parseInt(args[i], pingTimeout) || args[i].empty()) {
                    terminalView.println("Invalid timeout value.");
                    return;
                }
            }
        } else if (argument == "-i") {
            if (++i < args.size()) {
                if (!argTransformer.parseInt(args[i], pingInterval) || args[i].empty()) {
                    terminalView.println("Invalid interval value.");
                    return;
                }
            }
        }
    }

    icmpService.startPingTask(host, pingCount, pingTimeout, pingInterval);
    while (!icmpService.isPingReady())
        vTaskDelay(pdMS_TO_TICKS(50));

    terminalView.print(icmpService.getReport());
}

/*
Discovery  
*/
void ANetworkController::handleDiscovery(const TerminalCommand &cmd)
{
    bool wifiConnected = wifiService.isConnected();
    phy_interface_t phy_interface = phy_interface_t::phy_none;

    // Which interface to scan
    auto mode = globalState.getCurrentMode();
    if (wifiConnected && mode == ModeEnum::WiFi){
        phy_interface = phy_interface_t::phy_wifi;
    }
    else {
        terminalView.println("Discovery: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    // Optional timeout argument
    int timeoutMs = 250;
    std::string timeoutStr = cmd.getSubcommand();

    if (!timeoutStr.empty()) {
        if (!argTransformer.isValidNumber(timeoutStr)) {
            terminalView.println("Usage: discovery [timeout_ms]");
            terminalView.println("Timeout must be a number between 5 and 5000 ms.");
            return;
        }

        timeoutMs = argTransformer.parseHexOrDec(timeoutStr);

        if (timeoutMs < 5) {
            timeoutMs = 5;
        }
        else if (timeoutMs > 5000) {
            timeoutMs = 5000;
        }
    }

    const std::string deviceIP = wifiService.getLocalIP();

    // Start discovery task
    icmpService.startDiscoveryTask(deviceIP, timeoutMs);

    while (!icmpService.isDiscoveryReady()) {
        // Display logs
        auto batch = icmpService.fetchICMPLog();
        for (auto& line : batch) {
            terminalView.println(line);
        }

        // Enter Press to stop
        int terminalKey = terminalInput.readChar();
        if (terminalKey == '\n' || terminalKey == '\r') {
            icmpService.stopICMPService();
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    delay(500);

    // Flush final logs
    for (auto& line : icmpService.fetchICMPLog()) {
        terminalView.println(line);
    }

    ICMPService::clearICMPLogging();
    icmpService.clearDiscoveryFlag();
}

/*
Nmap
*/
void ANetworkController::handleNmap(const TerminalCommand &cmd)
{
    // Check connection
    if (!wifiService.isConnected())
    {
        terminalView.println("Nmap: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    auto args = argTransformer.splitArgs(cmd.getArgs());

    // Parse args
    // Parse hosts first
    auto hosts_arg = cmd.getSubcommand();
    
    // First helper invoke
    if (hosts_arg.compare("-h") == 0 || hosts_arg.compare("--help") == 0  || hosts_arg.empty()){
        terminalView.println(nmapService.getHelpText());
        return;
    }

    if(!nmapService.parseHosts(hosts_arg)) {
        terminalView.println("Nmap: Invalid host.");
        return;
    }

    // Check the first char of args is '-'
    if (!args.empty() && (args[0].empty() || args[0][0] != '-')) {
        terminalView.println("Nmap: Options must start with '-' (ex: -p 22)");
        return;
    }

    nmapService.setArgTransformer(argTransformer);
    auto tokens = argTransformer.splitArgs(cmd.getArgs());
    auto options = NmapService::parseNmapArgs(tokens);
    this->nmapService.setOptions(options);
    
    // Second helper
    if (options.help) {
        terminalView.println(nmapService.getHelpText());
        return;
    }

    if (options.hasTrash){
        // TODO handle this better
        //terminalView.println("Nmap: Invalid options.");
    }

    if (options.hasPort) {
        nmapService.setLayer4(options.tcp);
        // Parse ports
        if (!nmapService.parsePorts(options.ports)) {
            terminalView.println("Nmap: invalid -p value. Use 80,22,443 or 1000-2000.");
            return;
        }
    } else {
        nmapService.setLayer4(options.tcp);
        // Set the most popular ports
        nmapService.setDefaultPorts(options.tcp);
        terminalView.println("Nmap: Using top 100 common ports (may take a few seconds)");
    }

    // Re-use it for ICMP pings
    nmapService.setICMPService(&icmpService);
    nmapService.startTask(options.verbosity);
    
    while(!nmapService.isReady()){
        delay(100);
    }

    terminalView.println(nmapService.getReport());
    nmapService.clean();
    
    terminalView.println("\r\n\nNmap: Scan finished.");
}

/*
HTTP
*/
void ANetworkController::handleHttp(const TerminalCommand &cmd)
{
    // Check connection
    if (!wifiService.isConnected())
    {
        terminalView.println("HTTP: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    const auto sub = cmd.getSubcommand();

    // http get <url>
    if (sub == "get" && !cmd.getArgs().empty()) {
        handleHttpGet(cmd);
        return;
    // PH for POST, PUT, DELETE
    } else if (sub == "post" || sub == "put" || sub == "delete") {
        terminalView.println("HTTP: Only GET implemented for now.");
        return;
    // http analyze <url>
    } else if (sub == "analyze") {
        handleHttpAnalyze(cmd);
        return;
    // http <url>
    } else if (!sub.empty() && cmd.getArgs().empty()) {
        handleHttpGet(cmd);
        return;
    } else {
        terminalView.println("Usage: http <get|post|put|delete> <url>");
    }
}

/*
HTTP GET
*/
void ANetworkController::handleHttpGet(const TerminalCommand &cmd)
{
    if (cmd.getSubcommand() == "get" && cmd.getArgs().empty())
    {
        terminalView.println("Usage: http get <url>");
        return;
    }

    // Support for http <url> or http get <url>
    auto arg = cmd.getArgs().empty() ? cmd.getSubcommand() : cmd.getArgs();
    std::string url = argTransformer.ensureHttpScheme(arg);

    terminalView.println("HTTP: Sending GET request to " + url + "...");
    httpService.startGetTask(url, 10000, 8192, true, 30000);

    // Wait until timeout or response is ready
    const unsigned long deadline = millis() + 10000;
    while (!httpService.isResponseReady() && millis() < deadline) {
        delay(50);
    }

    if (httpService.isResponseReady()) {
        terminalView.println("\n========== HTTP GET =============");
        terminalView.println(argTransformer.normalizeLines(httpService.lastResponse()));
        terminalView.println("=================================\n");

    } else {
        terminalView.println("\nHTTP: Error, request timed out");
    }

    httpService.reset();
}

/*
HTTP Analayze
*/
void ANetworkController::handleHttpAnalyze(const TerminalCommand& cmd)
{
    if (cmd.getArgs().empty()) {
        terminalView.println("Usage: http analyze <url>");
        return;
    }

    // Ensure URL has HTTP scheme and then extract host
    const std::string url  = argTransformer.ensureHttpScheme(cmd.getArgs());
    const std::string host = argTransformer.extractHostFromUrl(url);
    std::vector<std::string> lines;
    std::string resp;

    // === urlscan.io (last public scan) ====
    const std::string urlscanUrl =
        "https://urlscan.io/api/v1/search?datasource=scans&q=page.domain:" + host + "&size=1";

    terminalView.println("HTTP Analyze: " + urlscanUrl + " (latest public scan)...");
    resp = httpService.fetchJson(urlscanUrl, 8192);
    terminalView.println("\n===== URLSCAN LATEST =====");
    lines = jsonTransformer.toLines(jsonTransformer.dechunk(resp));
    for (auto& l : lines) terminalView.println(l);
    terminalView.println("==========================\n");


    // === ssllabs.com ====
    const std::string ssllabsUrl =
        "https://api.ssllabs.com/api/v3/analyze?host=" + url;
        

    terminalView.println("HTTP Analyze: " + ssllabsUrl + " (SSL Labs)...");
    resp = httpService.fetchJson(ssllabsUrl, 16384);

    terminalView.println("\n===== SSL LABS =====");
    lines = jsonTransformer.toLines(jsonTransformer.dechunk(resp));
    for (auto& l : lines) terminalView.println(l);
    terminalView.println("====================\n");
    httpService.reset();

    // ==== W3C HTML Validator (optional) ====
    auto confirm = userInputManager.readYesNo("\nAnalyze with the W3C Validator?", false);
    if (confirm) {
        const std::string w3cUrl =
            "https://validator.w3.org/nu/?out=json&doc=" + url;

        terminalView.println("Analyze: " + w3cUrl + " (W3C validator)...");
        resp = httpService.fetchJson(w3cUrl, 16384);
        terminalView.println("\n===== W3C RESULT =====");
        lines = jsonTransformer.toLines(jsonTransformer.dechunk(resp));
        for (auto& l : lines) terminalView.println(l);
        terminalView.println("======================\n");
        httpService.reset();
    }
    terminalView.println("\nHTTP Analyze: Finished.");
}

/*
Lookup
*/
void ANetworkController::handleLookup(const TerminalCommand& cmd)
{
    if (!wifiService.isConnected()) {
        terminalView.println("Lookup: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    const std::string sub = cmd.getSubcommand();
    if (sub == "mac") {
        handleLookupMac(cmd);
    } else if (sub == "ip") {
        handleLookupIp(cmd);
    } else {
        terminalView.println("Usage: lookup mac <addr>");
        terminalView.println("       lookup ip <addr or url>");
    }
}

/*
Lookup MAC
*/
void ANetworkController::handleLookupMac(const TerminalCommand& cmd)
{
    if (cmd.getArgs().empty()) {
        terminalView.println("Usage: lookup mac <mac addr>");
        return;
    }

    const std::string mac = cmd.getArgs();
    const std::string url = "https://api.maclookup.app/v2/macs/" + mac;

    terminalView.println("Lookup MAC: " + url + " ...");

    std::string resp = httpService.fetchJson(url, 1024 * 4);

    terminalView.println("\n===== MAC LOOKUP =====");
    auto lines = jsonTransformer.toLines(resp);
    for (auto& l : lines) {
        terminalView.println(l);
    }
    terminalView.println("======================\n");

    httpService.reset();
}

/*
Lookup IP info
*/
void ANetworkController::handleLookupIp(const TerminalCommand& cmd)
{
    if (cmd.getArgs().empty()) {
        terminalView.println("Usage: lookup ip <addr or url>");
        return;
    }

    const std::string target = cmd.getArgs();
    const std::string url = "http://ip-api.com/json/" + target;
    const std::string url2 = "https://isc.sans.edu/api/ip/" + target + "?json";
    std::vector<std::string> lines;
    std::string resp;

    terminalView.println("Lookup IP: " + url + " ...");

    resp = httpService.fetchJson(url, 1024 * 4);
    terminalView.println("\n===== IP LOOKUP =====");
    lines = jsonTransformer.toLines(resp);
    for (auto& l : lines) terminalView.println(l);
    terminalView.println("=====================");

    resp = httpService.fetchJson(url2, 1024 * 4);
    lines = jsonTransformer.toLines(resp);
    for (auto& l : lines) terminalView.println(l);
    terminalView.println("=====================\n");

    httpService.reset();
}

/*
Modbus
*/
void ANetworkController::handleModbus(const TerminalCommand &cmd)
{
    // Verify connection
    if (!wifiService.isConnected()) {
        terminalView.println("Modbus: You must be connected to Wi-Fi. Use 'connect' first.");
        return;
    }

    // Verify host
    const std::string host = cmd.getSubcommand();
    if (host.empty()) {
        terminalView.println("Usage: modbus <host> [port]");
        return;
    }

    // Port
    uint16_t port = 502; // default modbus
    if (argTransformer.isValidNumber(cmd.getArgs())) {
        port = argTransformer.parseHexOrDec16(cmd.getArgs());
    }

    // Start shell
    terminalView.println("Starting Modbus shell...");
    modbusShell.run(host, port);
}
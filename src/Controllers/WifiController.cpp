#include "Controllers/WifiController.h"
#include "Vendors/wifi_atks.h"
#include "Vendors/slave_unified_c5.h"

/*
Entry point for command
*/
void WifiController::handleCommand(const TerminalCommand &cmd)
{
    const auto &root = cmd.getRoot();

    if (root == "connect") handleConnect(cmd);
    else if (root == "disconnect") handleDisconnect(cmd);
    else if (root == "status") handleStatus(cmd);
    else if (root == "ap") handleAp(cmd);
    else if (root == "spam") handleApSpam();
    else if (root == "spoof") handleSpoof(cmd);
    else if (root == "scan") handleScan(cmd);
    else if (root == "probe") handleProbe();
    else if (root == "sniff") handleSniff(cmd);
    else if (root == "flood") handleFlood(cmd);
    else if (root == "repeater" || root == "extender") handleRepeater(cmd);  
    else if (root == "evil") handleEvil(cmd);
    else if (root == "deauth") handleDeauth(cmd);
    else if (root == "ping") handlePing(cmd);
    else if (root == "nmap") handleNmap(cmd);
    else if (root == "modbus") handleModbus(cmd);
    else if (root == "http") handleHttp(cmd);
    else if (root == "lookup") handleLookup(cmd);
    else if (root == "discovery") handleDiscovery(cmd);
    else if (root == "reset") handleReset();
    else if (root == "exit") handleExit(); // hidden command to signal master to exit
    else if (root == "handshake") handleHandshake(); // hidden command to signal detection
    else handleHelp();
}

/*
Ensure Configuration
*/
void WifiController::ensureConfigured()
{
    if (!configured)
    {
        handleConfig();
        configured = true;
    }
}

/*
Connect
*/
void WifiController::handleConnect(const TerminalCommand &cmd)
{
    std::string ssid;
    std::string password;
    auto args = argTransformer.splitArgs(cmd.getSubcommand());

    // No args provided, we need to check saved creds or scan and select networks
    if (cmd.getSubcommand().empty()) {

        // Check saved creds
        nvsService.open();
        ssid = nvsService.getString(state.getNvsSsidField());
        password = nvsService.getString(state.getNvsPasswordField());
        nvsService.close();
        auto confirmation = false;

        // Creds found
        if (!ssid.empty() && !password.empty()) {
            confirmation = userInputManager.readYesNo(
                "C5 WiFi: Use saved credentials for " + ssid + "? (Y/n)", true
            );
        } 

        // Select network if no creds or not confirmed
        if (!confirmation) {
            terminalView.println("Wifi: Scanning for available networks...");
            auto networks = wifiService.scanNetworks();
            if (networks.empty()) {
                terminalView.println("No Wi-Fi networks found.\n");
                return;
            }

            networks.push_back("Exit");
            int selectedIndex = userInputManager.readValidatedChoiceIndex("\nSelect Wi-Fi network", networks, 0);
            if (selectedIndex == networks.size() - 1) {
                terminalView.println("Exiting network selection....\n");
                return;
            }
            ssid = networks[selectedIndex];
            terminalView.println("Selected SSID: " + ssid);
            terminalView.print("Password: ");
            password = userInputManager.getLine();
        }

    // Args provided
    } else  {
        // Concatenate subcommand and args
        std::string full = cmd.getSubcommand() + " " + cmd.getArgs();
    
        // Find the last space to separate SSID and password
        size_t pos = full.find_last_of(' ');
        if (pos == std::string::npos || pos == full.size() - 1) {
            terminalView.println("Usage: connect <ssid> <password>");
            return;
        }
        ssid = full.substr(0, pos);
        password = full.substr(pos + 1);
    }

    terminalView.println("C5 WiFi: Connecting to " + ssid + "...");

    wifiService.setModeApSta();
    wifiService.connect(ssid, password);
    if (wifiService.isConnected()) {
        terminalView.println("\nC5 WiFi: ✅ Connected successfully.\n");

        // Save creds
        nvsService.open();
        nvsService.saveString(state.getNvsSsidField(), ssid);
        nvsService.saveString(state.getNvsPasswordField(), password);
        nvsService.close();
    } else {
        terminalView.println("\nC5 WiFi: Connection failed.\n");
        wifiService.reset();
        delay(100);
    }
}

/*
Disconnect
*/
void WifiController::handleDisconnect(const TerminalCommand &cmd)
{
    wifiService.disconnect();
    terminalView.println("C5 WiFi: Disconnected.");
}

/*
Status
*/
void WifiController::handleStatus(const TerminalCommand &cmd)
{
    auto ssid     = wifiService.getSsid();     if (ssid.empty()) ssid = "N/A";
    auto bssid    = wifiService.getBssid();    if (bssid.empty()) bssid = "N/A";
    auto hostname = wifiService.getHostname(); if (hostname.empty()) hostname = "N/A";

    terminalView.println("\n=== C5 Wi-Fi Status ===");
    terminalView.println("Radio        : 2.4 GHz / 5 GHz");
    terminalView.println("Mode         : " + std::string(wifiService.getWifiModeRaw() == WIFI_MODE_AP ? "Access Point" : "Station"));
    terminalView.println("AP MAC       : " + wifiService.getMacAddressAp());
    terminalView.println("STA MAC      : " + wifiService.getMacAddressSta());
    terminalView.println("IP           : " + wifiService.getLocalIp());
    terminalView.println("Subnet       : " + wifiService.getSubnetMask());
    terminalView.println("Gateway      : " + wifiService.getGatewayIp());
    terminalView.println("DNS1         : " + wifiService.getDns1());
    terminalView.println("DNS2         : " + wifiService.getDns2());
    terminalView.println("Hostname     : " + hostname);

    terminalView.println("SSID         : " + ssid);
    terminalView.println("BSSID        : " + bssid);
    terminalView.println("Prov enabled : " + std::string(wifiService.isProvisioningEnabled() ? "Yes" : "No"));

    const int status = wifiService.getWifiStatusRaw();
    if (status == 3 /* WL_CONNECTED */) {
        terminalView.println("RSSI         : " + std::to_string(wifiService.getRssi()) + " dBm");
        terminalView.println("Channel      : " + std::to_string(wifiService.getChannel()));
    } else {
        terminalView.println("RSSI         : N/A");
        terminalView.println("Channel      : N/A");
    }

    terminalView.println("Mode         : " + std::string(wifiService.wifiModeToStr(wifiService.getWifiModeRaw())));
    terminalView.println("Status       : " + std::string(wifiService.wlStatusToStr(status)));
    terminalView.println("====================\n");
}

/*
Access Point
*/
void WifiController::handleAp(const TerminalCommand &cmd)
{
    auto ssid = cmd.getSubcommand();

    if (ssid.empty())
    {
        terminalView.println("Usage: ap <ssid> <password>");
        terminalView.println("       ap spam");
        return;
    }

    if (ssid == "spam") {
        handleApSpam();
        return;
    }
    
    if (ssid == "stop") {
        wifiService.stopAccessPoint();
        terminalView.println("C5 WiFi: Access Point stopped.\n");
        return;
    }

    auto full = cmd.getSubcommand() + " " + cmd.getArgs();

    // Find the last space to separate SSID and password
    size_t pos = full.find_last_of(' ');
    if (pos == std::string::npos || pos == full.size() - 1) {
        terminalView.println("Usage: ap <ssid> <password>");
        return;
    }
    ssid = full.substr(0, pos);
    auto password = full.substr(pos + 1);

    // Confirm forwarding
    if (wifiService.isConnected()) {
        auto forward = userInputManager.readYesNo("Enable internet access forwarding ?", true);
        if (forward) {
            handleRepeater(cmd);
            return;
        }
    }

    // Already connected, mode AP+STA
    if (wifiService.isConnected())
    {
        wifiService.setModeApSta();
    }
    else
    {
        wifiService.setModeApOnly();
    }

    if (wifiService.startAccessPoint(ssid, password))
    {
        terminalView.println("\nWiFi: Access Point is started, no forwarding...\n");
        terminalView.println("  SSID            : " + ssid);
        std::string apPassMasked = password.empty() ? "" : std::string(password.length(), '*');
        std::string first2 = password.substr(0, password.size() >= 2 ? 2 : 1);
        apPassMasked = first2 + "********" + std::string(1, password.back()); 
        terminalView.println("  Password        : " + (apPassMasked.empty() ? "(open)" : apPassMasked));
        terminalView.println("  Access point IP : " + wifiService.getApIp());

        auto nvsSsidField = state.getNvsSsidField();
        auto nvsPasswordField = state.getNvsPasswordField();
        auto ssid = nvsService.getString(nvsSsidField, "");
        auto password = nvsService.getString(nvsPasswordField, "");

        // Try to reconnect to saved C5 WiFi
        if (!ssid.empty() && !password.empty())
        {
            wifiService.connect(ssid, password);
        }

        if (wifiService.isConnected())
        {
            terminalView.println("  Station IP      : " + wifiService.getLocalIp());
        }
        terminalView.println("");

        terminalView.println("  Use 'ap stop' to stop the access point\n");
    }
    else
    {
        terminalView.println("C5 WiFi: Failed to start Access Point.");
    }
}

/*
AP Spam
*/
void WifiController::handleApSpam()
{
    terminalView.println("C5 WiFi: Starting beacon spam on 5 GHz channels... Press [ENTER] to stop.");
    while (true)
    {
        beaconCreate("", 0, 0); // func from Vendors/wifi_atks.h

        // Enter press to stop
        char key = terminalInput.readChar();
        if (key == '\r' || key == '\n') break;
        delay(10);
    }

    terminalView.println("C5 WiFi: Beacon spam stopped.\n");
}

/*
Scan
*/
void WifiController::handleScan(const TerminalCommand &)
{
    terminalView.println("C5 WiFi: Scanning for networks...");
    delay(300);

    auto networks = wifiService.scanDetailedNetworks();

    for (const auto &net : networks)
    {
        std::string line = "  SSID: " + net.ssid;
        line += " | Sec: " + wifiService.encryptionTypeToString(net.encryption);
        line += " | BSSID: " + net.bssid;
        line += " | CH: " + std::to_string(net.channel);
        line += " | RSSI: " + std::to_string(net.rssi) + " dBm";
        if (net.open)
            line += " [open]";
        if (net.vulnerable)
            line += " [vulnerable]";
        if (net.hidden)
            line += " [hidden]";

        terminalView.println(line);
    }

    if (networks.empty())
    {
        terminalView.println("C5 WiFi: No networks found.");
    }
}

/*
Probe
*/
void WifiController::handleProbe() 
{
    terminalView.println("WIFI: Starting probe for internet access on open networks...");
    terminalView.println("\n [⚠️  WARNING] ");
    terminalView.println(" This will try to connect to surrounding open networks.\n");

    // Confirm before starting
    auto confirmation = userInputManager.readYesNo("Start Wi-Fi probe to find internet access?", false);
    if (!confirmation) {
        terminalView.println("WIFI: Probe cancelled.\n");
        return;
    }

    // Stop any existing probe
    if (wifiOpenScannerService.isOpenProbeRunning()) {
        wifiOpenScannerService.stopOpenProbe();
    }
    wifiOpenScannerService.clearProbeLog();

    // Start the open probe service
    if (!wifiOpenScannerService.startOpenProbe()) {
        terminalView.println("WIFI: Failed to start probe.\n");
        return;
    }

    terminalView.println("WIFI: Probe for internet access... Press [ENTER] to stop.\n");

    // Start the open probe task
    while (wifiOpenScannerService.isOpenProbeRunning()) {
        // Display logs
        auto batch = wifiOpenScannerService.fetchProbeLog();
        for (auto& ln : batch) {
            terminalView.println(ln.c_str());
        }

        // Enter Press to stop
        int ch = terminalInput.readChar();
        if (ch == '\n' || ch == '\r') {
            wifiOpenScannerService.stopOpenProbe();
            break;
        }

        delay(10);
    }

    // Flush final logs
    for (auto& ln : wifiOpenScannerService.fetchProbeLog()) {
        terminalView.println(ln.c_str());
    }
    terminalView.println("WIFI: Open-Wifi probe ended.\n");
}

/*
Sniff
*/
void WifiController::handleSniff(const TerminalCommand &cmd)
{
    std::vector<std::string> modes = {
        " Band 2.4 GHz",
        " Band 5 GHz",
        " Band 2.4 + 5 GHz",
        " Band All + Deauth + Handshake",
        " Exit"
    };

    int mode = userInputManager.readValidatedChoiceIndex(
        "Select sniff mode",
        modes,
        modes.size() - 1
    );

    if (mode == 4) return;

    if (mode == 3) {
        handleEvil(cmd);
        return;
    }

    terminalView.println("C5 WiFi Sniffing started... Press [ENTER] to stop.\n");

    wifiService.startPassiveSniffing();

    const uint8_t* ch5 = wifiService.getWifi5ghzChannels();
    size_t ch5Count = wifiService.getWifi5ghzChannelsCount();

    size_t hopIndex = 0;
    unsigned long lastHop = 0;
    unsigned long lastPull = 0;

    while (true)
    {
        char key = terminalInput.readChar();
        if (key == '\r' || key == '\n')
            break;

        if (millis() - lastPull > 20)
        {
            auto logs = wifiService.getSniffLog();
            for (const auto &line : logs)
                terminalView.println(line);

            lastPull = millis();
        }

        if (millis() - lastHop > 100)
        {
            uint8_t channel;

            if (mode == 0) { // 2.4
                channel = (hopIndex % 13) + 1;
                hopIndex++;
            }
            else if (mode == 1) { // 5 GHz
                channel = ch5[hopIndex % ch5Count];
                hopIndex++;
            }
            else { // both
                size_t total = 13 + ch5Count;

                if (hopIndex % total < 13)
                    channel = (hopIndex % 13) + 1;
                else
                    channel = ch5[(hopIndex - 13) % ch5Count];

                hopIndex++;
            }

            wifiService.switchChannel(channel);
            lastHop = millis();
        }

        delay(5);
    }

    wifiService.stopPassiveSniffing();
    terminalView.println("C5 WiFi Sniffing stopped.\n");
}

/*
Spoof
*/
void WifiController::handleSpoof(const TerminalCommand &cmd)
{
    auto mode = cmd.getSubcommand();
    auto mac  = cmd.getArgs();

    if (mode.empty() && mac.empty())
    {
        terminalView.println("Usage: spoof sta 02:AA:BB:CC:DD:EE");
        terminalView.println("       spoof ap 02:AA:BB:CC:DD:EE");
        return;
    }

    // user entered: spoof <mac> -> assume station mode
    if (mac.empty())
    {
        mac = mode;
        mode = "sta";
    }

    if (mode != "sta" && mode != "ap")
    {
        terminalView.println("Invalid mode. Use 'sta' or 'ap'.");
        return;
    }

    WifiService::MacInterface iface =
        (mode == "sta")
            ? WifiService::MacInterface::Station
            : WifiService::MacInterface::AccessPoint;

    terminalView.println("WiFi: Spoofing " + mode + " MAC to " + mac + "...");

    bool ok = wifiService.spoofMacAddress(mac, iface);

    if (ok)
    {
        terminalView.println("WiFi: MAC spoofed successfully.");
    }
    else
    {
        terminalView.println("WiFi: Failed to spoof. Use a valid unicast MAC (ex: 02:AA:BB:CC:DD:EE).");
    }
}


/*
Repeater
*/
void WifiController::handleRepeater(const TerminalCommand& cmd)
{
    // Usage:
    // repeater
    // repeater [ap_ssid] [ap_pass]
    // repeater stop
    // repeater start (prompt for ap_ssid/ap_pass)
    // repeater start [ap_ssid] [ap_pass]

    std::string sub = cmd.getSubcommand();
    std::string args = cmd.getArgs();
    std::string apSsid = "";
    std::string apPass = "";
    std::string apPassMasked = "";
    const uint8_t maxConn = 10;

    // Must be connected first
    if (!wifiService.isConnected()) {
        terminalView.println("C5 WiFi Repeater: C5 WiFi not connected. Run 'connect' first.\n");
        return;
    }

    // Status   
    if (sub.empty() ) {
        sub = wifiService.isRepeaterRunning() ? "stop" : "start";
    }

    if (sub == "stop") {
        wifiService.stopRepeater();
        terminalView.println("C5 WiFi Repeater: Stop routing traffic between uplink and repeater.\n");
        return;
    }

    if (sub != "start") {
        if (!args.empty())
            args = sub + " " + args;
        else
            args = sub;
    }

    // Parse ap ssid/pass from args
    if (!args.empty()) {
        auto parts = argTransformer.splitArgs(args);

        if (parts.size() >= 1) apSsid = parts[0];
        if (parts.size() >= 2) apPass = parts[1];

        // If SSID had spaces, keep last token as pass and rest as SSID
        if (parts.size() > 2) {
            apPass = parts.back();
            apSsid.clear();
            for (size_t i = 0; i + 1 < parts.size(); ++i) {
                if (i) apSsid += " ";
                apSsid += parts[i];
            }
        }
    }

    // Prompt for missing info
    if (apSsid.empty()) {
        terminalView.println("\nWiFi Repeater: Forwarding traffic from uplink.");
        apSsid = userInputManager.readSanitizedString(
            "Enter Repeater SSID", 
            "esp32repeater", 
            /*onlyLetter=*/false
        );
        apSsid = apSsid.size() > 32 ? apSsid.substr(0, 32) : apSsid;
    }

    if (apPass.empty()) {
        apPass = userInputManager.readSanitizedString(
            "Enter Repeater Pass", 
            "esp32buspirate", 
            /*onlyLetter=*/false
        );
        if (apPass.size() > 64) {
            terminalView.println("Password must be at most 64 chars. Length reduced.");
            apPass = apPass.substr(0, 64);
        }
    }

    if (apPass.length() < 12 && !apPass.empty()) {
        terminalView.println("Password must be at least 12 characters.");
        return;
    }

    // at this point, password can't be empty
    std::string first2 = apPass.substr(0, apPass.size() >= 2 ? 2 : 1);
    apPassMasked = first2 + "********" + std::string(1, apPass.back());

    // Read current uplink creds from NVS
    std::string staSsid;
    std::string staPass;
    nvsService.open();
    staSsid = nvsService.getString(state.getNvsSsidField());
    staPass = nvsService.getString(state.getNvsPasswordField());
    nvsService.close();

    if (staSsid.empty()) {
        // fallback to current SSID if NVS empty
        staSsid = wifiService.getSsid();
    }

    if (staSsid.empty()) {
        terminalView.println("C5 WiFi Repeater: C5 WiFi not connected, run 'connect' first.\n");
        return;
    }

    terminalView.println("\nWiFi Repeater: Starting repeater...\n");

    // Start NAT repeater
    bool ok = wifiService.startRepeater(
        staSsid,
        staPass,
        apSsid,
        apPass,
        /*apChannel=*/1,
        /*maxConn=*/maxConn,
        /*timeoutMs=*/15000
    );

    if (!ok) {
        terminalView.println("\nWiFi Repeater: Failed to start. Abort\n");
        return;
    }

    terminalView.println("C5 WiFi Repeater: Routing traffic between uplink and repeater...");
    terminalView.println("\n  Uplink           : " + staSsid);
    terminalView.println("  Repeater SSID    : " + apSsid);
    terminalView.println("  Repeater Pass    : " + std::string(apPassMasked.empty() ? "(open)" :  apPassMasked));
    terminalView.println("  Repeater IP      : " + wifiService.getRepeaterIp());
    terminalView.println("  Max connections  : " + std::to_string(maxConn));
    terminalView.println("\n  Use 'repeater stop' to stop.");
    terminalView.println("");
}

/*
Evil Slave (from Evil Firmware)
https://github.com/7h30th3r0n3/Evil-M5Project/blob/main/slave/C5-Slave/slave_unified_C5.ino
*/
void WifiController::handleEvil(const TerminalCommand& cmd)
{
    terminalView.println("\n [⚠️  WARNING] ");
    terminalView.println(" This starts an active Wi-Fi sniff / deauth / capture.");
    terminalView.println(" Nearby access points and client traffic may be disrupted.");
    terminalView.println(" Use only on networks and devices you are explicitly authorized.\n");

    auto confirmation = userInputManager.readYesNo("Start Wi-Fi attack/sniffer module?", false);
    if (!confirmation) {
        terminalView.println("C5 WiFi: Start cancelled.\n");
        return;
    }

    setupEvilSlave();

    terminalView.println("C5 WiFi: Started sniffing... Press [ENTER] to stop.\n");

    while (true) {
        char c = terminalInput.readChar();
        if (c == '\r' || c == '\n') break;
        runEvilSlave(); // by default scan, deauth and sniff handshakes on all channels
    }

    terminalView.println("\nC5 WiFi: Stopped by user.\n");
}

/*
Flood
*/
void WifiController::handleFlood(const TerminalCommand& cmd)
{   
    // Channel
    uint8_t channel = 0;
    if (cmd.getSubcommand().empty()) {
        // prompt for channel
        channel = userInputManager.readValidatedUint8("Enter channel to flood", 1, 1, 165);
    } else {
        // parse channel from subcommand
        if (argTransformer.isValidNumber(cmd.getSubcommand())) {
            channel = argTransformer.toUint8(cmd.getSubcommand());
            if (channel < 1 || channel > 165) {
                terminalView.println("Invalid channel. Must be between 1 and 165.");
                return;
            }
        } else {
            terminalView.println("Usage: flood [channel]");
            return;
        }
    }
     
    terminalView.println("\nWiFi Flood: Starting on channel " + std::to_string(channel) + "... Press [ENTER] to stop.");

    while (true) {
        char c = terminalInput.readChar();
        if (c == '\r' || c == '\n') break;
        beaconCreate("", channel, 0); // func from Vendors/wifi_atks.h
     }

    terminalView.println("C5 WiFi Flood: Stopped by user.\n");
}

/*
Deauthenticate stations attack
*/
void WifiController::handleDeauth(const TerminalCommand &cmd)
{   
    auto target = cmd.getSubcommand();
    
    // Select network if no target provided
    if (target.empty()) {
        terminalView.println("Wifi: Scanning for available networks...");
        auto networks = wifiService.scanNetworks();
        int selectedIndex = userInputManager.readValidatedChoiceIndex("\nSelect Wi-Fi network", networks, 0);
        target = networks[selectedIndex];
    }

    // if the SSID have space in name, e.g "Router Wifi"
    if (!cmd.getArgs().empty())
    {
        target += " " + cmd.getArgs();
    }

    terminalView.println("C5 WiFi: Sending deauth to \"" + target + "\"...");

    bool ok = wifiService.deauthApBySsid(target);

    if (ok)
        terminalView.println("C5 WiFi: Deauth frames sent.");
    else
        terminalView.println("C5 WiFi: SSID not found.");
}

/*
Help
*/
void WifiController::handleHelp()
{
    terminalView.println("\nAvailable C5 WiFi commands:");
    terminalView.println("");
    terminalView.println("  connect [ssid] [password]  Connect to 2.4GHz or 5GHz Wi-Fi");
    terminalView.println("  disconnect                 Disconnect from current Wi-Fi");
    terminalView.println("  status                     Show C5 Wi-Fi status");
    terminalView.println("  scan                       Scan nearby 2.4GHz and 5GHz networks");
    terminalView.println("  discovery                  Run network discovery commands");
    terminalView.println("  probe                      Probe open networks for internet access");
    terminalView.println("  sniff                      Sniff 2.4GHz and 5GHz traffic");
    terminalView.println("  evil                       Start active sniff/deauth/handshake capture mode");
    terminalView.println("  spam                       Start beacon spam on 5GHz channels");
    terminalView.println("  flood [channel]            Flood beacon frames on a channel");
    terminalView.println("  deauth [ssid]              Send 2.4GHz or 5GHz deauth to an AP");
    terminalView.println("  ap <ssid> <password>       Start access point");
    terminalView.println("  repeater                   Start or stop Wi-Fi repeater mode");
    terminalView.println("  spoof sta <mac>            Spoof station MAC address");
    terminalView.println("  spoof ap <mac>             Spoof access point MAC address");
    terminalView.println("  ping <host>                Send ICMP ping to a host");
    terminalView.println("  nmap <host> [-p port]      Scan ports on a host");
    terminalView.println("  http get <url>             HTTP(s) GET request");
    terminalView.println("  http analyze <url>         Get analysis report for a URL");
    terminalView.println("  lookup mac|ip <host>       Run lookup utilities (IP, MAC, etc.)");
    terminalView.println("  modbus <host> [port]       Open Modbus-related commands");
    terminalView.println("  reset                      Reset C5 Wi-Fi interface");
    terminalView.println("  exit                       Exit the C5 WiFi mode");
    terminalView.println("");
}

/*
Reset
*/
void WifiController::handleReset()
{
    wifiService.reset();
    terminalView.println("C5 WiFi: Interface reset. Disconnected.");
}

/*
Config
*/
void WifiController::handleConfig()
{
    // Not needed for now
}

/*
Handshake (detect from master)
*/
void WifiController::handleHandshake()
{
    // Just send a seq that will be detected by the master 
    terminalView.println("[[BP-HANDSHAKE-OK]]");
}

/*
Exit (signal from master)
*/
void WifiController::handleExit()
{   
    // Nothing for now, handled by the master
    // could be used to do something on exit signal
    // terminalView.println("[[BP-EXIT]]");
}
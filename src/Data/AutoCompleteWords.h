static const char* const autoCompleteWords[] = {

    // --- WIFI ---
    "connect", "probe", "deauth", "disconnect", "ap", "ap spam",
    "spam", "sniff", "scan", "exit", "flood", "repeater", "extender",
    "reset", "reboot", "spoof", "deauth", "status", "discovery", "evil", "nmap",
    "http get", "http analyze", "lookup", "modbus", "ping",

    // --- ZIGBEE ---
    "start", "setchannel", "events", "monitor",
#if defined(ZIGBEE_MODE_ZCZR)
    "permit", "permit off", "pair", "devices",
#elif defined(ZIGBEE_MODE_ED)
    "bindings", "device", "on", "off", "toggle", "dim", "color",
    "rgb", "hsv", "settemp", "sethum", "setocc", "report",
    "device light", "device dimlight", "device colorlight",
    "device switch", "device tempsensor", "device occupancy",
    "device fan", "device outlet", "device rangeextender", "device none",
#endif

    nullptr
};

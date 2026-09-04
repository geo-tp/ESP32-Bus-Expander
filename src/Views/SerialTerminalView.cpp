#include "SerialTerminalView.h"

void SerialTerminalView::initialize() {
#if ARDUINO_USB_MODE
    // USB Serial/JTAG console: no pin muxing, only the baud is configurable
    Serial.begin(baudrate);
#else
    Serial.begin(baudrate, SERIAL_8N1, rxPin, txPin);
#endif
    while (!Serial) {
        delay(10);
    }
}

void SerialTerminalView::welcome() {

    GlobalState& state = GlobalState::getInstance();
    std::string version = state.getVersion();

    Serial.println("  _____                          _           ");
    Serial.println(" | ____|_  ___ __   __ _ _ __ __| | ___ _ __ ");
    Serial.println(" |  _| \\ \\/ / '_ \\ / _` | '__/ _` |/ _ \\ '__|");
    Serial.println(" | |___ >  <| |_) | (_| | | | (_| |  __/ |   ");
    Serial.println(" |_____/_/\\_\\ .__/ \\__,_|_|  \\__,_|\\___|_|   ");
    Serial.println("            |_|                              ");
    Serial.println();
    Serial.println("              C5 SLAVE INTERFACE");
    Serial.println();
    Serial.printf("     Version %s           Ready\n", version.c_str());
    Serial.println();
    Serial.println(" This device acts as a UART bridge to the ESP32-C5 slave firmware.");
    Serial.println(" All commands and output are provided directly by the C5.");
    Serial.println();
    Serial.println(" Type 'mode' to start or 'help' for commands");
    Serial.println();
}

void SerialTerminalView::print(const std::string& text) {
    Serial.print(text.c_str());
}

void SerialTerminalView::print(const uint8_t data) {
    Serial.write(data);
}

void SerialTerminalView::println(const std::string& text) {
    Serial.println(text.c_str());
}

void SerialTerminalView::printPrompt(const std::string& mode) {
    if (!mode.empty()) {
        Serial.print(mode.c_str());
        Serial.print("> ");
    } else {
        Serial.print("> ");
    }
}

void SerialTerminalView::clear() {
    Serial.write(27);  // ESC
    Serial.print("[2J"); // erase screen
    Serial.write(27);
    Serial.print("[H");  // default cursor pos
}

void SerialTerminalView::waitPress() {
    Serial.println("\n\n\rPress any key to start...");
}

void SerialTerminalView::setBaudrate(unsigned long baud) {
    baudrate = baud;
}
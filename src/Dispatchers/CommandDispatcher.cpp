#include "CommandDispatcher.h"
#include "Data/AutoCompleteWords.h"

/*
Constructor
*/
CommandDispatcher::CommandDispatcher(DependencyProvider& provider)
    : provider(provider) {}

/*
Setup
*/
void CommandDispatcher::setup() {
    // Initialize serial
    provider.getTerminalView().initialize();
}

/*
Run loop
*/
void CommandDispatcher::run() {
    while (true) {
        auto mode = ModeEnumMapper::toString(state.getCurrentMode());
        provider.getTerminalView().printPrompt(mode);
        std::string action = getUserAction();
        if (action.empty()) {
            continue;
        }
        dispatch(action);
    }
}

/*
Dispatch
*/
void CommandDispatcher::dispatch(const std::string& raw) {
    if (raw.empty()) return;

    // Single terminal command
    TerminalCommand cmd = provider.getCommandTransformer().transform(raw);
    dispatchCommand(cmd);
}

/*
Dispatch Command
*/
void CommandDispatcher::dispatchCommand(const TerminalCommand& cmd) {
    // Could be used for other mode as zigbee etc, for now only WiFi
    // Mode change command
    if (cmd.getRoot() == "mode") {
        ModeEnum maybeNewMode = ModeEnumMapper::fromString(cmd.getSubcommand());
        if (maybeNewMode != ModeEnum::None) {
            setCurrentMode(maybeNewMode);
        } else {
            provider.getTerminalView().println("Unknown mode. Available: wifi, zigbee");
        }
        return;
    }

    // Mode specific command
    switch (state.getCurrentMode()) {
        case ModeEnum::WiFi:
            provider.getWifiController().handleCommand(cmd);
            break;

        case ModeEnum::Zigbee:
            provider.getZigbeeController().handleCommand(cmd);
            break;
    }
}

/*
Set Mode
*/
void CommandDispatcher::setCurrentMode(ModeEnum newMode) {
    // Release resources of current mode if needed
    auto currentMode = state.getCurrentMode();
    releaseMode(currentMode, newMode);
    state.setCurrentMode(newMode);

    // Ensure configuration for new mode
    switch (newMode) {
        case ModeEnum::WiFi:
            provider.getWifiController().ensureConfigured();
            break;

        case ModeEnum::Zigbee:
            provider.getZigbeeController().ensureConfigured();
            break;
    }
}

/*
Release mode resources
*/
void CommandDispatcher::releaseMode(ModeEnum currentMode, ModeEnum newMode) {
    if (currentMode == newMode) {
        return;
    }

    switch (currentMode) {
        case ModeEnum::WiFi:
            break;

        // Stop the radio when leaving Zigbee mode
        case ModeEnum::Zigbee:
            provider.getZigbeeController().ensureReleased();
            break;

        default:
            break;
    }
}

/*
User Action
*/
std::string CommandDispatcher::getUserAction() {
    std::string inputLine;
    auto mode = ModeEnumMapper::toString(state.getCurrentMode());
    size_t cursorIndex = 0;

    while (true) {
        char c = provider.getTerminalInput().readChar();
        if (c == '\0') continue;

        if (handleEscapeSequence(c, inputLine, cursorIndex, mode)) continue;
        if (handleEnterKey(c, inputLine)) return inputLine;
        if (handleBackspace(c, inputLine, cursorIndex, mode)) continue;
        if (handlePrintableChar(c, inputLine, cursorIndex, mode));
        if (handleTabCompletion(c, inputLine, cursorIndex, mode));
    }
}

/*
User Action: Escape
*/
bool CommandDispatcher::handleEscapeSequence(char c, std::string& inputLine, size_t& cursorIndex, const std::string& mode) {
    if (c != '\x1B') return false;

    if (provider.getTerminalInput().readChar() == '[') {
        char next = provider.getTerminalInput().readChar();

        if (next == 'A') {
            inputLine = provider.getCommandHistoryManager().up();
            cursorIndex = inputLine.length();
        } else if (next == 'B') {
            inputLine = provider.getCommandHistoryManager().down();
            cursorIndex = inputLine.length();
        } else if (next == 'C') {
            if (cursorIndex < inputLine.length()) {
                cursorIndex++;
                provider.getTerminalView().print("\x1B[C");
            }
            return true;
        } else if (next == 'D') {
            if (cursorIndex > 0) {
                cursorIndex--;
                provider.getTerminalView().print("\x1B[D");
            }
            return true;
        } else {
            return false;
        }

        provider.getTerminalView().print("\r" + mode + "> " + inputLine + "\033[K");
        return true;
    }

    return false;
}

/*
User Action: Enter
*/
bool CommandDispatcher::handleEnterKey(char c, const std::string& inputLine) {
    if (c != '\r' && c != '\n') return false;

    provider.getTerminalView().println("");
    provider.getCommandHistoryManager().add(inputLine);
    return true;
}

bool CommandDispatcher::handleTabCompletion(char c,
                                           std::string& inputLine,
                                           size_t& cursorIndex,
                                           const std::string& mode) {
    if (c != '\t') return false;

    // prefix up to cursor
    std::string prefix = inputLine.substr(0, cursorIndex);

    // history autocomplete
    std::string suggestion =
        provider.getCommandHistoryManager().autocomplete(prefix);

    // fallback dictionary autocomplete
    if (suggestion.empty()) {
        for (size_t i = 0; autoCompleteWords[i] != nullptr; ++i) {
            std::string w(autoCompleteWords[i]);

            if (w.size() >= prefix.size() &&
                w.compare(0, prefix.size(), prefix) == 0) {
                suggestion = w;
                break;
            }
        }
    }

    // apply suggestion
    if (!suggestion.empty()) {
        inputLine = suggestion;
        cursorIndex = inputLine.length();
        provider.getTerminalView().print("\r" + mode + "> " + inputLine + "\033[K");
    }

    return true;
}

/*
User Action: Backspace
*/
bool CommandDispatcher::handleBackspace(char c, std::string& inputLine, size_t& cursorIndex, const std::string& mode) {
    if (c != '\b' && c != 127) return false;
    if (cursorIndex == 0) return true;

    cursorIndex--;
    inputLine.erase(cursorIndex, 1);

    provider.getTerminalView().print("\r" + mode + "> " + inputLine + " \033[K");

    int moveBack = inputLine.length() - cursorIndex;
    for (int i = 0; i <= moveBack; ++i) {
        provider.getTerminalView().print("\x1B[D");
    }

    return true;
}

/*
User Action: Printable
*/
bool CommandDispatcher::handlePrintableChar(char c, std::string& inputLine, size_t& cursorIndex, const std::string& mode) {
    if (!std::isprint((unsigned char)c)) return false;

    if (inputLine.size() >= MAX_ALLOWED_COMMAND_LENGTH) {
        return true; // ignore extra chars
    }

    inputLine.insert(cursorIndex, 1, c);
    cursorIndex++;

    provider.getTerminalView().print("\r" + mode + "> " + inputLine + "\033[K");

    size_t moveBack = inputLine.length() - cursorIndex;
    for (size_t i = 0; i < moveBack; ++i) {
        provider.getTerminalView().print("\x1B[D");
    }

    return true;
}

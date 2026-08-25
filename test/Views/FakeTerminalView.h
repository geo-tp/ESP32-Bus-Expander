#pragma once

#include <string>
#include <vector>

#include "Interfaces/ITerminalView.h"

class FakeTerminalView final : public ITerminalView {
public:
    std::string output;
    std::vector<std::string> printCalls;
    std::vector<std::string> printlnCalls;

    void initialize() override {}
    void welcome() override {}

    void print(const std::string& text) override {
        printCalls.push_back(text);
        output += text;
    }

    void print(const uint8_t data) override {
        output += static_cast<char>(data);
        printCalls.push_back(std::string(1, static_cast<char>(data)));
    }

    void println(const std::string& text) override {
        printlnCalls.push_back(text);
        output += text;
        output += "\n";
    }

    void printPrompt(const std::string& mode = "HIZ") override {
        output += mode;
    }

    void waitPress() override {}

    void clear() override {
        output.clear();
        printCalls.clear();
        printlnCalls.clear();
    }

    // Test helper: true when any printed line contains the given text
    bool contains(const std::string& needle) const {
        return output.find(needle) != std::string::npos;
    }
};

#pragma once

#include <deque>
#include <string>

#include "Interfaces/IInput.h"

class FakeInput final : public IInput {
public:
    std::deque<char> blockingChars;
    std::deque<char> nonBlockingChars;
    uint32_t waitPressCalls = 0;

    char handler() override {
        if (blockingChars.empty()) {
            return '\n';
        }
        const char c = blockingChars.front();
        blockingChars.pop_front();
        return c;
    }

    char readChar() override {
        if (nonBlockingChars.empty()) {
            return '\n';
        }
        const char c = nonBlockingChars.front();
        nonBlockingChars.pop_front();
        return c;
    }

    void waitPress(uint32_t timeoutMs = 0) override {
        (void)timeoutMs;
        ++waitPressCalls;
    }
};

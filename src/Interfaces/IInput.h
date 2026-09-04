#pragma once

#include <string>
#include <cstdint>

// Interface for terminal input
// This is the interface expected by the CommandDispatcher to handle user input.
// It abstracts how input is received (from keyboard, serial, web, etc.).

class IInput {
public:
    virtual ~IInput() = default;

    // Blocking read
    virtual char handler() = 0;

    // Non blocking read
    virtual char readChar() = 0;

    // Wait an inpout
    virtual void waitPress(uint32_t timeoutMs = 0) = 0;
    
};
#include <unity.h>

#include "Enums/ModeEnum.h"

void runModeEnumTests() {
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ModeEnum::WiFi),
                          static_cast<int>(ModeEnumMapper::fromString("wifi")));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ModeEnum::WiFi),
                          static_cast<int>(ModeEnumMapper::fromString("C5 WIFI")));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ModeEnum::Zigbee),
                          static_cast<int>(ModeEnumMapper::fromString("zigbee")));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ModeEnum::None),
                          static_cast<int>(ModeEnumMapper::fromString("unknown")));
}
#include <unity.h>

#include "Enums/ZigbeeRoleEnum.h"

namespace zigbee_role_enum_tests {

void test_from_string_accepts_coordinator_aliases() {
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Router;
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("coordinator", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Coordinator), static_cast<int>(role));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("zc", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Coordinator), static_cast<int>(role));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("c", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Coordinator), static_cast<int>(role));
}

void test_from_string_accepts_router_aliases() {
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("router", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Router), static_cast<int>(role));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("zr", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Router), static_cast<int>(role));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("r", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Router), static_cast<int>(role));
}

void test_from_string_accepts_end_device_aliases() {
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("ed", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::EndDevice), static_cast<int>(role));
    role = ZigbeeRoleEnum::Coordinator;
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("enddevice", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::EndDevice), static_cast<int>(role));
    role = ZigbeeRoleEnum::Coordinator;
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::fromString("zed", role));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::EndDevice), static_cast<int>(role));
}

void test_from_string_is_case_sensitive_and_rejects_unknown() {
    ZigbeeRoleEnum role = ZigbeeRoleEnum::Coordinator;
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::fromString("COORDINATOR", role));
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::fromString("ROUTER", role));
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::fromString("Coordinator", role));
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::fromString("zigbee", role));
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::fromString("", role));
}

void test_to_string_reports_uppercase_roles() {
    TEST_ASSERT_EQUAL_STRING("COORDINATOR",
                             ZigbeeRoleEnumMapper::toString(ZigbeeRoleEnum::Coordinator).c_str());
    TEST_ASSERT_EQUAL_STRING("ROUTER",
                             ZigbeeRoleEnumMapper::toString(ZigbeeRoleEnum::Router).c_str());
    TEST_ASSERT_EQUAL_STRING("ENDDEVICE",
                             ZigbeeRoleEnumMapper::toString(ZigbeeRoleEnum::EndDevice).c_str());
}

void test_is_valid_channel_accepts_11_to_26_only() {
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::isValidChannel(10));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::isValidChannel(11));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::isValidChannel(15));
    TEST_ASSERT_TRUE(ZigbeeRoleEnumMapper::isValidChannel(26));
    TEST_ASSERT_FALSE(ZigbeeRoleEnumMapper::isValidChannel(27));
}

}  // namespace zigbee_role_enum_tests

void runZigbeeRoleEnumTests() {
    using namespace zigbee_role_enum_tests;
    RUN_TEST(test_from_string_accepts_coordinator_aliases);
    RUN_TEST(test_from_string_accepts_router_aliases);
    RUN_TEST(test_from_string_accepts_end_device_aliases);
    RUN_TEST(test_from_string_is_case_sensitive_and_rejects_unknown);
    RUN_TEST(test_to_string_reports_uppercase_roles);
    RUN_TEST(test_is_valid_channel_accepts_11_to_26_only);
}

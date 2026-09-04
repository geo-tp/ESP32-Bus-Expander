#include <unity.h>

// Production units exercised by the native test runner.
#include "../src/Transformers/ArgTransformer.cpp"
#include "../src/Managers/UserInputManager.cpp"
#include "../src/Controllers/ZigbeeController.cpp"

#include "Controllers/test_ZigbeeController.cpp"
#include "Enums/test_ZigbeeRoleEnum.cpp"
#include "Enums/test_ModeEnum.cpp"

void setUp() {}
void tearDown() {}

int main() {
    UNITY_BEGIN();
    runZigbeeRoleEnumTests();
    runModeEnumTests();
    runZigbeeControllerTests();
    return UNITY_END();
}

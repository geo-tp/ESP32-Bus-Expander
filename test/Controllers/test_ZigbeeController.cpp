#include <unity.h>

#include "Controllers/ZigbeeController.h"
#include "../Inputs/FakeInput.h"
#include "../Services/FakeZigbeeService.h"
#include "../Views/FakeTerminalView.h"

namespace zigbee_controller_tests {

struct ZigbeeControllerFixture {
    FakeTerminalView view;
    FakeInput input;
    FakeZigbeeService service;
    ArgTransformer argTransformer;
    UserInputManager userInput{view, input, argTransformer};
    ZigbeeController controller{
        view,
        input,
        service,
        argTransformer,
        userInput
    };

    ZigbeeControllerFixture() {
        GlobalState::getInstance().setCurrentMode(ModeEnum::Zigbee);
    }

    void consumeBanner() {
        view.output.clear();
        view.printCalls.clear();
        view.printlnCalls.clear();
    }
};

void test_start_without_role_defaults_to_coordinator_and_opens_network() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("start"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Coordinator),
                          static_cast<int>(fixture.service.startRoles[0]));
    TEST_ASSERT_EQUAL_UINT8(15, fixture.service.startChannels[0]);
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.permitCalls);
    TEST_ASSERT_EQUAL_UINT8(180, fixture.service.permitSeconds[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Starting Zigbee as COORDINATOR"));
}

void test_start_router_starts_stack_in_router_role() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("start", "router"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Router),
                          static_cast<int>(fixture.service.startRoles[0]));
}

void test_start_accepts_short_aliases() {
    ZigbeeControllerFixture fixture;
    fixture.controller.handleCommand(TerminalCommand("start", "zc"));
    fixture.controller.handleCommand(TerminalCommand("stop"));
    fixture.controller.handleCommand(TerminalCommand("start", "zr"));

    TEST_ASSERT_EQUAL_UINT32(2, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Coordinator),
                          static_cast<int>(fixture.service.startRoles[0]));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::Router),
                          static_cast<int>(fixture.service.startRoles[1]));
}

void test_start_with_invalid_role_reports_error_without_touching_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("start", "bridge"));

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.permitCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Unknown role. Usage: start [coordinator|router|enddevice]"));
}

void test_status_prints_zigbee_status_line() {
    ZigbeeControllerFixture fixture;
    fixture.service.status.started = true;
    fixture.service.status.connected = true;
    fixture.service.status.role = ZigbeeRoleEnum::Coordinator;
    fixture.service.status.channel = 15;
    fixture.service.status.panId = 0x1A2B;

    fixture.controller.handleCommand(TerminalCommand("status"));

    TEST_ASSERT_TRUE(fixture.view.contains("zigbee{"));
    TEST_ASSERT_TRUE(fixture.view.contains("supported=true"));
    TEST_ASSERT_TRUE(fixture.view.contains("started=true"));
    TEST_ASSERT_TRUE(fixture.view.contains("connected=true"));
    TEST_ASSERT_TRUE(fixture.view.contains("role=COORDINATOR"));
    TEST_ASSERT_TRUE(fixture.view.contains("channel=15}"));
}

void test_channel_within_range_is_forwarded_to_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("channel", "25"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setChannelCalls);
    TEST_ASSERT_EQUAL_UINT8(25, fixture.service.channelsSet[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Primary channel set to 25."));
}

void test_channel_outside_range_reports_error_without_recording() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("channel", "9"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.setChannelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid channel. Valid range is 11..26."));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("channel", "27"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.setChannelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid channel. Valid range is 11..26."));
}

void test_channel_without_number_shows_usage() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("channel"));

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.setChannelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Usage: channel <11-26>"));
}

void test_permit_defaults_to_60_seconds_without_arguments() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("permit"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.permitCalls);
    TEST_ASSERT_EQUAL_UINT8(60, fixture.service.permitSeconds[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Network open for joining devices for 60s."));
}

void test_permit_with_seconds_argument_uses_given_value() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("permit", "30"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.permitCalls);
    TEST_ASSERT_EQUAL_UINT8(30, fixture.service.permitSeconds[0]);
}

void test_permit_failure_reports_closed_network() {
    ZigbeeControllerFixture fixture;
    fixture.service.permitResult = false;

    fixture.controller.handleCommand(TerminalCommand("permit", "30"));

    TEST_ASSERT_TRUE(fixture.view.contains("Cannot open network"));
}

void test_stop_calls_service_stop() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("stop"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.stopCalls);
    TEST_ASSERT_FALSE(fixture.service.status.started);
    TEST_ASSERT_TRUE(fixture.view.contains("Zigbee stack stopped."));
}

void test_reset_calls_factory_reset_and_reports_failure() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("reset"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.resetCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Zigbee network state erased."));

    fixture.consumeBanner();
    fixture.service.resetResult = false;
    fixture.controller.handleCommand(TerminalCommand("reset"));
    TEST_ASSERT_EQUAL_UINT32(2, fixture.service.resetCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Factory reset failed."));
}

void test_config_prints_current_configuration() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("config"));

    TEST_ASSERT_TRUE(fixture.view.contains("zigbee{"));
}

void test_ensure_released_stops_stack_and_resets_configured_flag() {
    ZigbeeControllerFixture fixture;

    fixture.controller.ensureConfigured();
    fixture.controller.ensureReleased();
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.stopCalls);

    fixture.consumeBanner();
    fixture.controller.ensureConfigured();
    TEST_ASSERT_TRUE(fixture.view.contains("Zigbee mode. Type 'help' to list commands."));
}

void test_ensure_released_skips_stop_on_unsupported_chip_but_resets_flag() {
    ZigbeeControllerFixture fixture;
    fixture.service.supportedFlag = false;
    fixture.controller.ensureConfigured();

    fixture.controller.ensureReleased();

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.stopCalls);
}

void test_unsupported_chip_warns_and_never_reaches_service_on_start() {
    ZigbeeControllerFixture fixture;
    fixture.service.supportedFlag = false;
    fixture.service.status.supported = false;

    fixture.controller.handleCommand(TerminalCommand("start"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.startCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("no Zigbee radio"));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("stop"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.stopCalls);

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("status"));
    TEST_ASSERT_TRUE(fixture.view.contains("zigbee{"));
    TEST_ASSERT_TRUE(fixture.view.contains("supported=false"));
}

void test_unknown_command_displays_help() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("wat"));

    TEST_ASSERT_TRUE(fixture.view.contains("Zigbee commands:"));
    TEST_ASSERT_TRUE(fixture.view.contains("start [coordinator|router|enddevice]"));
}

void test_start_failure_reports_stack_error() {
    ZigbeeControllerFixture fixture;
    fixture.service.startResult = false;

    fixture.controller.handleCommand(TerminalCommand("start"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.permitCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Failed to start the Zigbee stack."));
}

void test_channel_change_while_started_hints_restart_needed() {
    ZigbeeControllerFixture fixture;
    fixture.service.status.started = true;
    fixture.service.status.channel = 15;
    fixture.controller.handleCommand(TerminalCommand("channel", "20"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setChannelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Channel applies after 'stop' + 'start'."));
}

void test_start_end_device_role_is_forwarded_to_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("start", "ed"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startCalls);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeRoleEnum::EndDevice),
                          static_cast<int>(fixture.service.startRoles[0]));
    TEST_ASSERT_TRUE(fixture.view.contains("Starting Zigbee as ENDDEVICE"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.permitCalls);
}

void test_device_light_propagates_endpoint_and_confirms() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("device", "light"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setEndpointCalls);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ZigbeeEndpointEnum::Light),
                          static_cast<int>(fixture.service.endpointsSet[0]));
    TEST_ASSERT_TRUE(fixture.view.contains("Tool will act as On/Off Light after 'start'."));
}

void test_device_invalid_shows_usage_without_touching_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("device", "bulb"));

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.setEndpointCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Usage: device <none|light|dimlight|colorlight|switch|"));
}

void test_on_off_toggle_always_delegate_to_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("on"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendOnCalls);
    TEST_ASSERT_TRUE(fixture.service.onStates[0]);

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("off"));
    TEST_ASSERT_EQUAL_UINT32(2, fixture.service.sendOnCalls);
    TEST_ASSERT_FALSE(fixture.service.onStates[1]);

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("toggle"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.toggleCalls);
}

void test_on_failure_reports_send_error_when_service_fails() {
    ZigbeeControllerFixture fixture;
    fixture.service.sendResult = false;

    fixture.controller.handleCommand(TerminalCommand("on"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendOnCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Failed to send command"));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("toggle"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.toggleCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Failed to send command"));
}

void test_devices_with_empty_list_reports_no_devices_bound() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("devices"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.getBoundListCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("No devices bound"));
}

void test_devices_prints_each_bound_address() {
    ZigbeeControllerFixture fixture;
    fixture.service.boundList = {"1A2B", "3C4D"};

    fixture.controller.handleCommand(TerminalCommand("devices"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.getBoundListCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("1A2B"));
    TEST_ASSERT_TRUE(fixture.view.contains("3C4D"));
    TEST_ASSERT_FALSE(fixture.view.contains("No devices bound"));
}

void test_scan_polls_status_then_prints_table_with_pan_and_channel() {
    ZigbeeControllerFixture fixture;
    fixture.service.scanStatusQueue = {-1, -1, 3};

    ZigbeeNetworkInfo first;
    first.panId = 0x1A2B;
    first.channel = 15;
    ZigbeeNetworkInfo second;
    second.panId = 0x3C4D;
    second.channel = 20;
    fixture.service.scanResults = {first, second};

    fixture.controller.handleCommand(TerminalCommand("scan", "3"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startScanCalls);
    TEST_ASSERT_EQUAL_UINT8(3, fixture.service.startScanDurations[0]);
    TEST_ASSERT_EQUAL_UINT32(3, fixture.service.getScanStatusCalls);
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.takeScanResultsCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("PAN"));
    TEST_ASSERT_TRUE(fixture.view.contains("CH"));
    TEST_ASSERT_TRUE(fixture.view.contains("1A2B"));
    TEST_ASSERT_TRUE(fixture.view.contains("3C4D"));
    TEST_ASSERT_TRUE(fixture.view.contains("15"));
    TEST_ASSERT_TRUE(fixture.view.contains("20"));
}

void test_scan_without_duration_defaults_to_2_seconds() {
    ZigbeeControllerFixture fixture;
    fixture.service.scanStatusQueue = {0};

    fixture.controller.handleCommand(TerminalCommand("scan"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.startScanCalls);
    TEST_ASSERT_EQUAL_UINT8(2, fixture.service.startScanDurations[0]);
}

void test_scan_with_invalid_duration_shows_usage_without_starting() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("scan", "0"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.startScanCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid scan duration. Usage: scan [1-4]"));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("scan", "5"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.startScanCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid scan duration. Usage: scan [1-4]"));
}

void test_help_mentions_new_endpoint_scan_and_switch_commands() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("help"));

    TEST_ASSERT_TRUE(fixture.view.contains("Zigbee commands:"));
    TEST_ASSERT_TRUE(fixture.view.contains("device <type>"));
    TEST_ASSERT_TRUE(fixture.view.contains("scan [1-4]"));
    TEST_ASSERT_TRUE(fixture.view.contains("on | off | toggle [group]"));
    TEST_ASSERT_TRUE(fixture.view.contains("dim <0-255 | 0-100%> [group]"));
    TEST_ASSERT_TRUE(fixture.view.contains("color rgb|hsv <v v v> [group]"));
    TEST_ASSERT_TRUE(fixture.view.contains("events"));
}

void test_device_accepts_all_new_endpoint_names() {
    ZigbeeControllerFixture fixture;

    struct {
        const char* name;
        ZigbeeEndpointEnum expected;
    } cases[] = {
        {"light", ZigbeeEndpointEnum::Light},
        {"dimlight", ZigbeeEndpointEnum::DimmableLight},
        {"colorlight", ZigbeeEndpointEnum::ColorLight},
        {"switch", ZigbeeEndpointEnum::Switch},
        {"tempsensor", ZigbeeEndpointEnum::TempSensor},
        {"occupancy", ZigbeeEndpointEnum::OccupancySensor},
        {"fan", ZigbeeEndpointEnum::Fan},
        {"outlet", ZigbeeEndpointEnum::Outlet},
        {"rangeextender", ZigbeeEndpointEnum::RangeExtender},
        {"none", ZigbeeEndpointEnum::None},
    };

    for (const auto& c : cases) {
        fixture.controller.handleCommand(TerminalCommand("device", c.name));
    }

    // All names must have been forwarded in order
    TEST_ASSERT_EQUAL_UINT32(10, fixture.service.setEndpointCalls);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        TEST_ASSERT_EQUAL_INT(static_cast<int>(cases[i].expected),
                              static_cast<int>(fixture.service.endpointsSet[i]));
    }
}

void test_on_with_group_token_forwards_group_address() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("on", "0x1234"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendOnCalls);
    TEST_ASSERT_EQUAL_UINT16(0x1234, fixture.service.onGroups[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Group: 0x1234"));
}

void test_toggle_without_group_defaults_to_zero() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("toggle"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.toggleCalls);
    TEST_ASSERT_EQUAL_UINT16(0, fixture.service.toggleGroups[0]);
}

void test_dim_percent_suffix_scales_to_level() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("dim", "50%"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendLevelCalls);
    TEST_ASSERT_EQUAL_UINT8(128, fixture.service.levelsSent[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("level 128"));
}

void test_dim_raw_value_passes_through() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("dim", "200"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendLevelCalls);
    TEST_ASSERT_EQUAL_UINT8(200, fixture.service.levelsSent[0]);
}

void test_dim_invalid_values_are_rejected_without_sending() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("dim", "300"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.sendLevelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid level."));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("dim", "101%"));
    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.sendLevelCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid percent."));
}

void test_dim_with_group_forwards_both() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("dim", "128", "0xABCD"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendLevelCalls);
    TEST_ASSERT_EQUAL_UINT8(128, fixture.service.levelsSent[0]);
    TEST_ASSERT_EQUAL_UINT16(0xABCD, fixture.service.levelGroups[0]);
}

void test_color_rgb_forwards_components() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("color", "rgb", "10 20 30"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendColorCalls);
    TEST_ASSERT_EQUAL_UINT8(10, fixture.service.colorReds[0]);
    TEST_ASSERT_EQUAL_UINT8(20, fixture.service.colorGreens[0]);
    TEST_ASSERT_EQUAL_UINT8(30, fixture.service.colorBlues[0]);
}

void test_color_hsv_converts_to_rgb() {
    ZigbeeControllerFixture fixture;

    // Pure red: hue 0, full saturation and value
    fixture.controller.handleCommand(TerminalCommand("color", "hsv", "0 255 255"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendColorCalls);
    TEST_ASSERT_EQUAL_UINT8(255, fixture.service.colorReds[0]);
    TEST_ASSERT_EQUAL_UINT8(0, fixture.service.colorGreens[0]);
    TEST_ASSERT_EQUAL_UINT8(0, fixture.service.colorBlues[0]);

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("color", "hsv", "120 255 255"));
    TEST_ASSERT_EQUAL_UINT8(0, fixture.service.colorReds[1]);
    TEST_ASSERT_EQUAL_UINT8(255, fixture.service.colorGreens[1]);
    TEST_ASSERT_EQUAL_UINT8(0, fixture.service.colorBlues[1]);
}

void test_color_with_group_and_invalid_inputs() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("color", "rgb", "1 2 3 0xBEEF"));
    TEST_ASSERT_EQUAL_UINT16(0xBEEF, fixture.service.colorGroups[0]);

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("color", "rgb", "999 0 0"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendColorCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid RGB."));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("color", "hsv", "361 0 0"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.sendColorCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Invalid HSV."));
}

void test_color_unknown_format_shows_usage() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("color", "foo"));

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.sendColorCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Usage: color rgb <r> <g> <b> [group] | color hsv <h> <s> <v> [group]"));
}

void test_settemp_forwards_celsius_reading() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("settemp", "23.5"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setTempCalls);
    TEST_ASSERT_FLOAT_WITHIN(0.01, 23.5, fixture.service.tempValues[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Temperature reading set to 23.5 C."));
}

void test_settemp_rejects_non_numeric_without_calling_service() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("settemp", "abc"));

    TEST_ASSERT_EQUAL_UINT32(0, fixture.service.setTempCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Usage: settemp"));
}

void test_sethum_and_setocc_forward_state() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("sethum", "45.5"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setHumCalls);
    TEST_ASSERT_FLOAT_WITHIN(0.01, 45.5, fixture.service.humValues[0]);

    fixture.controller.handleCommand(TerminalCommand("setocc", "1"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setOccCalls);
    TEST_ASSERT_TRUE(fixture.service.occStates[0]);
    TEST_ASSERT_TRUE(fixture.view.contains("Occupancy set to occupied."));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("setocc", "7"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.setOccCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Usage: setocc <0|1>"));
}

void test_report_forwards_to_service_and_reports_failure() {
    ZigbeeControllerFixture fixture;

    fixture.controller.handleCommand(TerminalCommand("report"));
    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.reportCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("Sensor readings reported."));

    fixture.consumeBanner();
    fixture.service.sensorResult = false;
    fixture.controller.handleCommand(TerminalCommand("report"));
    TEST_ASSERT_TRUE(fixture.view.contains("Failed. Requires running tempsensor or occupancy endpoint."));
}

void test_events_drains_log_once() {
    ZigbeeControllerFixture fixture;
    fixture.service.eventLog = {"light: state=ON", "fan: mode=HIGH"};

    fixture.controller.handleCommand(TerminalCommand("events"));

    TEST_ASSERT_EQUAL_UINT32(1, fixture.service.takeEventsCalls);
    TEST_ASSERT_TRUE(fixture.view.contains("2 event(s):"));
    TEST_ASSERT_TRUE(fixture.view.contains("light: state=ON"));
    TEST_ASSERT_TRUE(fixture.view.contains("fan: mode=HIGH"));

    fixture.consumeBanner();
    fixture.controller.handleCommand(TerminalCommand("events"));
    TEST_ASSERT_TRUE(fixture.view.contains("No Zigbee events."));
}

}  // namespace zigbee_controller_tests

void runZigbeeControllerTests() {
    using namespace zigbee_controller_tests;
    RUN_TEST(test_start_without_role_defaults_to_coordinator_and_opens_network);
    RUN_TEST(test_start_router_starts_stack_in_router_role);
    RUN_TEST(test_start_accepts_short_aliases);
    RUN_TEST(test_start_end_device_role_is_forwarded_to_service);
    RUN_TEST(test_start_with_invalid_role_reports_error_without_touching_service);
    RUN_TEST(test_status_prints_zigbee_status_line);
    RUN_TEST(test_channel_within_range_is_forwarded_to_service);
    RUN_TEST(test_channel_outside_range_reports_error_without_recording);
    RUN_TEST(test_channel_without_number_shows_usage);
    RUN_TEST(test_permit_defaults_to_60_seconds_without_arguments);
    RUN_TEST(test_permit_with_seconds_argument_uses_given_value);
    RUN_TEST(test_permit_failure_reports_closed_network);
    RUN_TEST(test_stop_calls_service_stop);
    RUN_TEST(test_reset_calls_factory_reset_and_reports_failure);
    RUN_TEST(test_config_prints_current_configuration);
    RUN_TEST(test_ensure_released_stops_stack_and_resets_configured_flag);
    RUN_TEST(test_ensure_released_skips_stop_on_unsupported_chip_but_resets_flag);
    RUN_TEST(test_unsupported_chip_warns_and_never_reaches_service_on_start);
    RUN_TEST(test_unknown_command_displays_help);
    RUN_TEST(test_start_failure_reports_stack_error);
    RUN_TEST(test_channel_change_while_started_hints_restart_needed);
    RUN_TEST(test_device_light_propagates_endpoint_and_confirms);
    RUN_TEST(test_device_invalid_shows_usage_without_touching_service);
    RUN_TEST(test_on_off_toggle_always_delegate_to_service);
    RUN_TEST(test_on_failure_reports_send_error_when_service_fails);
    RUN_TEST(test_devices_with_empty_list_reports_no_devices_bound);
    RUN_TEST(test_devices_prints_each_bound_address);
    RUN_TEST(test_scan_polls_status_then_prints_table_with_pan_and_channel);
    RUN_TEST(test_scan_without_duration_defaults_to_2_seconds);
    RUN_TEST(test_scan_with_invalid_duration_shows_usage_without_starting);
    RUN_TEST(test_help_mentions_new_endpoint_scan_and_switch_commands);
    RUN_TEST(test_device_accepts_all_new_endpoint_names);
    RUN_TEST(test_on_with_group_token_forwards_group_address);
    RUN_TEST(test_toggle_without_group_defaults_to_zero);
    RUN_TEST(test_dim_percent_suffix_scales_to_level);
    RUN_TEST(test_dim_raw_value_passes_through);
    RUN_TEST(test_dim_invalid_values_are_rejected_without_sending);
    RUN_TEST(test_dim_with_group_forwards_both);
    RUN_TEST(test_color_rgb_forwards_components);
    RUN_TEST(test_color_hsv_converts_to_rgb);
    RUN_TEST(test_color_with_group_and_invalid_inputs);
    RUN_TEST(test_color_unknown_format_shows_usage);
    RUN_TEST(test_settemp_forwards_celsius_reading);
    RUN_TEST(test_settemp_rejects_non_numeric_without_calling_service);
    RUN_TEST(test_sethum_and_setocc_forward_state);
    RUN_TEST(test_report_forwards_to_service_and_reports_failure);
    RUN_TEST(test_events_drains_log_once);
}

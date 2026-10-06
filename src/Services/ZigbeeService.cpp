#include "Services/ZigbeeService.h"

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "Zigbee.h"
#include "esp_zigbee_core.h"
#include "nwk/esp_zigbee_nwk.h"
#include "aps/esp_zigbee_aps.h"
#include "zdo/esp_zigbee_zdo_command.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "esp_ieee802154.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Arduino ZigbeeCore's APS hook is deliberately non-static. monitor wraps it
// rather than replacing normal Arduino processing.
bool zb_apsde_data_indication_handler(esp_zb_apsde_data_ind_t ind);

namespace {

// The Zigbee core invokes plain function pointers, so a file-local self
// pointer routes the callbacks back into the single service instance.
// pushEvent_ is public on ZigbeeService for exactly this reason.
ZigbeeService* g_self = nullptr;

constexpr size_t kMaxEvents = 32;
constexpr size_t kMaxSniffPans = 8;
constexpr size_t kMaxSniffJoinIeee = 4;
constexpr size_t kMaxSniffFrames = 32;
constexpr size_t kMaxSniffPayload = 32;

struct RawSniffAccumulator {
    uint8_t channel = 0;
    uint32_t frames = 0;
    uint32_t beacons = 0;
    uint32_t dataFrames = 0;
    uint32_t ackFrames = 0;
    uint32_t commandFrames = 0;
    uint32_t otherFrames = 0;
    uint32_t associationRequests = 0;
    uint32_t associationResponses = 0;
    uint32_t beaconRequests = 0;
    uint32_t orphanNotifications = 0;
    uint32_t phyHits = 0;
    uint32_t probableZigbeeBeacons = 0;
    uint32_t probableZigbeeNwkFrames = 0;
    uint32_t probableZigbeeNwkCommands = 0;
    uint32_t zigbeeRejoinRequests = 0;
    uint32_t zigbeeRejoinResponses = 0;
    uint32_t zigbeeLeaveCommands = 0;
    bool hasLastNwkAddresses = false;
    uint16_t lastNwkSource = 0xFFFF;
    uint16_t lastNwkDestination = 0xFFFF;
    int32_t rssiSum = 0;
    uint32_t lqiSum = 0;
    int8_t weakestRssi = 127;
    int8_t strongestRssi = -128;
    uint8_t strongestLqi = 0;
    uint16_t panIds[kMaxSniffPans] = {};
    uint8_t panCount = 0;
    uint8_t joinIeee[kMaxSniffJoinIeee][8] = {};
    uint8_t joinIeeeCount = 0;
};

RawSniffAccumulator g_sniffStats;
portMUX_TYPE g_sniffMux = portMUX_INITIALIZER_UNLOCKED;
volatile bool g_sniffActive = false;

struct RawSniffFrame {
    uint8_t channel = 0;
    int8_t rssi = -128;
    uint8_t lqi = 0;
    uint8_t macType = 7;
    bool macSecurity = false;
    bool hasPanId = false;
    uint16_t panId = 0xFFFF;
    bool hasMacSource = false;
    uint16_t macSource = 0xFFFF;
    bool hasMacDestination = false;
    uint16_t macDestination = 0xFFFF;
    bool hasSourceIeee = false;
    uint8_t sourceIeee[8] = {};
    bool probableZigbeeBeacon = false;
    bool probableZigbeeNwk = false;
    bool probableZigbeeInterPan = false;
    bool nwkSecurity = false;
    bool nwkCommand = false;
    bool hasNwkAddresses = false;
    uint16_t nwkSource = 0xFFFF;
    uint16_t nwkDestination = 0xFFFF;
    bool hasNwkCommand = false;
    uint8_t nwkCommandId = 0;
    bool hasMacCommand = false;
    uint8_t macCommandId = 0;
    bool hasAps = false;
    bool apsSecurity = false;
    uint8_t sourceEndpoint = 0;
    uint8_t destinationEndpoint = 0;
    uint16_t clusterId = 0;
    uint16_t profileId = 0;
    bool hasZcl = false;
    uint8_t zclFrameType = 0;
    uint8_t zclSequence = 0;
    uint8_t zclCommand = 0;
    uint8_t payloadLength = 0;
    uint8_t payload[kMaxSniffPayload] = {};
};

RawSniffFrame g_sniffFrames[kMaxSniffFrames];
size_t g_sniffFrameHead = 0;
size_t g_sniffFrameCount = 0;

constexpr size_t kMaxMonitorFrames = 24;
constexpr size_t kMaxMonitorPayload = 48;
struct RawMonitorFrame {
    uint16_t source = 0xFFFF;
    uint16_t destination = 0xFFFF;
    uint8_t sourceEndpoint = 0;
    uint8_t destinationEndpoint = 0;
    uint16_t profileId = 0;
    uint16_t clusterId = 0;
    uint8_t destinationAddressMode = 0;
    uint8_t securityStatus = 0;
    int lqi = 0;
    uint8_t payloadLength = 0;
    uint8_t payload[kMaxMonitorPayload] = {};
};
RawMonitorFrame g_monitorFrames[kMaxMonitorFrames];
size_t g_monitorHead = 0;
size_t g_monitorCount = 0;
portMUX_TYPE g_monitorMux = portMUX_INITIALIZER_UNLOCKED;
volatile bool g_monitorActive = false;

bool monitorApsHandler_(esp_zb_apsde_data_ind_t ind) {
    if (g_monitorActive && ind.status == 0) {
        RawMonitorFrame record;
        record.source = ind.src_short_addr;
        record.destination = ind.dst_short_addr;
        record.sourceEndpoint = ind.src_endpoint;
        record.destinationEndpoint = ind.dst_endpoint;
        record.profileId = ind.profile_id;
        record.clusterId = ind.cluster_id;
        record.destinationAddressMode = ind.dst_addr_mode;
        record.securityStatus = ind.security_status;
        record.lqi = ind.lqi;
        const size_t copyLength = std::min<size_t>(ind.asdu_length, kMaxMonitorPayload);
        record.payloadLength = static_cast<uint8_t>(copyLength);
        if (ind.asdu != nullptr && copyLength > 0) {
            memcpy(record.payload, ind.asdu, copyLength);
        }

        portENTER_CRITICAL(&g_monitorMux);
        g_monitorFrames[g_monitorHead] = record;
        g_monitorHead = (g_monitorHead + 1) % kMaxMonitorFrames;
        if (g_monitorCount < kMaxMonitorFrames) ++g_monitorCount;
        portEXIT_CRITICAL(&g_monitorMux);
    }

    // Preserve Arduino's bind/unbind tracking and always let the stack keep
    // processing the packet exactly as it did before monitor was enabled.
    return zb_apsde_data_indication_handler(ind);
}

struct DeviceInspectAccumulator {
    bool active = false;
    volatile bool done = false;
    volatile uint8_t pending = 0;
    bool hadError = false;
    uint16_t address = 0xFFFF;
    std::vector<ZigbeeEndpointDescriptor> endpoints;
};

DeviceInspectAccumulator g_inspect;

void inspectSimpleDescCb_(esp_zb_zdp_status_t status,
                          esp_zb_af_simple_desc_1_1_t* simpleDesc,
                          void*) {
    if (!g_inspect.active) return;

    if (status == ESP_ZB_ZDP_STATUS_SUCCESS && simpleDesc != nullptr) {
        ZigbeeEndpointDescriptor ep;
        ep.endpoint = simpleDesc->endpoint;
        ep.profileId = simpleDesc->app_profile_id;
        ep.deviceId = simpleDesc->app_device_id;
        ep.deviceVersion = simpleDesc->app_device_version;

        for (uint8_t i = 0; i < simpleDesc->app_input_cluster_count; ++i) {
            ep.inputClusters.push_back(simpleDesc->app_cluster_list[i]);
        }
        for (uint8_t i = 0; i < simpleDesc->app_output_cluster_count; ++i) {
            ep.outputClusters.push_back(
                simpleDesc->app_cluster_list[simpleDesc->app_input_cluster_count + i]);
        }
        g_inspect.endpoints.push_back(std::move(ep));
    } else {
        g_inspect.hadError = true;
    }

    if (g_inspect.pending > 0) {
        --g_inspect.pending;
    }
    if (g_inspect.pending == 0) {
        g_inspect.active = false;
        g_inspect.done = true;
    }
}

void inspectActiveEpCb_(esp_zb_zdp_status_t status,
                        uint8_t epCount,
                        uint8_t* epList,
                        void*) {
    if (!g_inspect.active) return;

    if (status != ESP_ZB_ZDP_STATUS_SUCCESS || epCount == 0 || epList == nullptr) {
        g_inspect.hadError = status != ESP_ZB_ZDP_STATUS_SUCCESS;
        g_inspect.active = false;
        g_inspect.done = true;
        return;
    }

    g_inspect.pending = epCount;
    for (uint8_t i = 0; i < epCount; ++i) {
        esp_zb_zdo_simple_desc_req_param_t req = {};
        req.addr_of_interest = g_inspect.address;
        req.endpoint = epList[i];
        esp_zb_zdo_simple_desc_req(&req, inspectSimpleDescCb_, nullptr);
    }
}

uint16_t IRAM_ATTR readLe16_(const uint8_t* data) {
    return static_cast<uint16_t>(data[0])
        | (static_cast<uint16_t>(data[1]) << 8);
}

size_t IRAM_ATTR addressLength_(uint8_t mode) {
    return mode == 2 ? 2U : (mode == 3 ? 8U : 0U);
}

void IRAM_ATTR addPanLocked_(uint16_t panId) {
    // 0xffff is the broadcast PAN used by discovery requests; it is not a
    // useful network identity for the summary.
    if (panId == 0xFFFF) return;
    for (uint8_t i = 0; i < g_sniffStats.panCount; ++i) {
        if (g_sniffStats.panIds[i] == panId) return;
    }
    if (g_sniffStats.panCount < kMaxSniffPans) {
        g_sniffStats.panIds[g_sniffStats.panCount++] = panId;
    }
}

void IRAM_ATTR addJoinIeeeLocked_(const uint8_t* ieee) {
    if (!ieee) return;
    for (uint8_t i = 0; i < g_sniffStats.joinIeeeCount; ++i) {
        bool same = true;
        for (uint8_t b = 0; b < 8; ++b) {
            if (g_sniffStats.joinIeee[i][b] != ieee[b]) {
                same = false;
                break;
            }
        }
        if (same) return;
    }
    if (g_sniffStats.joinIeeeCount < kMaxSniffJoinIeee) {
        const uint8_t slot = g_sniffStats.joinIeeeCount++;
        for (uint8_t b = 0; b < 8; ++b) {
            g_sniffStats.joinIeee[slot][b] = ieee[b];
        }
    }
}

struct ParsedMacFrame {
    uint8_t type = 7;
    bool security = false;
    bool hasDestPan = false;
    uint16_t destPan = 0xFFFF;
    bool hasSrcPan = false;
    uint16_t srcPan = 0xFFFF;
    bool hasSrcIeee = false;
    uint8_t srcIeee[8] = {};
    bool hasDestShort = false;
    uint16_t destShort = 0xFFFF;
    bool hasSrcShort = false;
    uint16_t srcShort = 0xFFFF;
    const uint8_t* payload = nullptr;
    size_t payloadLength = 0;
    bool hasCommandId = false;
    uint8_t commandId = 0;
};

ParsedMacFrame IRAM_ATTR parseMacFrame_(const uint8_t* frame) {
    ParsedMacFrame out;
    if (!frame) return out;

    // PHR length includes the two-byte FCS. The receive buffer contains those
    // slots as RSSI/LQI, so the actual MAC bytes stop two bytes earlier.
    const uint8_t phrLength = frame[0] & 0x7F;
    if (phrLength < 5) return out;
    const size_t macLength = static_cast<size_t>(phrLength - 2);
    const uint8_t* mac = frame + 1;
    if (macLength < 3) return out;

    const uint16_t fcf = readLe16_(mac);
    out.type = static_cast<uint8_t>(fcf & 0x7);
    out.security = (fcf & (1U << 3)) != 0;
    const bool panCompression = (fcf & (1U << 6)) != 0;
    const bool sequenceSuppressed = (fcf & (1U << 8)) != 0;
    const uint8_t dstMode = static_cast<uint8_t>((fcf >> 10) & 0x3);
    const uint8_t frameVersion = static_cast<uint8_t>((fcf >> 12) & 0x3);
    const uint8_t srcMode = static_cast<uint8_t>((fcf >> 14) & 0x3);

    size_t offset = 2;
    if (!sequenceSuppressed) {
        if (offset >= macLength) return out;
        ++offset;
    }

    if (dstMode != 0) {
        const size_t addrLen = addressLength_(dstMode);
        if (addrLen == 0 || offset + 2 + addrLen > macLength) return out;
        out.destPan = readLe16_(mac + offset);
        out.hasDestPan = true;
        offset += 2;
        if (dstMode == 2) {
            out.destShort = readLe16_(mac + offset);
            out.hasDestShort = true;
        }
        offset += addrLen;
    }

    if (srcMode != 0) {
        const size_t addrLen = addressLength_(srcMode);
        if (addrLen == 0) return out;

        // Zigbee uses legacy/2006 MAC headers in the common case. For version
        // 2 frames the PAN-ID presence matrix is richer; only consume a source
        // PAN when its presence is unambiguous, otherwise keep the summary
        // conservative instead of mis-parsing payload bytes as addresses.
        const bool srcPanPresent = frameVersion <= 1
            ? (dstMode == 0 || !panCompression)
            : (dstMode == 0 && !panCompression);
        if (srcPanPresent) {
            if (offset + 2 > macLength) return out;
            out.srcPan = readLe16_(mac + offset);
            out.hasSrcPan = true;
            offset += 2;
        } else if (panCompression && out.hasDestPan) {
            out.srcPan = out.destPan;
            out.hasSrcPan = true;
        }

        if (offset + addrLen > macLength) return out;
        if (srcMode == 2) {
            out.srcShort = readLe16_(mac + offset);
            out.hasSrcShort = true;
        } else if (srcMode == 3) {
            for (uint8_t b = 0; b < 8; ++b) {
                out.srcIeee[b] = mac[offset + b];
            }
            out.hasSrcIeee = true;
        }
        offset += addrLen;
    }

    if (offset <= macLength) {
        out.payload = mac + offset;
        out.payloadLength = macLength - offset;
    }

    // MAC command payload starts immediately after addressing for unsecured
    // legacy frames. Association/beacon requests used during classic Zigbee
    // commissioning are normally visible here.
    if (out.type == 3 && !out.security && out.payloadLength > 0) {
        out.hasCommandId = true;
        out.commandId = out.payload[0];
    }
    return out;
}

struct ParsedZigbeeFrame {
    bool beacon = false;
    bool nwk = false;
    bool interPan = false;
    bool nwkCommand = false;
    bool nwkSecurity = false;
    uint16_t source = 0xFFFF;
    uint16_t destination = 0xFFFF;
    bool hasCommandId = false;
    uint8_t commandId = 0;
    const uint8_t* payload = nullptr;
    size_t payloadLength = 0;
};

struct ParsedApsFrame {
    bool valid = false;
    bool security = false;
    uint8_t sourceEndpoint = 0;
    uint8_t destinationEndpoint = 0;
    uint16_t clusterId = 0;
    uint16_t profileId = 0;
    const uint8_t* payload = nullptr;
    size_t payloadLength = 0;
};

struct ParsedZclFrame {
    bool valid = false;
    uint8_t frameType = 0;
    uint8_t sequence = 0;
    uint8_t command = 0;
};

bool IRAM_ATTR isLikelyZigbeeBeacon_(const ParsedMacFrame& mac) {
    if (mac.type != 0 || mac.payload == nullptr || mac.payloadLength < 5) return false;

    // IEEE beacon payload starts after Superframe + GTS + Pending Address
    // fields. Zigbee beacon payload then begins with Protocol ID 0x00 and
    // normally advertises protocol version 2 in the next byte.
    size_t off = 0;
    if (mac.payloadLength < 3) return false;
    off += 2; // Superframe Specification
    const uint8_t gtsSpec = mac.payload[off++];
    const uint8_t gtsCount = static_cast<uint8_t>(gtsSpec & 0x07);
    if (gtsCount != 0) {
        if (off + 1U + static_cast<size_t>(gtsCount) * 3U > mac.payloadLength) return false;
        off += 1U + static_cast<size_t>(gtsCount) * 3U;
    }
    if (off >= mac.payloadLength) return false;
    const uint8_t pending = mac.payload[off++];
    const size_t pendingBytes = static_cast<size_t>(pending & 0x07U) * 2U
        + static_cast<size_t>((pending >> 4) & 0x07U) * 8U;
    if (off + pendingBytes + 2U > mac.payloadLength) return false;
    off += pendingBytes;

    const uint8_t* beacon = mac.payload + off;
    const size_t beaconLen = mac.payloadLength - off;
    if (beaconLen < 2) return false;
    const uint8_t protocolId = beacon[0];
    const uint8_t protocolVersion = static_cast<uint8_t>((beacon[1] >> 4) & 0x0F);
    return protocolId == 0x00 && protocolVersion == 2;
}

ParsedZigbeeFrame IRAM_ATTR parseLikelyZigbee_(const ParsedMacFrame& mac) {
    ParsedZigbeeFrame out;
    out.beacon = isLikelyZigbeeBeacon_(mac);
    if (mac.type != 1 || mac.payload == nullptr || mac.payloadLength < 8) return out;

    const uint16_t fcf = readLe16_(mac.payload);
    const uint8_t frameType = static_cast<uint8_t>(fcf & 0x03U);
    const uint8_t protocolVersion = static_cast<uint8_t>((fcf >> 2) & 0x0FU);
    // Zigbee PRO uses NWK protocol version 2. Frame type 3 is the Inter-PAN
    // stub used by some commissioning flows (for example Touchlink). Its
    // header is different, so classify it but do not pretend the normal NWK
    // short-address fields below apply to it.
    if (protocolVersion != 2 || frameType == 2 || (fcf & 0xC000U) != 0) return out;
    if (frameType == 3) {
        out.interPan = true;
        return out;
    }

    out.nwk = true;
    out.nwkCommand = frameType == 1;
    out.nwkSecurity = (fcf & (1U << 9)) != 0;
    out.destination = readLe16_(mac.payload + 2);
    out.source = readLe16_(mac.payload + 4);

    size_t off = 8; // FC + dst + src + radius + sequence
    if (fcf & (1U << 11)) off += 8; // destination IEEE
    if (fcf & (1U << 12)) off += 8; // source IEEE
    if (off > mac.payloadLength) return out;

    if (fcf & (1U << 10)) {
        // Source-route subframe: relay count, relay index, then short addrs.
        if (off + 2 > mac.payloadLength) return out;
        const uint8_t relayCount = mac.payload[off];
        off += 2U + static_cast<size_t>(relayCount) * 2U;
        if (off > mac.payloadLength) return out;
    }

    out.payload = mac.payload + off;
    out.payloadLength = mac.payloadLength - off;

    // Zigbee NWK security encrypts the NWK command payload, but the base NWK
    // header above is still useful to identify likely Zigbee traffic.
    if (out.nwkCommand && !out.nwkSecurity && off < mac.payloadLength) {
        out.hasCommandId = true;
        out.commandId = mac.payload[off];
    }
    return out;
}

ParsedApsFrame IRAM_ATTR parseLikelyAps_(const ParsedZigbeeFrame& nwk) {
    ParsedApsFrame out;
    if (!nwk.nwk || nwk.nwkCommand || nwk.nwkSecurity
        || nwk.payload == nullptr || nwk.payloadLength < 8) {
        return out;
    }

    const uint8_t fc = nwk.payload[0];
    const uint8_t frameType = static_cast<uint8_t>(fc & 0x03U);
    const uint8_t deliveryMode = static_cast<uint8_t>((fc >> 2) & 0x03U);
    const bool extendedHeader = (fc & 0x80U) != 0;
    if (frameType != 0 || extendedHeader) return out; // data, non-fragmented

    out.security = (fc & 0x20U) != 0;
    size_t off = 1;
    if (deliveryMode == 3) {
        // Group delivery carries a 16-bit group instead of destination EP.
        if (off + 2 > nwk.payloadLength) return out;
        off += 2;
        out.destinationEndpoint = 0;
    } else {
        if (off >= nwk.payloadLength) return out;
        out.destinationEndpoint = nwk.payload[off++];
    }

    if (off + 2 + 2 + 1 + 1 > nwk.payloadLength) return out;
    out.clusterId = readLe16_(nwk.payload + off);
    off += 2;
    out.profileId = readLe16_(nwk.payload + off);
    off += 2;
    out.sourceEndpoint = nwk.payload[off++];
    ++off; // APS counter

    out.valid = true;
    out.payload = nwk.payload + off;
    out.payloadLength = nwk.payloadLength - off;
    return out;
}

ParsedZclFrame IRAM_ATTR parseLikelyZcl_(const ParsedApsFrame& aps) {
    ParsedZclFrame out;
    if (!aps.valid || aps.security || aps.profileId == 0x0000
        || aps.payload == nullptr || aps.payloadLength < 3) {
        return out;
    }

    size_t off = 0;
    const uint8_t fc = aps.payload[off++];
    out.frameType = static_cast<uint8_t>(fc & 0x03U);
    if (fc & 0x04U) {
        if (off + 2 > aps.payloadLength) return out;
        off += 2; // manufacturer code
    }
    if (off + 2 > aps.payloadLength) return out;
    out.sequence = aps.payload[off++];
    out.command = aps.payload[off++];
    out.valid = true;
    return out;
}

void IRAM_ATTR sniffSfdDone_() {
    if (!g_sniffActive) return;
    portENTER_CRITICAL_ISR(&g_sniffMux);
    ++g_sniffStats.phyHits;
    portEXIT_CRITICAL_ISR(&g_sniffMux);
}

void IRAM_ATTR sniffRxDone_(uint8_t* frame, esp_ieee802154_frame_info_t* frameInfo) {
    if (!frame) return;

    const ParsedMacFrame parsed = parseMacFrame_(frame);
    const ParsedZigbeeFrame zigbee = parseLikelyZigbee_(parsed);
    const ParsedApsFrame aps = parseLikelyAps_(zigbee);
    const ParsedZclFrame zcl = parseLikelyZcl_(aps);
    if (g_sniffActive) {
        RawSniffFrame record;
        record.channel = g_sniffStats.channel;
        record.macType = parsed.type;
        record.macSecurity = parsed.security;
        record.hasPanId = parsed.hasDestPan || parsed.hasSrcPan;
        record.panId = parsed.hasDestPan ? parsed.destPan : parsed.srcPan;
        record.hasMacSource = parsed.hasSrcShort;
        record.macSource = parsed.srcShort;
        record.hasMacDestination = parsed.hasDestShort;
        record.macDestination = parsed.destShort;
        record.hasSourceIeee = parsed.hasSrcIeee;
        if (parsed.hasSrcIeee) {
            for (uint8_t i = 0; i < 8; ++i) record.sourceIeee[i] = parsed.srcIeee[i];
        }
        record.probableZigbeeBeacon = zigbee.beacon;
        record.probableZigbeeNwk = zigbee.nwk;
        record.probableZigbeeInterPan = zigbee.interPan;
        record.nwkSecurity = zigbee.nwkSecurity;
        record.nwkCommand = zigbee.nwkCommand;
        record.hasNwkAddresses = zigbee.nwk;
        record.nwkSource = zigbee.source;
        record.nwkDestination = zigbee.destination;
        record.hasNwkCommand = zigbee.hasCommandId;
        record.nwkCommandId = zigbee.commandId;
        record.hasMacCommand = parsed.hasCommandId;
        record.macCommandId = parsed.commandId;
        record.hasAps = aps.valid;
        record.apsSecurity = aps.security;
        record.sourceEndpoint = aps.sourceEndpoint;
        record.destinationEndpoint = aps.destinationEndpoint;
        record.clusterId = aps.clusterId;
        record.profileId = aps.profileId;
        record.hasZcl = zcl.valid;
        record.zclFrameType = zcl.frameType;
        record.zclSequence = zcl.sequence;
        record.zclCommand = zcl.command;
        if (frameInfo) {
            record.rssi = frameInfo->rssi;
            record.lqi = frameInfo->lqi;
        }
        if (aps.valid && !aps.security && aps.payload != nullptr) {
            const size_t copyLength = std::min<size_t>(aps.payloadLength, kMaxSniffPayload);
            record.payloadLength = static_cast<uint8_t>(copyLength);
            for (size_t i = 0; i < copyLength; ++i) record.payload[i] = aps.payload[i];
        }

        portENTER_CRITICAL_ISR(&g_sniffMux);
        ++g_sniffStats.frames;
        switch (parsed.type) {
            case 0: ++g_sniffStats.beacons; break;
            case 1: ++g_sniffStats.dataFrames; break;
            case 2: ++g_sniffStats.ackFrames; break;
            case 3: ++g_sniffStats.commandFrames; break;
            default: ++g_sniffStats.otherFrames; break;
        }

        if (frameInfo) {
            g_sniffStats.rssiSum += frameInfo->rssi;
            g_sniffStats.lqiSum += frameInfo->lqi;
            if (frameInfo->rssi < g_sniffStats.weakestRssi) g_sniffStats.weakestRssi = frameInfo->rssi;
            if (frameInfo->rssi > g_sniffStats.strongestRssi) g_sniffStats.strongestRssi = frameInfo->rssi;
            if (frameInfo->lqi > g_sniffStats.strongestLqi) g_sniffStats.strongestLqi = frameInfo->lqi;
        }

        if (parsed.hasDestPan) addPanLocked_(parsed.destPan);
        if (parsed.hasSrcPan) addPanLocked_(parsed.srcPan);

        if (zigbee.beacon) ++g_sniffStats.probableZigbeeBeacons;
        if (zigbee.interPan) ++g_sniffStats.probableZigbeeNwkFrames;
        if (zigbee.nwk) {
            ++g_sniffStats.probableZigbeeNwkFrames;
            g_sniffStats.hasLastNwkAddresses = true;
            g_sniffStats.lastNwkSource = zigbee.source;
            g_sniffStats.lastNwkDestination = zigbee.destination;
        }
        if (zigbee.nwkCommand) ++g_sniffStats.probableZigbeeNwkCommands;
        if (zigbee.hasCommandId) {
            switch (zigbee.commandId) {
                case 0x04: ++g_sniffStats.zigbeeLeaveCommands; break;
                case 0x06: ++g_sniffStats.zigbeeRejoinRequests; break;
                case 0x07: ++g_sniffStats.zigbeeRejoinResponses; break;
                default: break;
            }
        }

        if (parsed.hasCommandId) {
            bool joinRelated = false;
            switch (parsed.commandId) {
                case 0x01: ++g_sniffStats.associationRequests; joinRelated = true; break;
                case 0x02: ++g_sniffStats.associationResponses; joinRelated = true; break;
                case 0x06: ++g_sniffStats.orphanNotifications; joinRelated = true; break;
                case 0x07: ++g_sniffStats.beaconRequests; joinRelated = true; break;
                default: break;
            }
            if (joinRelated && parsed.hasSrcIeee) {
                addJoinIeeeLocked_(parsed.srcIeee);
            }
        }

        g_sniffFrames[g_sniffFrameHead] = record;
        g_sniffFrameHead = (g_sniffFrameHead + 1) % kMaxSniffFrames;
        if (g_sniffFrameCount < kMaxSniffFrames) ++g_sniffFrameCount;
        portEXIT_CRITICAL_ISR(&g_sniffMux);
    }

    // Return the driver's RX buffer immediately; the sniffer keeps only
    // aggregate metadata so it cannot exhaust the small 802.15.4 RX pool.
    esp_ieee802154_receive_handle_done(frame);
}

void resetSniffStats_(uint8_t channel) {
    portENTER_CRITICAL(&g_sniffMux);
    g_sniffStats = RawSniffAccumulator{};
    g_sniffStats.channel = channel;
    g_sniffFrameHead = 0;
    g_sniffFrameCount = 0;
    portEXIT_CRITICAL(&g_sniffMux);
}

std::string formatIeee_(const uint8_t* addr) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             addr[7], addr[6], addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
    return buf;
}

const char* onOffName(bool state) {
    return state ? "ON" : "OFF";
}

std::string miredsToKelvinSuffix(uint16_t mireds) {
    if (mireds == 0) {
        return "?K";
    }
    char buf[16];
    snprintf(buf, sizeof(buf), "%uK", static_cast<unsigned>((1000000UL + mireds / 2) / mireds));
    return buf;
}

void trampLightState(bool state) {
    if (g_self) g_self->pushEvent_(std::string("light: state=") + onOffName(state));
}

void trampDimmableState(bool state, uint8_t level) {
    if (g_self) {
        g_self->pushEvent_("dimlight: state=" + std::string(onOffName(state))
                           + " level=" + std::to_string(level));
    }
}

void trampColorRgb(bool state, uint8_t r, uint8_t g, uint8_t b, uint8_t level) {
    if (g_self) {
        char buf[64];
        snprintf(buf, sizeof(buf), "colorlight: state=%s rgb=(%u,%u,%u) level=%u",
                 onOffName(state), r, g, b, level);
        g_self->pushEvent_(buf);
    }
}

void trampColorHsv(bool state, uint8_t h, uint8_t s, uint8_t v) {
    if (g_self) {
        g_self->pushEvent_("colorlight: state=" + std::string(onOffName(state))
                           + " hsv=(" + std::to_string(h) + "," + std::to_string(s)
                           + "," + std::to_string(v) + ")");
    }
}

void trampColorTemp(bool state, uint8_t level, uint16_t mireds) {
    if (g_self) {
        g_self->pushEvent_("colorlight: state=" + std::string(onOffName(state))
                           + " level=" + std::to_string(level)
                           + " temp=" + std::to_string(mireds) + "m("
                           + miredsToKelvinSuffix(mireds) + ")");
    }
}

void trampSwitchState(bool state) {
    if (g_self) {
        g_self->pushEvent_("switch: bound light state=" + std::string(onOffName(state)));
    }
}

void trampSwitchLevel(uint8_t level) {
    if (g_self) {
        g_self->pushEvent_("switch: bound light level=" + std::to_string(level));
    }
}

void trampSwitchColor(uint8_t r, uint8_t g, uint8_t b) {
    if (g_self) {
        char buf[48];
        snprintf(buf, sizeof(buf), "switch: bound light rgb=(%u,%u,%u)", r, g, b);
        g_self->pushEvent_(buf);
    }
}

void trampFanMode(ZigbeeFanMode mode) {
    const char* name = "UNKNOWN";
    switch (mode) {
        case FAN_MODE_OFF:    name = "OFF"; break;
        case FAN_MODE_LOW:    name = "LOW"; break;
        case FAN_MODE_MEDIUM: name = "MEDIUM"; break;
        case FAN_MODE_HIGH:   name = "HIGH"; break;
        case FAN_MODE_ON:     name = "ON"; break;
        case FAN_MODE_AUTO:   name = "AUTO"; break;
        case FAN_MODE_SMART:  name = "SMART"; break;
        default: break;
    }
    if (g_self) g_self->pushEvent_(std::string("fan: mode=") + name);
}

void trampOutletState(bool state) {
    if (g_self) {
        g_self->pushEvent_(std::string("outlet: state=") + onOffName(state));
    }
}


}  // namespace

#endif  // ZIGBEE_MODE_ED || ZIGBEE_MODE_ZCZR; remaining functions are
        // guarded individually so non-Zigbee targets still get their stubs

// Out-of-line so the unique_ptr member can hold a forward-declared endpoint
// type (complete types are visible above in Zigbee builds)
ZigbeeService::ZigbeeService() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    g_self = this;
#endif
}

ZigbeeService::~ZigbeeService() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    endMonitor();
    endSniff();
    if (g_self == this) {
        g_self = nullptr;
    }
#endif
}

bool ZigbeeService::isSupported() const {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    return true;
#else
    return false;
#endif
}

bool ZigbeeService::isRoleSupported(ZigbeeRoleEnum role) const {
#if defined(ZIGBEE_MODE_ED)
    return role == ZigbeeRoleEnum::EndDevice;
#elif defined(ZIGBEE_MODE_ZCZR)
    return role == ZigbeeRoleEnum::Coordinator || role == ZigbeeRoleEnum::Router;
#else
    (void)role;
    return false;
#endif
}

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
void ZigbeeService::pushEvent_(const std::string& text) {
    if (events_.size() >= kMaxEvents) {
        events_.pop_front();
    }
    events_.push_back(text);
}

void ZigbeeService::clearError_() {
    lastError_.clear();
}

bool ZigbeeService::fail_(const std::string& reason) {
    lastError_ = reason;
    return false;
}

ZigbeeEP* ZigbeeService::makeEndpoint_() {
    switch (endpoint_) {
        case ZigbeeEndpointEnum::Light: {
            auto* ep = new ZigbeeLight(1);
            ep->onLightChange(trampLightState);
            return ep;
        }
        case ZigbeeEndpointEnum::DimmableLight: {
            auto* ep = new ZigbeeDimmableLight(1);
            ep->onLightChange(trampDimmableState);
            return ep;
        }
        case ZigbeeEndpointEnum::ColorLight: {
            auto* ep = new ZigbeeColorDimmableLight(1);
            // Advertise hue/saturation, XY and color temperature support
            ep->setLightColorCapabilities(
                ZIGBEE_COLOR_CAPABILITY_HUE_SATURATION | ZIGBEE_COLOR_CAPABILITY_X_Y
                | ZIGBEE_COLOR_CAPABILITY_COLOR_TEMP);
            ep->onLightChangeRgb(trampColorRgb);
            ep->onLightChangeHsv(trampColorHsv);
            ep->onLightChangeTemp(trampColorTemp);
            return ep;
        }
        case ZigbeeEndpointEnum::Switch: {
            auto* ep = new ZigbeeColorDimmerSwitch(1);
            ep->onLightStateChange(trampSwitchState);
            ep->onLightLevelChange(trampSwitchLevel);
            ep->onLightColorChange(trampSwitchColor);
            return ep;
        }
        case ZigbeeEndpointEnum::TempSensor: {
            auto* ep = new ZigbeeTempSensor(1);
            // Humidity cluster plus periodic reporting so hubs see updates
            ep->addHumiditySensor();
            ep->setReporting(30, 3600, 0.5f);
            ep->setHumidityReporting(30, 3600, 1.0f);
            return ep;
        }
        case ZigbeeEndpointEnum::OccupancySensor:
            return new ZigbeeOccupancySensor(1);
        case ZigbeeEndpointEnum::Fan: {
            auto* ep = new ZigbeeFanControl(1);
            ep->onFanModeChange(trampFanMode);
            return ep;
        }
        case ZigbeeEndpointEnum::Outlet: {
            auto* ep = new ZigbeePowerOutlet(1);
            ep->onPowerOutletChange(trampOutletState);
            return ep;
        }
        case ZigbeeEndpointEnum::RangeExtender:
            return new ZigbeeRangeExtender(1);
        default:
            return nullptr;
    }
}

bool ZigbeeService::ensureStarted_() {
    if (started_) {
        clearError_();
        return true;
    }

    // Never call begin() twice in one boot. If an already-initialized stack
    // is found inactive, resume it rather than attempting a second initialization.
    if (initialized_) {
        if (initFailed_) {
            return fail_("Previous Zigbee initialization failed in this boot. Refusing to resume an unknown stack state; reboot the expander first.");
        }
        Zigbee.start();
        started_ = Zigbee.started();
        if (!started_) {
            return fail_("Zigbee stack could not be resumed. Reboot the expander before retrying.");
        }
        pushEvent_("[STACK] resumed");
        clearError_();
        return true;
    }

    // Single-channel mask for the configured primary channel (11..26)
    Zigbee.setPrimaryChannelMask(1UL << channel_);
    // Create the selected HA endpoint on EP 1 before begin(); the object must
    // stay alive while the stack runs. An endpoint swap releases the previous
    // object here.
    if (!endpointObj_ || activeEndpoint_ != endpoint_) {
        endpointObj_.reset(makeEndpoint_());
        activeEndpoint_ = endpoint_;
        if (endpointObj_) {
            Zigbee.addEndpoint(endpointObj_.get());
        }
    }
#if defined(ZIGBEE_MODE_ED)
    // End-device firmware only supports the sleepy end-device role
    if (role_ != ZigbeeRoleEnum::EndDevice) {
        return false;
    }
    const zigbee_role_t target = ZIGBEE_END_DEVICE;
#elif defined(ZIGBEE_MODE_ZCZR)
    // Coordinator/router firmware cannot run as an end device
    if (role_ == ZigbeeRoleEnum::EndDevice) {
        return false;
    }
    const zigbee_role_t target =
        (role_ == ZigbeeRoleEnum::Coordinator) ? ZIGBEE_COORDINATOR : ZIGBEE_ROUTER;
#endif
    // Mark initialized once begin() is attempted. Even if begin() later times
    // out, 3.3.x may already have created the Zigbee task, so retrying begin()
    // in the same boot is unsafe.
    // Always start factory-new after a reboot. This prevents Arduino-ESP32
    // from restoring a previously commissioned PAN/channel from Zigbee NVRAM
    // and makes the selected role/channel deterministic for Bit Pirate.
    const bool ok = Zigbee.begin(target, true);
    initialized_ = true;
    if (!ok) {
        started_ = Zigbee.started();
        initFailed_ = true;
        return fail_("Zigbee begin failed or timed out. The stack is now locked for this boot; reboot before changing configuration.");
    }
    initFailed_ = false;
    started_ = true;
    pushEvent_("[STACK] started as " + ZigbeeRoleEnumMapper::toString(role_)
               + " on channel " + std::to_string(channel_));
    clearError_();
    return true;
}
#endif

bool ZigbeeService::setChannel(uint8_t channel) {
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        lastError_ = "Invalid Zigbee channel. Valid range is 11..26.";
        return false;
    }
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (initialized_ && channel != channel_) {
        return fail_("Channel is locked after the Zigbee stack has been initialized. \n\rReboot the expander, set the channel, then start again.");
    }
#endif
    channel_ = channel;
    lastError_.clear();
    return true;
}

bool ZigbeeService::setEndpoint(ZigbeeEndpointEnum endpoint) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (initialized_ && endpoint != activeEndpoint_) {
        return fail_("Emulated endpoint is locked after Zigbee initialization. Reboot the expander before changing it.");
    }
#endif
    endpoint_ = endpoint;
    lastError_.clear();
    return true;
}

ZigbeeEndpointEnum ZigbeeService::getEndpoint() const {
    return endpoint_;
}

bool ZigbeeService::start(ZigbeeRoleEnum role, uint8_t channel) {
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        lastError_ = "Invalid Zigbee channel. Valid range is 11..26.";
        return false;
    }
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (sniffing_) {
        return fail_("Raw 802.15.4 sniffer still owns the radio. Stop sniffing before starting Zigbee.");
    }
    if (!isRoleSupported(role)) {
        return fail_("Requested Zigbee role is not supported by this firmware build.");
    }
    if (initialized_) {
        if (role != role_) {
            return fail_("Role is locked after Zigbee initialization. Reboot the expander before changing role.");
        }
        if (channel != channel_) {
            return fail_("Channel is locked after Zigbee initialization. \n\rReboot the expander before changing channel.");
        }
        if (endpoint_ != activeEndpoint_) {
            return fail_("Emulated endpoint is locked after Zigbee initialization. Reboot the expander before changing endpoint.");
        }
    }
    role_ = role;
    channel_ = channel;
    return ensureStarted_();
#else
    (void)role;
    (void)channel;
    return false;
#endif
}

bool ZigbeeService::permitJoining(uint8_t seconds) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        return fail_("Zigbee stack is not running.");
    }
    if (role_ == ZigbeeRoleEnum::EndDevice) {
        return fail_("End devices cannot permit other devices to join.");
    }
    if (seconds == 0) {
        return closeJoining();
    }

    // ESP-Zigbee APIs are not thread-safe. Arduino's openNetwork() wrapper
    // calls esp_zb_bdb_open_network() without acquiring the Zigbee lock,
    // which is unsafe from our CLI task and can trip FreeRTOS critical-section
    // assertions when permit-join is reopened while the stack is running.
    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        return fail_("Could not acquire Zigbee stack lock for permit-join.");
    }
    const esp_err_t err = esp_zb_bdb_open_network(seconds);
    esp_zb_lock_release();
    if (err != ESP_OK) {
        return fail_(std::string("Could not open Zigbee network: ") + esp_err_to_name(err));
    }

    permitJoining_ = true;
    permitJoinDeadlineUs_ = static_cast<uint64_t>(esp_timer_get_time())
        + static_cast<uint64_t>(seconds) * 1000000ULL;
    pushEvent_("[JOIN] permit joining for " + std::to_string(seconds) + "s");
    clearError_();
    return true;
#else
    (void)seconds;
    return false;
#endif
}

bool ZigbeeService::closeJoining() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        return fail_("Zigbee stack is not running.");
    }
    if (role_ == ZigbeeRoleEnum::EndDevice) {
        return fail_("End devices do not manage permit-join state.");
    }

    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        return fail_("Could not acquire Zigbee stack lock to close joining.");
    }
    const esp_err_t err = esp_zb_bdb_close_network();
    esp_zb_lock_release();
    if (err != ESP_OK) {
        return fail_(std::string("Could not close Zigbee network: ") + esp_err_to_name(err));
    }

    permitJoining_ = false;
    permitJoinDeadlineUs_ = 0;
    pushEvent_("[JOIN] permit joining closed");
    clearError_();
    return true;
#else
    return false;
#endif
}

#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
static ZigbeeColorDimmerSwitch* asSwitch_(const std::unique_ptr<ZigbeeEP>& obj, bool started) {
    if (!started || !obj) {
        return nullptr;
    }
    return static_cast<ZigbeeColorDimmerSwitch*>(obj.get());
}
#endif

bool ZigbeeService::sendOn(bool state, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    if (group != 0) {
        state ? sw->lightOn(group) : sw->lightOff(group);
    } else {
        state ? sw->lightOn() : sw->lightOff();
    }
    return true;
#else
    (void)state;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendToggle(uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->lightToggle(group) : sw->lightToggle();
    return true;
#else
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendLevel(uint8_t level, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->setLightLevel(level, group) : sw->setLightLevel(level);
    return true;
#else
    (void)level;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::sendColorRgb(uint8_t red, uint8_t green, uint8_t blue, uint16_t group) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    ZigbeeColorDimmerSwitch* sw = asSwitch_(endpointObj_, started_);
    if (sw == nullptr || endpoint_ != ZigbeeEndpointEnum::Switch) {
        return false;
    }
    group ? sw->setLightColor(red, green, blue, group) : sw->setLightColor(red, green, blue);
    return true;
#else
    (void)red;
    (void)green;
    (void)blue;
    (void)group;
    return false;
#endif
}

bool ZigbeeService::setSensorTemperature(float celsius) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::TempSensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->setTemperature(celsius);
#else
    (void)celsius;
    return false;
#endif
}

bool ZigbeeService::setSensorHumidity(float percent) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::TempSensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->setHumidity(percent);
#else
    (void)percent;
    return false;
#endif
}

bool ZigbeeService::setOccupancyState(bool occupied) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || endpoint_ != ZigbeeEndpointEnum::OccupancySensor || !endpointObj_) {
        return false;
    }
    return static_cast<ZigbeeOccupancySensor*>(endpointObj_.get())->setOccupancy(occupied);
#else
    (void)occupied;
    return false;
#endif
}

bool ZigbeeService::reportSensorValues() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_ || !endpointObj_) {
        return false;
    }
    if (endpoint_ == ZigbeeEndpointEnum::TempSensor) {
        return static_cast<ZigbeeTempSensor*>(endpointObj_.get())->report();
    }
    if (endpoint_ == ZigbeeEndpointEnum::OccupancySensor) {
        return static_cast<ZigbeeOccupancySensor*>(endpointObj_.get())->report();
    }
    return false;
#else
    return false;
#endif
}

std::vector<std::string> ZigbeeService::takeEvents() {
    std::vector<std::string> drained;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    drained.reserve(events_.size());
    while (!events_.empty()) {
        drained.push_back(events_.front());
        events_.pop_front();
    }
#endif
    return drained;
}

std::vector<std::string> ZigbeeService::getRecentEvents() const {
    std::vector<std::string> snapshot;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    snapshot.reserve(events_.size());
    for (const auto& event : events_) {
        snapshot.push_back(event);
    }
#endif
    return snapshot;
}

std::vector<std::string> ZigbeeService::getBoundDeviceList() {
    std::vector<std::string> devices;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!endpointObj_) {
        return devices;
    }
    char addr[8];
    for (const zb_device_params_t* device : endpointObj_->getBoundDevices()) {
        snprintf(addr, sizeof(addr), "0x%04X", static_cast<unsigned>(device->short_addr));
        devices.emplace_back(addr);
    }
#endif
    return devices;
}

std::vector<ZigbeeNeighborInfo> ZigbeeService::getNeighborList() {
    std::vector<ZigbeeNeighborInfo> neighbors;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        fail_("Zigbee stack is not running.");
        return neighbors;
    }

    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        fail_("Could not acquire Zigbee stack lock.");
        return neighbors;
    }

    esp_zb_nwk_info_iterator_t iterator = ESP_ZB_NWK_INFO_ITERATOR_INIT;
    esp_zb_nwk_neighbor_info_t entry = {};
    while (esp_zb_nwk_get_next_neighbor(&iterator, &entry) == ESP_OK) {
        ZigbeeNeighborInfo info;
        info.ieeeAddress = formatIeee_(entry.ieee_addr);
        info.shortAddress = entry.short_addr;
        info.deviceType = entry.device_type;
        info.relationship = entry.relationship;
        info.depth = entry.depth;
        info.lqi = entry.lqi;
        info.rssi = entry.rssi;
        info.rxOnWhenIdle = entry.rx_on_when_idle == 1;
        neighbors.push_back(info);
        entry = {};
    }
    esp_zb_lock_release();

    std::map<uint16_t, uint8_t> current;
    for (const auto& info : neighbors) {
        current[info.shortAddress] = info.relationship;
        const auto previous = observedNeighbors_.find(info.shortAddress);
        if (previous == observedNeighbors_.end()) {
            char msg[96];
            snprintf(msg, sizeof(msg), "[DEVICE] seen 0x%04X relation=%u LQI=%u RSSI=%d dBm",
                     static_cast<unsigned>(info.shortAddress),
                     static_cast<unsigned>(info.relationship),
                     static_cast<unsigned>(info.lqi),
                     static_cast<int>(info.rssi));
            pushEvent_(msg);
        } else if (previous->second != info.relationship) {
            char msg[80];
            snprintf(msg, sizeof(msg), "[DEVICE] 0x%04X relation %u -> %u",
                     static_cast<unsigned>(info.shortAddress),
                     static_cast<unsigned>(previous->second),
                     static_cast<unsigned>(info.relationship));
            pushEvent_(msg);
        }
    }
    for (const auto& previous : observedNeighbors_) {
        if (current.find(previous.first) == current.end()) {
            char msg[48];
            snprintf(msg, sizeof(msg), "[DEVICE] 0x%04X left neighbor table",
                     static_cast<unsigned>(previous.first));
            pushEvent_(msg);
        }
    }
    observedNeighbors_.swap(current);
    clearError_();
#endif
    return neighbors;
}


bool ZigbeeService::inspectDevice(uint16_t shortAddress,
                                  ZigbeeDeviceDescriptor& out,
                                  uint32_t timeoutMs) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    out = ZigbeeDeviceDescriptor{};
    out.shortAddress = shortAddress;

    if (!started_) {
        return fail_("Zigbee stack is not running.");
    }
    if (shortAddress == 0xFFFF) {
        return fail_("Invalid device address.");
    }
    if (g_inspect.active) {
        return fail_("Another Zigbee device query is already running.");
    }

    g_inspect = DeviceInspectAccumulator{};
    g_inspect.active = true;
    g_inspect.address = shortAddress;
    g_inspect.endpoints.clear();

    esp_zb_zdo_active_ep_req_param_t req = {};
    req.addr_of_interest = shortAddress;
    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        g_inspect.active = false;
        return fail_("Could not acquire Zigbee stack lock.");
    }
    esp_zb_zdo_active_ep_req(&req, inspectActiveEpCb_, nullptr);
    esp_zb_lock_release();

    const uint32_t stepMs = 20;
    uint32_t waited = 0;
    while (!g_inspect.done && waited < timeoutMs) {
        vTaskDelay(pdMS_TO_TICKS(stepMs));
        waited += stepMs;
    }

    if (!g_inspect.done) {
        g_inspect.active = false;
        return fail_("Device descriptor query timed out. Sleepy devices may need to be woken first.");
    }

    out.endpoints = g_inspect.endpoints;
    const bool hadError = g_inspect.hadError;
    g_inspect = DeviceInspectAccumulator{};

    if (out.endpoints.empty()) {
        return fail_(hadError
            ? "Device did not return usable endpoint descriptors."
            : "Device returned no active application endpoints.");
    }

    clearError_();
    return true;
#else
    (void)shortAddress;
    (void)out;
    (void)timeoutMs;
    return false;
#endif
}

bool ZigbeeService::startScan(uint8_t duration) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        return fail_("Zigbee stack is not running. Start it before scanning for PANs.");
    }
    if (scanning_) {
        return fail_("Another Zigbee scan is already running.");
    }
    if (duration < 1 || duration > 4) {
        return fail_("Scan duration must be between 1 and 4.");
    }
    Zigbee.scanNetworks(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK, duration);
    scanning_ = true;
    clearError_();
    return true;
#else
    (void)duration;
    return false;
#endif
}

int16_t ZigbeeService::getScanStatus() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    // Core reports -2 when no scan was ever started, -1 while running,
    // otherwise the number of networks found
    return Zigbee.scanComplete();
#else
    return -2;
#endif
}

std::vector<ZigbeeNetworkInfo> ZigbeeService::takeScanResults() {
    std::vector<ZigbeeNetworkInfo> networks;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    const int16_t status = Zigbee.scanComplete();
    const zigbee_scan_result_t* results = (status > 0) ? Zigbee.getScanResult() : nullptr;
    if (results != nullptr) {
        networks.reserve(static_cast<size_t>(status));
        for (int16_t i = 0; i < status; ++i) {
            const zigbee_scan_result_t& net = results[i];
            ZigbeeNetworkInfo info;
            info.panId = net.short_pan_id;
            info.extendedPanId = formatIeee_(net.extended_pan_id);
            info.channel = net.logic_channel;
            info.permitJoining = net.permit_joining;
            info.routerCapacity = net.router_capacity;
            info.endDeviceCapacity = net.end_device_capacity;
            networks.push_back(info);
        }
    }
    // Arduino Zigbee owns the scan buffer; release it after copying.
    Zigbee.scanDelete();
    // Scan cycle is over either way: allow a new startScan()
    scanning_ = false;
#endif
    return networks;
}

bool ZigbeeService::beginSniff() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (initialized_) {
        return fail_("Raw sniffing must run before Zigbee 'start'. Reboot the expander to use sniff after stack initialization.");
    }
    if (sniffing_) {
        clearError_();
        return true;
    }

    esp_ieee802154_event_cb_list_t callbacks = {};
    callbacks.rx_done_cb = sniffRxDone_;
    callbacks.rx_sfd_done_cb = sniffSfdDone_;
    esp_err_t err = esp_ieee802154_event_callback_list_register(callbacks);
    if (err != ESP_OK) {
        return fail_(std::string("Could not register 802.15.4 sniffer callback: ") + esp_err_to_name(err));
    }

    err = esp_ieee802154_enable();
    if (err != ESP_OK) {
        esp_ieee802154_event_callback_list_unregister();
        return fail_(std::string("Could not enable 802.15.4 radio: ") + esp_err_to_name(err));
    }

    bool ok = true;
    if (esp_ieee802154_set_promiscuous(true) != ESP_OK) ok = false;
    if (esp_ieee802154_set_coordinator(false) != ESP_OK) ok = false;
    if (esp_ieee802154_set_rx_when_idle(false) != ESP_OK) ok = false;
    if (!ok) {
        esp_ieee802154_disable();
        esp_ieee802154_event_callback_list_unregister();
        return fail_("Could not configure the 802.15.4 radio for promiscuous sniffing.");
    }

    sniffing_ = true;
    g_sniffActive = false;
    resetSniffStats_(0);
    clearError_();
    return true;
#else
    return false;
#endif
}

bool ZigbeeService::setSniffChannel(uint8_t channel) {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!sniffing_) {
        return fail_("Raw sniffer is not running.");
    }
    if (!ZigbeeRoleEnumMapper::isValidChannel(channel)) {
        return fail_("Invalid IEEE 802.15.4 channel. Valid range is 11..26.");
    }

    // Stop reception before retuning so frames from the previous channel do
    // not leak into the next channel's counters.
    g_sniffActive = false;
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_sleep();

    const esp_err_t channelErr = esp_ieee802154_set_channel(channel);
    if (channelErr != ESP_OK) {
        return fail_(std::string("Could not tune 802.15.4 channel: ") + esp_err_to_name(channelErr));
    }

    resetSniffStats_(channel);
    const esp_err_t idleErr = esp_ieee802154_set_rx_when_idle(true);
    if (idleErr != ESP_OK) {
        return fail_(std::string("Could not enable continuous 802.15.4 RX: ") + esp_err_to_name(idleErr));
    }

    g_sniffActive = true;
    const esp_err_t rxErr = esp_ieee802154_receive();
    if (rxErr != ESP_OK) {
        g_sniffActive = false;
        esp_ieee802154_set_rx_when_idle(false);
        return fail_(std::string("Could not start 802.15.4 RX: ") + esp_err_to_name(rxErr));
    }

    clearError_();
    return true;
#else
    (void)channel;
    return false;
#endif
}

ZigbeeSniffInfo ZigbeeService::getSniffInfo() {
    ZigbeeSniffInfo info;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    RawSniffAccumulator raw;
    portENTER_CRITICAL(&g_sniffMux);
    raw = g_sniffStats;
    portEXIT_CRITICAL(&g_sniffMux);

    info.channel = raw.channel;
    info.frames = raw.frames;
    info.beacons = raw.beacons;
    info.dataFrames = raw.dataFrames;
    info.ackFrames = raw.ackFrames;
    info.commandFrames = raw.commandFrames;
    info.otherFrames = raw.otherFrames;
    info.associationRequests = raw.associationRequests;
    info.associationResponses = raw.associationResponses;
    info.beaconRequests = raw.beaconRequests;
    info.orphanNotifications = raw.orphanNotifications;
    info.phyHits = raw.phyHits;
    info.probableZigbeeBeacons = raw.probableZigbeeBeacons;
    info.probableZigbeeNwkFrames = raw.probableZigbeeNwkFrames;
    info.probableZigbeeNwkCommands = raw.probableZigbeeNwkCommands;
    info.zigbeeRejoinRequests = raw.zigbeeRejoinRequests;
    info.zigbeeRejoinResponses = raw.zigbeeRejoinResponses;
    info.zigbeeLeaveCommands = raw.zigbeeLeaveCommands;
    info.hasLastNwkAddresses = raw.hasLastNwkAddresses;
    info.lastNwkSource = raw.lastNwkSource;
    info.lastNwkDestination = raw.lastNwkDestination;
    if (raw.frames > 0) {
        info.weakestRssi = raw.weakestRssi;
        info.strongestRssi = raw.strongestRssi;
        info.averageRssi = static_cast<int16_t>(raw.rssiSum / static_cast<int32_t>(raw.frames));
        info.strongestLqi = raw.strongestLqi;
        info.averageLqi = static_cast<uint8_t>(raw.lqiSum / raw.frames);
    }

    info.panIds.reserve(raw.panCount);
    for (uint8_t i = 0; i < raw.panCount; ++i) {
        info.panIds.push_back(raw.panIds[i]);
    }
    info.joiningIeeeAddresses.reserve(raw.joinIeeeCount);
    for (uint8_t i = 0; i < raw.joinIeeeCount; ++i) {
        info.joiningIeeeAddresses.push_back(formatIeee_(raw.joinIeee[i]));
    }
#endif
    return info;
}

std::vector<ZigbeeSniffFrame> ZigbeeService::takeSniffFrames() {
    std::vector<ZigbeeSniffFrame> out;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    RawSniffFrame local[kMaxSniffFrames];
    size_t count = 0;
    portENTER_CRITICAL(&g_sniffMux);
    count = g_sniffFrameCount;
    const size_t start = (g_sniffFrameHead + kMaxSniffFrames - count) % kMaxSniffFrames;
    for (size_t i = 0; i < count; ++i) {
        local[i] = g_sniffFrames[(start + i) % kMaxSniffFrames];
    }
    g_sniffFrameCount = 0;
    portEXIT_CRITICAL(&g_sniffMux);

    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto& raw = local[i];
        ZigbeeSniffFrame frame;
        frame.channel = raw.channel;
        frame.rssi = raw.rssi;
        frame.lqi = raw.lqi;
        frame.macType = raw.macType;
        frame.macSecurity = raw.macSecurity;
        frame.hasPanId = raw.hasPanId;
        frame.panId = raw.panId;
        frame.hasMacSource = raw.hasMacSource;
        frame.macSource = raw.macSource;
        frame.hasMacDestination = raw.hasMacDestination;
        frame.macDestination = raw.macDestination;
        if (raw.hasSourceIeee) frame.sourceIeee = formatIeee_(raw.sourceIeee);
        frame.probableZigbeeBeacon = raw.probableZigbeeBeacon;
        frame.probableZigbeeNwk = raw.probableZigbeeNwk;
        frame.probableZigbeeInterPan = raw.probableZigbeeInterPan;
        frame.nwkSecurity = raw.nwkSecurity;
        frame.nwkCommand = raw.nwkCommand;
        frame.hasNwkAddresses = raw.hasNwkAddresses;
        frame.nwkSource = raw.nwkSource;
        frame.nwkDestination = raw.nwkDestination;
        frame.hasNwkCommand = raw.hasNwkCommand;
        frame.nwkCommandId = raw.nwkCommandId;
        frame.hasMacCommand = raw.hasMacCommand;
        frame.macCommandId = raw.macCommandId;
        frame.hasAps = raw.hasAps;
        frame.apsSecurity = raw.apsSecurity;
        frame.sourceEndpoint = raw.sourceEndpoint;
        frame.destinationEndpoint = raw.destinationEndpoint;
        frame.clusterId = raw.clusterId;
        frame.profileId = raw.profileId;
        frame.hasZcl = raw.hasZcl;
        frame.zclFrameType = raw.zclFrameType;
        frame.zclSequence = raw.zclSequence;
        frame.zclCommand = raw.zclCommand;
        frame.payload.assign(raw.payload, raw.payload + raw.payloadLength);
        out.push_back(std::move(frame));
    }
#endif
    return out;
}

void ZigbeeService::endSniff() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!sniffing_) return;

    g_sniffActive = false;
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_sleep();
    esp_ieee802154_disable();
    esp_ieee802154_event_callback_list_unregister();
    sniffing_ = false;
#endif
}


bool ZigbeeService::beginMonitor() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!started_) {
        return fail_("Zigbee stack is not running. Start Zigbee before monitor.");
    }
    if (sniffing_) {
        return fail_("Raw sniffer owns the radio; stop sniffing first.");
    }
    if (monitoring_) {
        clearError_();
        return true;
    }

    portENTER_CRITICAL(&g_monitorMux);
    g_monitorHead = 0;
    g_monitorCount = 0;
    portEXIT_CRITICAL(&g_monitorMux);
    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        return fail_("Could not acquire Zigbee stack lock for monitor.");
    }
    g_monitorActive = true;
    esp_zb_aps_data_indication_handler_register(monitorApsHandler_);
    esp_zb_lock_release();
    monitoring_ = true;
    clearError_();
    return true;
#else
    return false;
#endif
}

std::vector<ZigbeeMonitorFrame> ZigbeeService::takeMonitorFrames() {
    std::vector<ZigbeeMonitorFrame> out;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    RawMonitorFrame local[kMaxMonitorFrames];
    size_t count = 0;

    portENTER_CRITICAL(&g_monitorMux);
    count = g_monitorCount;
    const size_t start = (g_monitorHead + kMaxMonitorFrames - count) % kMaxMonitorFrames;
    for (size_t i = 0; i < count; ++i) {
        local[i] = g_monitorFrames[(start + i) % kMaxMonitorFrames];
    }
    g_monitorCount = 0;
    portEXIT_CRITICAL(&g_monitorMux);

    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ZigbeeMonitorFrame frame;
        frame.source = local[i].source;
        frame.destination = local[i].destination;
        frame.sourceEndpoint = local[i].sourceEndpoint;
        frame.destinationEndpoint = local[i].destinationEndpoint;
        frame.profileId = local[i].profileId;
        frame.clusterId = local[i].clusterId;
        frame.destinationAddressMode = local[i].destinationAddressMode;
        frame.securityStatus = local[i].securityStatus;
        frame.lqi = local[i].lqi;
        frame.payload.assign(local[i].payload, local[i].payload + local[i].payloadLength);
        out.push_back(std::move(frame));
    }
#endif
    return out;
}

void ZigbeeService::endMonitor() {
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (!monitoring_) return;
    g_monitorActive = false;
    // Restore the exact handler Arduino ZigbeeCore installed during begin().
    // If locking unexpectedly fails during teardown, leave our wrapper in
    // place but inactive; it still forwards every frame to Arduino unchanged.
    if (esp_zb_lock_acquire(portMAX_DELAY)) {
        esp_zb_aps_data_indication_handler_register(zb_apsde_data_indication_handler);
        esp_zb_lock_release();
    }
    monitoring_ = false;
#endif
}

ZigbeeNetworkStatus ZigbeeService::getStatus() {
    ZigbeeNetworkStatus status;
    status.supported = isSupported();
    status.initialized = initialized_;
    status.initFailed = initFailed_;
    status.started = started_;
    status.role = role_;
    status.channel = channel_;
    status.panId = panId_;
    status.shortAddress = shortAddress_;
#if defined(ZIGBEE_MODE_ED) || defined(ZIGBEE_MODE_ZCZR)
    if (permitJoining_) {
        const uint64_t nowUs = static_cast<uint64_t>(esp_timer_get_time());
        if (permitJoinDeadlineUs_ > nowUs) {
            const uint64_t remainingUs = permitJoinDeadlineUs_ - nowUs;
            uint64_t remainingSeconds = (remainingUs + 999999ULL) / 1000000ULL;
            if (remainingSeconds > 255) remainingSeconds = 255;
            status.permitJoining = true;
            status.permitJoinSecondsRemaining = static_cast<uint8_t>(remainingSeconds);
        } else {
            permitJoining_ = false;
            permitJoinDeadlineUs_ = 0;
        }
    }
    status.connected = started_ ? Zigbee.connected() : false;
    // Query live Zigbee state only while the stack is running.
    if (started_ && esp_zb_lock_acquire(portMAX_DELAY)) {
        const uint8_t activeChannel = esp_zb_get_current_channel();
        if (ZigbeeRoleEnumMapper::isValidChannel(activeChannel)) {
            status.channel = activeChannel;
            channel_ = activeChannel;
        }
        shortAddress_ = esp_zb_get_short_address();
        status.shortAddress = shortAddress_;
        if (status.connected || (started_ && role_ == ZigbeeRoleEnum::Coordinator)) {
            panId_ = static_cast<uint16_t>(esp_zb_get_pan_id());
            status.panId = panId_;
        }
        esp_zb_lock_release();
    }
#endif
    return status;
}

std::string ZigbeeService::getLastError() const {
    return lastError_;
}

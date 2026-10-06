# ESP32 Bus Expander

![ESP32 Bus Expander](https://github.com/geo-tp/ESP32-Bit-Pirate/raw/pioarduino/images/bus_pirate_exp.png)

**ESP32 Bus Expander** is a companion firmware for the [ESP32 Bit Pirate](https://github.com/geo-tp/ESP32-Bit-Pirate).

It runs on an **ESP32-C5** or **ESP32-C6** and connects to Bit Pirate over **UART**, adding radio capabilities not available on the main board, including **5 GHz Wi-Fi on ESP32-C5** and **IEEE 802.15.4 / Zigbee** support.

Flash it from the [ESP32 Bit Pirate Web Flasher](https://geo-tp.github.io/ESP32-Bit-Pirate/webflasher/) by selecting **ESP32 Bus Expander**.

## Concept

The expander acts as a small radio coprocessor controlled from the normal Bit Pirate terminal:

```text
ESP32 Bit Pirate
      │
      │ UART
      ▼
ESP32 Bus Expander
   ESP32-C5 / C6
```

Bit Pirate keeps the CLI, scripting and tools while the expander handles additional wireless protocols.

## Features

The Bus Expander adds a dedicated wireless coprocessor to Bit Pirate, providing:

**Wi-Fi**
- 2.4 GHz support on ESP32-C5 and ESP32-C6
- 5 GHz support on ESP32-C5
- Network scanning, packet capture and diagnostic tools

**Zigbee / IEEE 802.15.4**
- Raw 802.15.4 / Zigbee traffic sniffing
- Zigbee network discovery and pairing
- Device probing, endpoint and cluster discovery
- Live monitoring of paired-device traffic

Support for **Thread**, **Matter** and additional IEEE 802.15.4 protocols is planned.

## Hardware

Any **ESP32-C5 or ESP32-C6 board with at least 4 MB flash** should generally be compatible.

**PSRAM is not required.**

| Board | Chip | Status | Wi-Fi |
|---|---|---|---|
| ESP32-C5 DevKitC-1 | ESP32-C5 | Supported / tested | 2.4 + 5 GHz |
| ESP32-C6 DevKitM-1 | ESP32-C6 | Supported / tested | 2.4 GHz |
| Other ESP32-C5 boards | ESP32-C5 | Expected compatible | 2.4 + 5 GHz |
| Other ESP32-C6 boards | ESP32-C6 | Expected compatible | 2.4 GHz |

Other boards may only require adjusting UART pins in `platformio.ini`.

## Connection

The expander communicates with Bit Pirate over UART.

### ESP32-C5

| Bit Pirate | Bus Expander |
|---|---|
| RX | GPIO 9 |
| TX | GPIO 10 |
| GND | GND |

### ESP32-C6

| Bit Pirate | Bus Expander |
|---|---|
| RX | GPIO 19 |
| TX | GPIO 18 |
| GND | GND |

UART pins can be changed from `platformio.ini`.

## Wi-Fi Mode

Wi-Fi mode exposes the C5/C6 radio through the Bit Pirate CLI.

The **ESP32-C5 supports both 2.4 and 5 GHz**, while the **ESP32-C6 is limited to 2.4 GHz**.

| Command | Description |
|---|---|
| `connect [ssid] [password]` | Connect to a network |
| `disconnect` | Disconnect |
| `status` | Show Wi-Fi status |
| `scan` | Scan nearby networks |
| `ap <ssid> <password>` | Start an access point |
| `repeater` | Wi-Fi repeater mode |
| `sniff` | Capture Wi-Fi traffic |
| `deauth [ssid]` | Send deauthentication frames |
| `flood [channel]` | Beacon flood on a channel |
| `spam` | 5 GHz beacon spam - C5 only |
| `evil` | Active sniff/deauth/handshake tools - C5 only |
| `probe` | Probe open networks for internet access |
| `nmap <host> [-p port]` | Port scan |
| `http get <url>` | HTTP(S) GET request |
| `lookup mac\|ip <host>` | Network lookup utilities |
| `reset` | Reset Wi-Fi interface |

Use active Wi-Fi transmission features only on networks and devices you are authorized to test.


## Zigbee Mode

Zigbee mode provides a CLI for **IEEE 802.15.4 discovery, Zigbee network creation, pairing, device inspection and traffic monitoring**.

Two firmware configurations are available:

- `ZIGBEE_MODE_ZCZR` — Coordinator / Router
- `ZIGBEE_MODE_ED` — End Device / device emulation

Only one Zigbee configuration should be enabled at build time.

The default for release 

### Coordinator / Router commands

| Command | Description |
|---|---|
| `sniff [channel]` | Raw IEEE 802.15.4 / Zigbee traffic |
| `start [coordinator\|router] [channel]` | Start the Zigbee network |
| `scan [seconds]` | Discover Zigbee PANs and devices |
| `status` | Show network and runtime status |
| `channel [11-26]` | Select channel before `start` |
| `events` | Show recent network events |
| `pair [seconds]` | Wait for and pair one device |
| `permit <seconds\|off>` | Control the join window |
| `devices` | List devices and probe endpoints/clusters |
| `monitor` | Monitor traffic from paired devices |

### End Device build

The `ZIGBEE_MODE_ED` build exposes device-emulation commands instead of coordinator-only pairing tools.

Supported device types include:

```text
none
light
dimlight
colorlight
switch
tempsensor
occupancy
fan
outlet
rangeextender
```

Depending on the selected endpoint, commands are available for light control, dimming, color, fake temperature/humidity/occupancy values, reporting and bindings.

This mode is mainly useful for testing hubs, automations and Zigbee controllers. Release builds use the Coordinator / Router configuration by default

## Global Commands

| Command | Description |
|---|---|
| `reboot` | Restart the Bus Expander |
| `exit` | Return to the Bit Pirate CLI |

## Warning

> ⚠️ **RF Usage Warning:** Always respect local regulations and only transmit or test against devices and networks you are authorized to use.

## Credits

The Wi-Fi `evil` command and its sniffing, deauthentication and handshake capture features are based on [Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project).
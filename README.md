
# ESP32 Bus Expander

![Logo banner of the ESP32 Bus Expander](https://github.com/geo-tp/ESP32-Bit-Pirate/raw/pioarduino/images/bus_pirate_exp.png)

**ESP32 Bus Expander** is a companion firmware designed to extend the capabilities of the [ESP32 Bit Pirate](https://github.com/geo-tp/ESP32-Bit-Pirate).

It runs on an **ESP32-C5** or **ESP32-C6** and connects to the main Bit Pirate device via **UART**, adding hardware features that are not available on the primary board.

The first goal of this expansion module is to extend the Bit Pirate with additional wireless capabilities, including **5 GHz Wi-Fi** and support for **IEEE 802.15.4-based radio protocols** such as Zigbee, Thread, and Matter.

To flash it, use the webflasher and select **ESP32 Bus Expander**: [ESP32 Bit Pirate Web Flasher](https://geo-tp.github.io/ESP32-Bit-Pirate/webflasher/).

## Concept

Many boards used with the ESP32 Bit Pirate  only support **2.4 GHz Wi-Fi**.

The **ESP32 Bus Expander** solves this limitation by adding a secondary device that provides additional radio capabilities.

The architecture becomes:

```
ESP32 Bit Pirate (ESP32-S3)
        │
        │ UART
        ▼
ESP32 Bus Expander (ESP32-C5)
```

- The **Bit Pirate** remains the main interface (CLI, scripts, tools).
- The **Bus Expander** provides additional wireless hardware features.

It allows new radio technologies to be added without changing the main firmware.

## Current Features

- **Wi-Fi support** (C5 and C6) - see [Wi-Fi Mode](#wi-fi-mode)
- **Zigbee support** (C5 and C6) see [Zigbee Mode](#zigbee-mode)
- Connected to the Bit Pirate via **UART**
- Works as a **radio coprocessor**
- Can be controlled from the Bit Pirate firmware

With the expander connected, the Bit Pirate can interact with networks that require **802.15.4-based radio protocols**.

## Planned Features

Future firmware versions may extend support for additional radio protocols:

- **Thread**
- **Matter**
- Other **802.15.4 based protocols**

This will allow the ESP32 Bit Pirate ecosystem to interact with more **IoT wireless networks and devices**.


## Hardware

The Bus Expander is designed for **ESP32-C5 and ESP32-C6 based boards** with at least 4MB flash, no PSRAM needed.

## Connection

The Bus Expander connects to the main Bit Pirate using **UART**.

Typical C5 wiring:

| Bit Pirate | Bus Expander (C5) |
|------------|--------------|
| RX         | GPIO 9            |
| TX         | GPIO 10           |
| GND        | GND          |

Typical C6 wiring:

| Bit Pirate | Bus Expander (C6) |
|------------|-------------------|
| RX         | GPIO 19            |
| TX         | GPIO 18            |
| GND        | GND               |

Once connected, the Bit Pirate firmware can detect and communicate with the expander. You can set the UART config in the `platformio.ini` file.

## Wi-Fi Mode

The **Wi-Fi** mode turns the expander into a wireless network controller with
its own CLI, exposed through the Bit Pirate terminal.

Build environments:

| Environment | Board | Wi-Fi bands |
|-------------|-------|-------------|
| `c5slave`   | ESP32-C5 DevKitC-1 | 2.4 GHz and 5 GHz |
| `c6slave`   | ESP32-C6 DevKitM-1 | 2.4 GHz only |

The 5 GHz features are available only in the `c5slave` build. The C6 firmware
uses the same Wi-Fi commands, but its radio supports 2.4 GHz only.

Commands available inside Wi-Fi mode:

| Command | Description |
|---------|-------------|
| `connect [ssid] [password]` | Connect to a Wi-Fi network |
| `disconnect` / `status` | Disconnect or show connection status |
| `scan` | Scan nearby Wi-Fi networks |
| `ap <ssid> <password>` | Start an access point |
| `repeater` | Start or stop Wi-Fi repeater mode |
| `sniff` | Capture Wi-Fi traffic |
| `deauth [ssid]` | Send deauthentication frames |
| `flood [channel]` | Flood beacon frames on a channel |
| `spam` | Send beacon frames on 5 GHz channels (C5 only) |
| `evil` | Start active sniff/deauth/handshake capture (C5 only) |
| `probe` | Probe open networks for internet access |
| `nmap <host> [-p port]` | Scan ports on a host |
| `http get <url>` | Send an HTTP(S) GET request |
| `lookup mac\|ip <host>` | Run network lookup utilities |
| `reset` | Reset the Wi-Fi interface |

Notes:

- The C5 build provides the additional 5 GHz Wi-Fi band and related features.
- The C6 build keeps the same command interface but is limited to 2.4 GHz.
- Use only Wi-Fi scanning, capture, and transmission features on networks and
        devices for which you have explicit authorization.

## Zigbee Mode

The **ZIGBEE** mode turns the expander into a standalone Zigbee device emulator and network controller with its own CLI, exposed through the Bit Pirate terminal.

Build environments:

| Environment | Board | Zigbee roles |
|-------------|-------|--------------|
| `c6slave`   | ESP32-C6 DevKitM-1 | 2.4 GHz Wi-Fi; Coordinator + Router by default, or End Device |
| `c5slave`   | ESP32-C5 DevKitC-1 | 2.4/5 GHz Wi-Fi; Coordinator + Router by default, or End Device |

The environment builds the Coordinator/Router firmware by default with
`-D ZIGBEE_MODE_ZCZR`. To build the End Device firmware, replace that flag in
`platformio.ini` with `-D ZIGBEE_MODE_ED` before compiling. These are separate
compile-time Zigbee configurations; do not enable both flags at once.

The C6 UART is the command transport. USB Serial/JTAG may be used for board debugging, but is not the Bit Pirate command transport. The C5 build keeps its existing UART behavior on GPIO9/10.

Commands available inside ZIGBEE mode:

| Command | Description |
|---------|-------------|
| `start [coordinator\|router]` | Start the network in the given role |
| `stop` / `status` / `config` | Stack control and status |
| `channel 11-26` | Set the 802.15.4 channel before starting |
| `permit [seconds]` | Allow new devices to join |
| `device <type>` | Emulate an endpoint (see below) |
| `on` / `off` / `toggle [group]` | Control paired lights or a group |
| `dim <0-255 \| 0-100%> [group]` | Brightness of paired lights |
| `color rgb <r g b>` / `color hsv <h s v> [group]` | Color of paired lights |
| `settemp <celsius>` / `sethum <percent>` / `setocc <0\|1>` | Inject fake sensor readings |
| `report` | Report sensor readings immediately |
| `events` | Show events received from the network |
| `devices` | List devices bound to this endpoint |
| `scan [1-4]` | Scan channels for active networks |
| `reset` | Factory-reset the Zigbee network state |

Emulated device types (`device <type>`): `none`, `light`, `dimlight`, `colorlight`, `switch`, `tempsensor`, `occupancy`, `fan`, `outlet`, `rangeextender`.

Notes:

- As a **Light** device, hubs control the tool (received commands appear under `events`); as a **Switch**, the tool controls paired lights.
- Sensor readings are fake by design - useful to test how hubs and automations react to injected telemetry.
- Scenes are handled natively when hubs store/recall them. Groups can be targeted directly (`on 0x1234`).
- The End Device role requires a C6 firmware built with `ZIGBEE_MODE_ED`.


## Warning

> ⚠️ **RF Usage Warning**: Always respect local regulations regarding wireless transmissions.

## Credits

The `evil` command with features such as sniffing, deauthentication, and handshake capture comes from the [Evil Firmware](https://github.com/7h30th3r0n3/Evil-M5Project)

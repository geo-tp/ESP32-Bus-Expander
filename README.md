
# ESP32 Bus Expander

![Logo banner of the ESP32 Bus Expander](logo.png)

**ESP32 Bus Expander** is a companion firmware designed to extend the capabilities of the [ESP32 Bus Pirate](https://github.com/geo-tp/ESP32-Bus-Pirate).

It runs on an **ESP32-C5** and connects to the main Bus Pirate device via **UART**, adding hardware features that are not available on the primary board.

The first goal of this expansion module is to provide **5 GHz Wi-Fi support**, which is not available on most ESP32-S3 based boards. Future versions may also expose **802.15.4 radio protocols** such as **Zigbee** and **Thread**.

To flash it, use the webflasher and select **ESP32 Bus Expander (ESP32-C5)**: [ESP32 Bus Pirate Web Flasher](https://geo-tp.github.io/ESP32-Bus-Pirate/webflasher/).

## Concept

Many boards used with the ESP32 Bus Pirate  only support **2.4 GHz Wi-Fi**.

The **ESP32 Bus Expander** solves this limitation by adding a secondary device that provides additional radio capabilities.

The architecture becomes:

```
ESP32 Bus Pirate (ESP32-S3)
        │
        │ UART
        ▼
ESP32 Bus Expander (ESP32-C5)
```

- The **Bus Pirate** remains the main interface (CLI, scripts, tools).
- The **Bus Expander** provides additional wireless hardware features.

It allows new radio technologies to be added without changing the main firmware.

## Current Features

- **Wi-Fi 5 GHz support**
- Connected to the Bus Pirate via **UART**
- Works as a **radio coprocessor**
- Can be controlled from the Bus Pirate firmware

With the expander connected, the Bus Pirate can interact with networks that require **5 GHz connectivity**.

## Planned Features

Future firmware versions may extend support for additional radio protocols available on the **ESP32-C5**, including:

- **Zigbee (IEEE 802.15.4)**
- **Thread**
- **Matter**
- Other **802.15.4 based protocols**

This will allow the ESP32 Bus Pirate ecosystem to interact with **IoT wireless networks and devices**.


## Hardware

The Bus Expander is designed for **ESP32-C5 based boards**.

Minimum requirements:

- ESP32-C5 chip (4MB flash, no PSRAM needed)
- UART connection to the Bus Pirate device

## Connection

The Bus Expander connects to the main Bus Pirate using **UART**.

Typical wiring:

| Bus Pirate | Bus Expander |
|------------|--------------|
| RX         | 9            |
| TX         | 10           |
| GND        | GND          |

Once connected, the Bus Pirate firmware can detect and communicate with the expander. You can set the UART config in the `platformio.ini` file.


## Warning

> ⚠️ **RF Usage Warning**: Always respect local regulations regarding wireless transmissions.

## Credits

The `evil` command with features such as sniffing, deauthentication, and handshake capture comes from the [Evil Firmware](https://github.com/7h30th3r0n3/Evil-M5Project)

# picow-iot

Small example project that demonstrates connecting to an MQTT broker with a Pico W.  It uses lwIP's MQTT client and mbedtls to connect to a broker and transmit a message to a topic.

## Setup

Some configuration is needed to get the build working

### pico-sdk

A customized version of the SDK is currently being used until library support for lwIP MQTT and mbedtls
are added.  

Rebasing https://github.com/peterharperuk/pico-sdk/tree/add_mbedtls onto https://github.com/raspberrypi/pico-sdk/tree/develop will suffice.

### cmake

Configure cmake with the following variables, generally the same as pico-examples.
- PICO_SDK_PATH
- PICO_BOARD
- WIFI_SSID
- WIFI_PASSWORD
- LWIP_MBEDTLSDIR
- PICO_MBEDTLS_PATH

### crypto_consts.h custom header

The build relies on a simple header file (crypto_consts.h) to provide cryptographic keys and certificates as well.

See crytpo_consts_example.h for a setup for AWS IoT and Mosquitto test servers.
#ifndef CRYPTO_CONSTS_H_
#define CRYPTO_CONSTS_H_

// To use, copy to crypto_consts.h and define either
// CRYPTO_AWS_IOT or CRYPTO_MOSQUITTO_TEST and populate desired values.

// AWS IoT Core
#ifdef CRYPTO_AWS_IOT
#define MQTT_SERVER_HOST "example.iot.us-east-1.amazonaws.com"
#define MQTT_SERVER_PORT 8883
#define CRYPTO_CERT \
"-----BEGIN CERTIFICATE-----\n" \
"-----END CERTIFICATE-----\n";
#define CRYPTO_KEY \
"-----BEGIN RSA PRIVATE KEY-----\n" \
"-----END RSA PRIVATE KEY-----";
#define CRYPTO_CA \
"-----BEGIN CERTIFICATE-----\n" \
"-----END CERTIFICATE-----";
#endif

// Mosquitto test servers
#ifdef CRYPTO_MOSQUITTO_TEST
#if MQTT_TLS
#define MQTT_SERVER_PORT 8883
#else
#define MQTT_SERVER_PORT 1883
#endif
#define MQTT_SERVER_HOST "test.mosquitto.org"
#define CRYPTO_CERT \
"-----BEGIN CERTIFICATE-----\n" \
"-----END CERTIFICATE-----\n"
#endif

#endif
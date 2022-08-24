#include "hardware/structs/rosc.h"

#include <string.h>
#include <time.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"

#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/apps/mqtt.h"

#include "tusb.h"

#define DEBUG_printf printf

#define MQTT_TLS 0 // needs to be 1 for AWS IoT
#define CRYPTO_MOSQUITTO_TEST
// #define CRYPTO_AWS_IOT
#include "crypto_consts.h"

#if MQTT_TLS
#ifdef CRYPTO_CERT
const char *cert = CRYPTO_CERT;
#endif
#ifdef CRYPTO_CA
const char *ca = CRYPTO_CA;
#endif
#ifdef CRYPTO_KEY
const char *key = CRYPTO_KEY;
#endif
#endif

typedef struct MQTT_CLIENT_T_ {
    ip_addr_t remote_addr;
    mqtt_client_t *mqtt_client;
} MQTT_CLIENT_T;

void mqtt_test_connect(MQTT_CLIENT_T *state);

/* cribbed from https://github.com/peterharperuk/pico-examples/tree/add_mbedtls_example */
/* Function to feed mbedtls entropy. May be better to move it to pico-sdk */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    /* Code borrowed from pico_lwip_random_byte(), which is static, so we cannot call it directly */
    static uint8_t byte;

    for(int p=0; p<len; p++) {
        for(int i=0;i<32;i++) {
            // picked a fairly arbitrary polynomial of 0x35u - this doesn't have to be crazily uniform.
            byte = ((byte << 1) | rosc_hw->randombit) ^ (byte & 0x80u ? 0x35u : 0);
            // delay a little because the random bit is a little slow
            busy_wait_at_least_cycles(30);
        }
        output[p] = byte;
    }

    *olen = len;
    return 0;
}

// Perform initialisation
static MQTT_CLIENT_T* mqtt_client_init(void) {
    MQTT_CLIENT_T *state = calloc(1, sizeof(MQTT_CLIENT_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    return state;
}

void dns_found(const char *name, const ip_addr_t *ipaddr, void *callback_arg) {
    MQTT_CLIENT_T *state = (MQTT_CLIENT_T*)callback_arg;
    DEBUG_printf("DNS query finished with resolved addr of %s.\n", ip4addr_ntoa(ipaddr));
    state->remote_addr = *ipaddr;
}

void run_dns_lookup(MQTT_CLIENT_T *state) {
    printf("Running DNS query for %s.\n", MQTT_SERVER_HOST);

    cyw43_arch_lwip_begin();
    err_t err = dns_gethostbyname(MQTT_SERVER_HOST, &(state->remote_addr), dns_found, state);
    cyw43_arch_lwip_end();

    if (err == ERR_ARG) {
        DEBUG_printf("failed to start DNS query\n");
        return;
    }

    if (err == ERR_OK) {
        DEBUG_printf("no lookup needed");
        return;
    }

    while (state->remote_addr.addr == 0) {
        DEBUG_printf("waiting for DNS query to finish\n");
        sleep_ms(1000);
    }
}

static void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status) {
    MQTT_CLIENT_T *state = (MQTT_CLIENT_T *)arg;
    if (status != 0) {
        printf("reconnecting due to %d.\n", status);
        mqtt_test_connect(state);
    }
}

void mqtt_pub_request_cb(void *arg, err_t err) {
    printf("mqtt_pub_request_cb: err %d\n", err);
}

void mqtt_test_publish(mqtt_client_t *client, const char* str)
{
  char buffer[128];
  sprintf(buffer, "hello from picow %s", str);

  err_t err;
  u8_t qos = 2; /* 0 1 or 2, see MQTT specification */
  u8_t retain = 0; /* No don't retain such crappy payload... */
  err = mqtt_publish(client, "pico_w/test", buffer, strlen(buffer), qos, retain, mqtt_pub_request_cb, NULL);
  if(err != ERR_OK) {
    printf("Publish err: %d\n", err);
  }
}

void mqtt_test_connect(MQTT_CLIENT_T *state) {
    struct mqtt_connect_client_info_t ci;
    err_t err;

    memset(&ci, 0, sizeof(ci));

    ci.client_id = "PicoW";
    ci.client_user = NULL;
    ci.client_pass = NULL;
    ci.keep_alive = 6;
    ci.will_topic = NULL;
    ci.will_msg = NULL;
    ci.will_retain = 0;
    ci.will_qos = 0;

    #if MQTT_TLS
    struct altcp_tls_config *tls_config;

    printf("Allocating tls config.  Encryption values:\n");
    // printf("%sLength: %d\n", ca, 1 + strlen((const char *)ca));
    // printf("%sLength: %d\n", key, 1 + strlen((const char *)key));
    // printf("%sLength: %d\n", cert, 1 + strlen((const char *)cert));
    sleep_ms(500);

    #if defined(CRYPTO_CA) && defined(CRYPTO_KEY) && defined(CRYPTO_CERT)
    tls_config = altcp_tls_create_config_client_2wayauth(
        (const u8_t *)ca, 1 + strlen((const char *)ca),
        (const u8_t *)key, 1 + strlen((const char *)key),
        (const u8_t *)"", 0,
        (const u8_t *)cert, 1 + strlen((const char *)cert)
    );
    #endif

    #ifdef CRYPTO_CERT
    tls_config = altcp_tls_create_config_client((const u8_t *) cert, 1 + strlen((const char *) cert));
    #endif

    if (tls_config == NULL) {
        printf("Failed to initialize config\n");
        return;
    }

    ci.tls_config = tls_config;
    #endif

    cyw43_arch_lwip_begin();
    err = mqtt_client_connect(state->mqtt_client, &(state->remote_addr), MQTT_SERVER_PORT, mqtt_connection_cb, state, &ci);
    cyw43_arch_lwip_end();
    
    if (err != ERR_OK) {
        printf("mqtt_connect return %d\n", err);
    }
}

void mqtt_run_test(MQTT_CLIENT_T *state) {
    
    u32_t counter = 0;

    mqtt_test_connect(state);

    while (true) {
        sleep_ms(1000);
        if (mqtt_client_is_connected(state->mqtt_client)) {
            char buffer[32];
            itoa(counter, buffer, 10);
            mqtt_test_publish(state->mqtt_client, buffer);
            counter++;
            sleep_ms(4000);
        } else {
            printf(".");
        }
    }
}

void wait_for_usb() {
    while (!tud_cdc_connected()) {
        printf(".");
        sleep_ms(500);
    }
    printf("usb host detected\n");
}

int main() {
    stdio_init_all();

    // wait_for_usb();

    if (cyw43_arch_init()) {
        DEBUG_printf("failed to initialise\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();

    printf("Connecting to WiFi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect.\n");
        return 1;
    } else {
        printf("Connected.\n");
    }

    MQTT_CLIENT_T *state = mqtt_client_init();
    
    run_dns_lookup(state);

    state->mqtt_client = mqtt_client_new();

    if (state->mqtt_client != NULL) {
        mqtt_run_test(state);
    } else {
        printf("Failed to create new mqtt client\n");
    }

    cyw43_arch_deinit();
    return 0;
}
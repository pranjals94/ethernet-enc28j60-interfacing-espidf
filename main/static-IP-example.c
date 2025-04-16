/* ENC28J60 Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.

  The ESP32 microcontroller has four SPI (Serial Peripheral Interface) peripherals,
  including SPI0, SPI1, HSPI (SPI2), and VSPI (SPI3). SPI0 and SPI1 are used internally
  for communication with the on-board flash memory and should not be used by the user.
  HSPI and VSPI are general-purpose SPI interfaces that can be used for external communication
   with other devices.
many examples including static ip are available in the espIdf project examples
   
*/
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_eth_enc28j60.h"
#include "driver/spi_master.h"
#include <esp_http_server.h>
#include "cJSON.h"

static const char *TAG = "eth_example";
#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN (64)

#define Led GPIO_NUM_2

//-----------------------------static ip set---------------
//static esp_err_t example_set_dns_server(esp_netif_t *netif, uint32_t addr, esp_netif_dns_type_t type)
//{
//    if (addr && (addr != IPADDR_NONE)) {
//        esp_netif_dns_info_t dns;
//        dns.ip.u_addr.ip4.addr = addr;
//        dns.ip.type = IPADDR_TYPE_V4;
//        ESP_ERROR_CHECK(esp_netif_set_dns_info(netif, type, &dns));
//    }
//    return ESP_OK;
//}


/*
APIPA: (not implemented in this code)
When a DHCP server is unavailable, devices configured for DHCP will often fallback to assigning themselves a private IP address in the 169.254.0.0/16 range through APIPA. This allows them to communicate locally on the same subnet, but they won't be able to access other networks or the internet.
Static IP:
If a device has been manually configured with a static IP address, subnet mask, and default gateway, it will continue to use those settings, regardless of the DHCP server's status.
No IP:
If a device relies solely on DHCP and no alternative addressing method is configured, it will likely not have a valid IP address and will not be able to communicate on the network.
 */
static void example_set_static_ip(esp_netif_t *netif)
{
	ESP_LOGI(TAG, "Setting Static IP");
    if (esp_netif_dhcpc_stop(netif) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stop dhcp client");
        return;
    }
    esp_netif_ip_info_t ip;
    memset(&ip, 0 , sizeof(esp_netif_ip_info_t));
    //enter the ip in reverse order
    //Advisable to set in this range to work properly 169.254.0.0/16
    ip.ip.addr = 419539136;//IP address 1.1.254.169 is equal to 16907945, IP address 25.1.168.192 is equal to 419539136
    ip.netmask.addr = 65535;//IP address 0.0.255.255 is equal to 65535
//  ip.gw.addr = 2851995929;//IP address 169.254.1.25 is equal to 2851995929
// ip.gw.addr = ipaddr_addr("192.168.1.1"); // use ipaddr_addr function in #include <netdb.h> header file to convert the ip address
    if (esp_netif_set_ip_info(netif, &ip) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set ip info");
        return;
    }
//    ESP_LOGD(TAG, "Success to set static ip: %s, netmask: %s, gw: %s", EXAMPLE_STATIC_IP_ADDR, EXAMPLE_STATIC_NETMASK_ADDR, EXAMPLE_STATIC_GW_ADDR);
//    ESP_ERROR_CHECK(example_set_dns_server(netif, ipaddr_addr(EXAMPLE_MAIN_DNS_SERVER), ESP_NETIF_DNS_MAIN));
//    ESP_ERROR_CHECK(example_set_dns_server(netif, ipaddr_addr(EXAMPLE_BACKUP_DNS_SERVER), ESP_NETIF_DNS_BACKUP));
}

//-----------------------------------------------------------

/** Event handler for Ethernet events */
static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data)
{
    uint8_t mac_addr[6] = {0};
    /* we can get the ethernet driver handle from event data */
    esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;

    switch (event_id)
    {
    case ETHERNET_EVENT_CONNECTED:
        esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac_addr);
        ESP_LOGI(TAG, "Ethernet Link Up");
        ESP_LOGI(TAG, "Ethernet HW Addr %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Ethernet Link Down");
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet Started");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "Ethernet Stopped");
        break;
    default:
        break;
    }
}

/** Event handler for IP_EVENT_ETH_GOT_IP */
static void got_ip_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data)
{

    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "Ethernet Got IP Address");
    ESP_LOGI(TAG, "~~~~~~~~~~~");
    ESP_LOGI(TAG, "ETHIP:" IPSTR, IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "ETHMASK:" IPSTR, IP2STR(&ip_info->netmask));
    ESP_LOGI(TAG, "ETHGW:" IPSTR, IP2STR(&ip_info->gw));
    ESP_LOGI(TAG, "~~~~~~~~~~~");
}

//------------------web server codes--------------------

static esp_err_t ajax_request_handler(httpd_req_t *req)
{

    ESP_LOGI(TAG, "ajax_request_handler function called");

    const char *response = (const char *)req->user_ctx;
    esp_err_t error = httpd_resp_send(req, response, strlen(response));
    return error;
}

//------------An http post handler-------------
static esp_err_t ledBlink_handler(httpd_req_t *req)
{
    //------------------------test code start-----------------------
    ESP_LOGI(TAG, "LED Blinking");
    gpio_set_level(Led, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(Led, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(Led, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(Led, 0);

    int total_len = req->content_len;
    ESP_LOGI(TAG, "content length is'%d'", total_len);
    char buf[64]; // length of the content
    ESP_LOGI(TAG, "size of Buffer'%d'", sizeof(buf));
    if (total_len > sizeof(buf))
    {
        /* Respond with Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Error: cant handle long contents.");
        return ESP_FAIL;
    }
    int recv_size = MIN(total_len, sizeof(buf)); // turncate if content length larger tha buffer
    int ret = httpd_req_recv(req, buf, recv_size);
    if (ret <= 0) // 0 indicates connection is closed
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Connection Closed");
        return ESP_FAIL;
    }

    // create a cJSON object
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "name", "John Doe");
    cJSON_AddNumberToObject(json, "age", 30);
    cJSON_AddStringToObject(json, "email", "john.doe@example.com");
    // convert the cJSON object to a JSON string
    char *json_str = cJSON_Print(json);

    esp_err_t error = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    ESP_LOGI(TAG, "content is '%s'", buf);
    // cJSON *root = cJSON_Parse(buf);
    // int red = cJSON_GetObjectItem(root, "red")->valueint;
    // int green = cJSON_GetObjectItem(root, "green")->valueint;
    // int blue = cJSON_GetObjectItem(root, "blue")->valueint;
    // ESP_LOGI(REST_TAG, "Light control: red = %d, green = %d, blue = %d", red, green, blue);
    // cJSON_Delete(root);
    return error;
}

//--------post Request------
static const httpd_uri_t test_post_uri = {
    .uri = "/testPost",
    .method = HTTP_POST,
    .handler = ledBlink_handler,
    // .user_ctx = NULL,
    .user_ctx = "Post Request Successful"};
//-------post request end----

static const httpd_uri_t ajax_request_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = ajax_request_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = "<!DOCTYPE html>\
				<html>\
				\
                <script>\
                    function makeRequestWithFetch(){fetch('/testPost', {method : 'POST', headers: {\
                                              'Content-Type' : 'application/json'\
                                          },\
                                          body : JSON.stringify({key : 'value'})\
                                      })\
                                          .then(response => {\
                                              if (!response.ok)\
                                              {\
                                                  throw new Error('Network response was not ok ' + response.statusText);\
                                              }\
                                              return response.json();\
                                          })\
                                          .then(data => {\
                                              console.log(data);\
                                          })\
                                          .catch(error => {\
                                              console.error('There has been a problem with your fetch operation:', error);\
                                        });\
                                    }\
                     setInterval(makeRequestWithFetch, 3000);\
                </script >\
                <head>\
                <title>Pranjal</title>\
                <link rel=\"icon\" type=\"image/x-icon\" href=\"/favicon.ico\" >\
                </head>\
                <body>\
                <button onclick = \"makeRequestWithFetch()\"> Make AJAX Request with Fetch</button>\
				</body>\
				</html>"};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by a priviliged user in linux.
    // So when a unpriviliged user tries to run the application, it throws bind error and the server is not started.
    // Port 8001 can be used by an unpriviliged user as well. So the application will not throw bind error and the
    // server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &ajax_request_uri);
        httpd_register_uri_handler(server, &test_post_uri);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

void app_main(void)
{
	gpio_reset_pin(Led);
	gpio_set_direction(Led, GPIO_MODE_OUTPUT);

    ESP_ERROR_CHECK(gpio_install_isr_service(0));
    // Initialize TCP/IP network interface (should be called only once in application)
    ESP_ERROR_CHECK(esp_netif_init());

    // Create default event loop that running in background
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);

    spi_bus_config_t buscfg = {
        .miso_io_num = CONFIG_EXAMPLE_ENC28J60_MISO_GPIO,
        .mosi_io_num = CONFIG_EXAMPLE_ENC28J60_MOSI_GPIO,
        .sclk_io_num = CONFIG_EXAMPLE_ENC28J60_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_EXAMPLE_ENC28J60_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));
    /* ENC28J60 ethernet driver is based on spi driver */
    spi_device_interface_config_t spi_devcfg = {
        .mode = 0,
        .clock_speed_hz = CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ * 1000 * 1000,
        .spics_io_num = CONFIG_EXAMPLE_ENC28J60_CS_GPIO,
        .queue_size = 20,
        .cs_ena_posttrans = enc28j60_cal_spi_cs_hold_time(CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ),
    };

    eth_enc28j60_config_t enc28j60_config = ETH_ENC28J60_DEFAULT_CONFIG(CONFIG_EXAMPLE_ENC28J60_SPI_HOST, &spi_devcfg);
    enc28j60_config.int_gpio_num = CONFIG_EXAMPLE_ENC28J60_INT_GPIO;

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_enc28j60(&enc28j60_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.autonego_timeout_ms = 0; // ENC28J60 doesn't support auto-negotiation
    phy_config.reset_gpio_num = -1;     // ENC28J60 doesn't have a pin to reset internal PHY
    esp_eth_phy_t *phy = esp_eth_phy_new_enc28j60(&phy_config);

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));

    /* ENC28J60 doesn't burn any factory MAC address, we need to set it manually.
       02:00:00 is a Locally Administered OUI range so should not be used except when testing on a LAN under your control.
    */
    mac->set_addr(mac, (uint8_t[]){
                           0x02, 0x00, 0x00, 0x12, 0x34, 0x56});

    // ENC28J60 Errata #1 check
    if (emac_enc28j60_get_chip_info(mac) < ENC28J60_REV_B5 && CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ < 8)
    {
        ESP_LOGE(TAG, "SPI frequency must be at least 8 MHz for chip revision less than 5");
        ESP_ERROR_CHECK(ESP_FAIL);
    }

    //set static ip
    example_set_static_ip(eth_netif);

    /* attach Ethernet driver to TCP/IP stack */
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    // Register user defined event handers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));
    /* It is recommended to use ENC28J60 in Full Duplex mode since multiple errata exist to the Half Duplex mode */
#if CONFIG_EXAMPLE_ENC28J60_DUPLEX_FULL
    eth_duplex_t duplex = ETH_DUPLEX_FULL;
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_DUPLEX_MODE, &duplex));
#endif

    /* start Ethernet driver state machine */
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    start_webserver();

    //--------------------------------
}

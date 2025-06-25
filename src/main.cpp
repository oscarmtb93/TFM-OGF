#include <Arduino.h>

#define IZQ // Si está definido, el código serña el ESP32 del lado izquierdo
// #define DER // Si está definido, el código serña el ESP32 del lado derecho

/*
El siguiente sketch es el código de la mplaca de control
de los mandos de los cepillos de la barredora de FCC.

v2.0 - ESP32-C6
*/

#include "driver/twai.h"

const unsigned long BAUDRATE = 115200;
const twai_timing_config_t BITRATE_CAN = TWAI_TIMING_CONFIG_500KBITS(); // Bitrate del CAN que conecta con control

#ifdef IZQ                             // Los pines para el transceptor CAN del lado izquierdo
const gpio_num_t txCtrl = GPIO_NUM_45; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_48; // Pin RxCAN del CAN
#endif
#ifdef DER                             // Los pines para el transceptor CAN del lado derecho
const gpio_num_t txCtrl = GPIO_NUM_10; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_9;  // Pin RxCAN del CAN
#endif

// Variables mensajes CAN
const bool CAN_EXTENDIDO = false; // Si es true, es CAN extendido; si es false, es estándar
const uint32_t MASCARA_EXTENDIDO = 0x1FFFFFFF;
const uint32_t MASCARA_ESTANDAR = 0x7FF;
const uint8_t SIZE_DLC = 8;
const uint32_t idCanDownloadRequest = 0x100;
twai_message_t mensajeCAN = {
    .flags = 0, // Inicializa toda la unión a 0
    .identifier = idCanDownloadRequest,
    .data_length_code = 8,
    .data = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}};
twai_message_t mensajeCANLeido;

void setup()
{
  Serial.begin(BAUDRATE);

  // Inicializamos CAN de control
  twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(txCtrl, rxCtrl, TWAI_MODE_NORMAL);
  // twai_filter_config_t filter_config = TWAI_FILTER_CONFIG_ACCEPT_ALL(); //Esta línea sería para aceptar cualquier mensaje CAN

  // Configuración de la máscara y el filtro
  // Configura la máscara en función si el CAN es estándar o extendido
  uint32_t mascara, desplazamiento, acceptance_code, acceptance_mask;
  if (CAN_EXTENDIDO)
  {
    mascara = MASCARA_EXTENDIDO;
    desplazamiento = 3;
  }
  else
  {
    mascara = MASCARA_ESTANDAR;
    desplazamiento = 21;
  }
  acceptance_code = idCanDownloadRequest << desplazamiento;
  acceptance_mask = ~(mascara << desplazamiento);
  twai_filter_config_t filter_config = {
      .acceptance_code = acceptance_code, // Filtro para ID idCanDownloadRequest
      .acceptance_mask = acceptance_mask, // Máscara para ID estándar (11 bits)
      .single_filter = true               // Usa un solo filtro
  };

  // Instalar el controlador TWAI para el bus de CAN
  twai_driver_uninstall();
  while (twai_driver_install(&g_config, &BITRATE_CAN, &filter_config) != ESP_OK) // Bucle mientras no esté todo correcto
  {
    Serial.println("Fallo al instalar el driver del CAN");
    delay(100);
  }
  Serial.println("Driver del CAN instalado");

  // Inicia TWAI driver para el bus de CAN
  while (twai_start() != ESP_OK) // Bucle mientras no esté todo correcto
  {
    Serial.println("Fallo al iniciar el driver del CAN");
    delay(100);
  }
  Serial.println("Driver del CAN iniciado");
}

void loop()
{
#ifdef IZQ                                         // El código para el ESP32 del lado izquierdo
  twai_transmit(&mensajeCAN, pdMS_TO_TICKS(1000)); // Enviar el mensaje CAN
  Serial.println("He enviado un mensaje de CAN");
  delay(1000);
#endif
#ifdef DER                                                        // El código para el ESP32 del lado derecho
  if (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) == ESP_OK) // Cuando recibo un mensaje de CAN
  {
    Serial.println("He recibido un mensaje de CAN");
  }
#endif
}

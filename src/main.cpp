#include <Arduino.h>

/*
El siguiente sketch es el código para analizar la
latencia en una red CAN cifrada.

v1.0 - ESP32-S3
*/

#define IZQ // Si está definido, el código serña el ESP32 del lado izquierdo
// #define DER // Si está definido, el código serña el ESP32 del lado derecho

#include "driver/twai.h"

const unsigned long BAUDRATE = 115200;

// Variables mensajes CAN
const twai_timing_config_t BITRATE_CAN = TWAI_TIMING_CONFIG_500KBITS(); // Bitrate de la línea CAN
const bool CAN_EXTENDIDO = false;                                       // Si es true, es CAN extendido; si es false, es estándar
const uint32_t MASCARA_EXTENDIDO = 0x1FFFFFFF;
const uint32_t MASCARA_ESTANDAR = 0x7FF;
const uint8_t SIZE_DLC = 8;
const uint32_t idCanDownloadRequest = 0x100;
twai_message_t mensajeCANTransmitido = {
    .flags = 0, // Inicializa toda la unión a 0
    .identifier = idCanDownloadRequest,
    .data_length_code = SIZE_DLC,
    .data = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}};
twai_message_t mensajeCANLeido;
// Número de repeticiones de cada prueba
const uint8_t NUM_REP = 100;

#ifdef IZQ                             // Los pines para el transceptor CAN del lado izquierdo
const gpio_num_t txCtrl = GPIO_NUM_45; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_48; // Pin RxCAN del CAN
unsigned long tiempoInicial, tiempoFinal, tiempoTranscurrido[NUM_REP], sumatorio;
double media;
#endif
#ifdef DER                             // Los pines para el transceptor CAN del lado derecho
const gpio_num_t txCtrl = GPIO_NUM_10; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_9;  // Pin RxCAN del CAN
uint8_t datosRecibidos[SIZE_DLC];
#endif

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
#ifdef IZQ // El código para el ESP32 del lado izquierdo
  // Con esto damos tiempo a que se inicie el ESP32 derecho
  delay(1000);
  // Iniciamos la fase de enviar mensajes sin cifrar
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < SIZE_DLC; i++)
    {
      mensajeCANTransmitido.data[i] = i;
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    // Esperamos a que nos llegue el mensaje de vuelta
    while (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) != ESP_OK)
    {
    }
    // Momento que finalizamos la cuenta
    tiempoFinal = micros();
    // Tiempo empleado en el proceso
    tiempoTranscurrido[i] = tiempoFinal - tiempoInicial;
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.print(tiempoTranscurrido[i]);
    Serial.print(" ");
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.print("\nLa media del envío de datos sin cifrar ha sido: ");
  Serial.print(media);
  Serial.println(" us");
  // Hemos acabado, mandamos al ESP32 a dormir para que no se ejecute infinitamente
  Serial.println("Fin de la ejecución del ESP32 izquierdo");
  esp_deep_sleep_start();
#endif
#ifdef DER // El código para el ESP32 del lado derecho
  // Iniciamos la fase de recibir mensajes sin cifrar
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    // Esperamos a que nos llegue el primer mensaje
    while (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) != ESP_OK)
    {
    }
    // Leemos el campo de datos recibido
    for (uint8_t i = 0; i < SIZE_DLC; i++)
    {
      datosRecibidos[i] = mensajeCANLeido.data[i];
    }
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < SIZE_DLC; i++)
    {
      mensajeCANTransmitido.data[i] = datosRecibidos[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Fin de la ejecución del ESP32 derecho");
#endif
}

#include <Arduino.h>

/*
El siguiente sketch es el código para analizar la
latencia en una red CAN cifrada.

v1.0 - ESP32-S3
*/

#define IZQ // Si está definido, el código serña el ESP32 del lado izquierdo
// #define DER // Si está definido, el código serña el ESP32 del lado derecho

// Librería para utilizar el controlador CAN del ESP32
#include "driver/twai.h"
// Librería para utilizar el cifrado integrado en el ESP32
#include <mbedtls/aes.h>

const unsigned long BAUDRATE = 115200;
const uint8_t LONGITUD_MENSAJE_AES = 16;
const uint8_t LONGITUD_128 = 128;
const uint16_t LONGITUD_256 = 256;
uint8_t claveAES128[LONGITUD_128 / 8] = {
    0x87, 0x04, 0x0A, 0x89, 0x59, 0x22, 0xE6, 0x52,
    0x05, 0x6C, 0xE6, 0xB2, 0xCD, 0x3F, 0xB1, 0xA0};
uint8_t claveAES256[LONGITUD_256 / 8] = {
    0x61, 0xB1, 0xC1, 0xEF, 0x69, 0xD1, 0x66, 0x41,
    0xE4, 0x53, 0x5A, 0x03, 0x38, 0x0F, 0x2C, 0x0B,
    0xFA, 0xCC, 0xB6, 0x5D, 0x1F, 0x0D, 0x5E, 0x06,
    0x8D, 0x56, 0x71, 0xE9, 0xB9, 0xEE, 0xD6, 0x25};

// Variables mensajes CAN
const twai_timing_config_t BITRATE_CAN = TWAI_TIMING_CONFIG_500KBITS(); // Bitrate de la línea CAN
const bool CAN_EXTENDIDO = false;                                       // Si es true, es CAN extendido; si es false, es estándar
const uint32_t MASCARA_EXTENDIDO = 0x1FFFFFFF;
const uint32_t MASCARA_ESTANDAR = 0x7FF;
const uint8_t LONGITUD_MENSAJE_CAN = 8;
const uint32_t idCanTransmiteIzq = 0x100;
const uint32_t idCanTransmiteDer = 0x101;
twai_message_t mensajeCANTransmitido = {
    .flags = 0, // Inicializa toda la unión a 0
#ifdef IZQ      // El lado izquierdo transmite en un mensaje
    .identifier = idCanTransmiteIzq,
#endif
#ifdef DER // El lado derecho transmite en otro mensaje
    .identifier = idCanTransmiteDer,
#endif
    .data_length_code = LONGITUD_MENSAJE_CAN,
    .data = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}};
twai_message_t mensajeCANLeido;
// Número de repeticiones de cada prueba
const uint8_t NUM_REP = 100;

// Variables para el cifrado
mbedtls_aes_context cifradorAES;
uint8_t mensajeCifradoAES[LONGITUD_MENSAJE_AES];
const uint8_t MENSAJES_AES = LONGITUD_MENSAJE_AES / LONGITUD_MENSAJE_CAN;
twai_message_t mensajesCanLeidosAES[MENSAJES_AES];

#ifdef IZQ                             // Los pines para el transceptor CAN del lado izquierdo
const gpio_num_t txCtrl = GPIO_NUM_45; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_48; // Pin RxCAN del CAN
unsigned long tiempoInicial, tiempoFinal, tiempoTranscurrido[NUM_REP], sumatorio;
double media;
uint8_t entradaCifradoAES[LONGITUD_MENSAJE_AES];
#endif
#ifdef DER                             // Los pines para el transceptor CAN del lado derecho
const gpio_num_t txCtrl = GPIO_NUM_10; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_9;  // Pin RxCAN del CAN
uint8_t datosRecibidos[LONGITUD_MENSAJE_CAN];
uint8_t salidaDescifradoAES[LONGITUD_MENSAJE_AES];
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
#ifdef IZQ // El lado izquierdo recibe en un mensaje
  acceptance_code = idCanTransmiteDer << desplazamiento;
#endif
#ifdef DER // El lado derecho recibe en otro mensaje
  acceptance_code = idCanTransmiteIzq << desplazamiento;
#endif
  acceptance_mask = ~(mascara << desplazamiento);
  twai_filter_config_t filter_config = {
      .acceptance_code = acceptance_code, // Filtro para ID idCan
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
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
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
    tiempoTranscurrido[k] = tiempoFinal - tiempoInicial;
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

  // Empezamos con el cifrado AES-128
  // Inicializamos el cifrador AES
  mbedtls_aes_init(&cifradorAES);
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el dato a ser cifrado con AES-128
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      entradaCifradoAES[i] = i;
    }
    for (uint8_t i = LONGITUD_MENSAJE_CAN; i < LONGITUD_MENSAJE_AES; i++)
    {
      entradaCifradoAES[i] = 0; // Padding ya que la entrada del cifrador es de 16 bytes
    }
    // Ciframos con AES-128
    mbedtls_aes_setkey_enc(&cifradorAES, claveAES128, LONGITUD_128);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_ENCRYPT, entradaCifradoAES, mensajeCifradoAES);
    // Rellenamos los dos mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = mensajeCifradoAES[j + i * LONGITUD_MENSAJE_CAN];
      }
      // Enviar el mensaje CAN
      twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    }
    // Esperamos a que nos llegue el mensaje de vuelta
    while (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) != ESP_OK)
    {
    }
    // Momento que finalizamos la cuenta
    tiempoFinal = micros();
    // Tiempo empleado en el proceso
    tiempoTranscurrido[k] = tiempoFinal - tiempoInicial;
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
  Serial.print("\nLa media del envío de datos cifrados con AES-128 ha sido: ");
  Serial.print(media);
  Serial.println(" us");
  // Limpiamos el cifrador AES
  mbedtls_aes_free(&cifradorAES);

  // Empezamos con el cifrado AES-256
  // Inicializamos el cifrador AES
  mbedtls_aes_init(&cifradorAES);
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el dato a ser cifrado con AES-256
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      entradaCifradoAES[i] = i;
    }
    for (uint8_t i = LONGITUD_MENSAJE_CAN; i < LONGITUD_MENSAJE_AES; i++)
    {
      entradaCifradoAES[i] = 0; // Padding ya que la entrada del cifrador es de 16 bytes
    }
    // Ciframos con AES-256
    mbedtls_aes_setkey_enc(&cifradorAES, claveAES256, LONGITUD_256);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_ENCRYPT, entradaCifradoAES, mensajeCifradoAES);
    // Rellenamos los dos mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = mensajeCifradoAES[j + i * LONGITUD_MENSAJE_CAN];
      }
      // Enviar el mensaje CAN
      twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    }
    // Esperamos a que nos llegue el mensaje de vuelta
    while (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) != ESP_OK)
    {
    }
    // Momento que finalizamos la cuenta
    tiempoFinal = micros();
    // Tiempo empleado en el proceso
    tiempoTranscurrido[k] = tiempoFinal - tiempoInicial;
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
  Serial.print("\nLa media del envío de datos cifrados con AES-256 ha sido: ");
  Serial.print(media);
  Serial.println(" us");
  // Limpiamos el cifrador AES
  mbedtls_aes_free(&cifradorAES);

  // Hemos acabado, mandamos al ESP32 a dormir para que no se ejecute infinitamente
  Serial.println("Fin de la ejecución del ESP32 izquierdo");
  esp_deep_sleep_start();
#endif
#ifdef DER // El código para el ESP32 del lado derecho
  // Iniciamos la fase de recibir mensajes sin cifrar
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    // Esperamos a que nos llegue el primer mensaje
    while (twai_receive(&mensajeCANLeido, pdMS_TO_TICKS(0)) != ESP_OK)
    {
    }
    // Leemos el campo de datos recibido
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      datosRecibidos[i] = mensajeCANLeido.data[i];
    }
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = datosRecibidos[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes sin cifrar");

  // Iniciamos la fase de recibir mensajes cifrados con AES-128
  // Inicializamos el cifrador AES
  mbedtls_aes_init(&cifradorAES);
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      // Esperamos a que nos llegue los mensajes cifrados
      while (twai_receive(&mensajesCanLeidosAES[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCifradoAES[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosAES[i].data[j];
      }
    }
    // Desciframos los mensajes recibidos
    mbedtls_aes_setkey_dec(&cifradorAES, claveAES128, LONGITUD_128);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_DECRYPT, mensajeCifradoAES, salidaDescifradoAES);
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes cifrados con AES-128");
  // Limpiamos el cifrador AES
  mbedtls_aes_free(&cifradorAES);

  // Iniciamos la fase de recibir mensajes cifrados con AES-256
  // Inicializamos el cifrador AES
  mbedtls_aes_init(&cifradorAES);
  for (uint8_t k = 0; k < NUM_REP; k++)
  {
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      // Esperamos a que nos llegue los mensajes cifrados
      while (twai_receive(&mensajesCanLeidosAES[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido
    for (uint8_t i = 0; i < MENSAJES_AES; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCifradoAES[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosAES[i].data[j];
      }
    }
    // Desciframos los mensajes recibidos
    mbedtls_aes_setkey_dec(&cifradorAES, claveAES256, LONGITUD_256);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_DECRYPT, mensajeCifradoAES, salidaDescifradoAES);
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes cifrados con AES-256");
  // Limpiamos el cifrador AES
  mbedtls_aes_free(&cifradorAES);

  Serial.println("Fin de la ejecución del ESP32 derecho");
#endif
}

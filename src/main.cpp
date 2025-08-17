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
// Librerías para utilizar el cifrado y firma integrados en el ESP32
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h> //Esta librería incluye SHA-224 y SHA-256

const unsigned long BAUDRATE = 115200;

// Constantes para el cifrado AES
const uint8_t LONGITUD_MENSAJE_AES = 16;
const uint8_t MENSAJES_AES = 2;
const uint8_t LONGITUD_128 = 128;
const uint16_t LONGITUD_256 = 256;
const uint8_t claveAES128[LONGITUD_128 / 8] = {
    0x87, 0x04, 0x0A, 0x89, 0x59, 0x22, 0xE6, 0x52,
    0x05, 0x6C, 0xE6, 0xB2, 0xCD, 0x3F, 0xB1, 0xA0};
const uint8_t claveAES256[LONGITUD_256 / 8] = {
    0x61, 0xB1, 0xC1, 0xEF, 0x69, 0xD1, 0x66, 0x41,
    0xE4, 0x53, 0x5A, 0x03, 0x38, 0x0F, 0x2C, 0x0B,
    0xFA, 0xCC, 0xB6, 0x5D, 0x1F, 0x0D, 0x5E, 0x06,
    0x8D, 0x56, 0x71, 0xE9, 0xB9, 0xEE, 0xD6, 0x25};

// Constantes para el hash MD5
const uint8_t LONGITUD_MD5 = 16;
const uint8_t MENSAJES_MD5 = 2;

// Constantes para el hash SHA-1
const uint8_t LONGITUD_SHA1 = 20;
const uint8_t MENSAJES_SHA1 = 3;

// Constantes para el hash SHA-224
const uint8_t LONGITUD_SHA224 = 28;
const uint8_t MENSAJES_SHA224 = 4;

// Constantes para el hash SHA-224
const uint8_t LONGITUD_SHA256 = 32;
const uint8_t MENSAJES_SHA256 = 4;

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

// Variables para el cifrado AES
mbedtls_aes_context cifradorAES;
uint8_t mensajeCifradoAES[LONGITUD_MENSAJE_AES];

// Variables para el hash MD5
mbedtls_md5_context contextoMD5;
uint8_t md5Generado[LONGITUD_MD5];

// Variables para el hash SHA-1
mbedtls_sha1_context contextoSHA1;
uint8_t sha1Generado[LONGITUD_SHA1];

// Variables para el hash SHA-224
mbedtls_sha256_context contextoSHA224;
uint8_t sha224Generado[LONGITUD_SHA224];

// Variables para el hash SHA-256
mbedtls_sha256_context contextoSHA256;
uint8_t sha256Generado[LONGITUD_SHA256];

// A continuación, variables que sólo aplican en el ESP32 izquierdo
#ifdef IZQ
// Los pines para el transceptor CAN del lado izquierdo
const gpio_num_t txCtrl = GPIO_NUM_45; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_48; // Pin RxCAN del CAN
unsigned long tiempoInicial, tiempoFinal, tiempoTranscurrido[NUM_REP], sumatorio;
double media;
uint8_t entradaCifradoAES[LONGITUD_MENSAJE_AES];
#endif

// A continuación, variables que sólo aplican en el ESP32 derecho
#ifdef DER
// Los pines para el transceptor CAN del lado derecho
const gpio_num_t txCtrl = GPIO_NUM_10; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_9;  // Pin RxCAN del CAN
uint8_t datosRecibidos[LONGITUD_MENSAJE_CAN];
twai_message_t mensajesCanLeidosAES[MENSAJES_AES];
uint8_t salidaDescifradoAES[LONGITUD_MENSAJE_AES];
twai_message_t mensajesCanLeidosMD5[MENSAJES_MD5];
uint8_t md5Recibido[LONGITUD_MD5];
twai_message_t mensajesCanLeidosSHA1[MENSAJES_SHA1];
uint8_t sha1Recibido[LONGITUD_SHA1];
twai_message_t mensajesCanLeidosSHA224[MENSAJES_SHA224];
uint8_t sha224Recibido[LONGITUD_SHA224];
twai_message_t mensajesCanLeidosSHA256[MENSAJES_SHA256];
uint8_t sha256Recibido[LONGITUD_SHA256];
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
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos sin cifrar ha sido: %f us\n", media);

  // Empezamos con el cifrado AES-128
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    mbedtls_aes_init(&cifradorAES); // Inicializamos el cifrador AES
    mbedtls_aes_setkey_enc(&cifradorAES, claveAES128, LONGITUD_128);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_ENCRYPT, entradaCifradoAES, mensajeCifradoAES);
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
    // Rellenamos los mensajes a enviar
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos cifrados con AES-128 ha sido: %f us\n", media);

  // Empezamos con el cifrado AES-256
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    mbedtls_aes_init(&cifradorAES); // Inicializamos el cifrador AES
    mbedtls_aes_setkey_enc(&cifradorAES, claveAES256, LONGITUD_256);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_ENCRYPT, entradaCifradoAES, mensajeCifradoAES);
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
    // Rellenamos los mensajes a enviar
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos cifrados con AES-256 ha sido: %f us\n", media);

  // Empezamos con el hash MD5
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar para que luego el receptor tenga la referencia
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = i;
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    // Realizamos el hash con MD5
    mbedtls_md5_init(&contextoMD5); // Inicializamos el contexto MD5
    mbedtls_md5_starts_ret(&contextoMD5);
    mbedtls_md5_update_ret(&contextoMD5, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_md5_finish_ret(&contextoMD5, md5Generado);
    mbedtls_md5_free(&contextoMD5); // Limpiamos el contexto MD5
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_MD5; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = md5Generado[j + i * LONGITUD_MENSAJE_CAN];
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash MD5 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash MD5 ha ido MAL\n", k);
    }
    */
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos hasheados con MD5 ha sido: %f us\n", media);

  // Empezamos con el hash SHA-1
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar para que luego el receptor tenga la referencia
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = i;
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    // Realizamos el hash con SHA-1
    mbedtls_sha1_init(&contextoSHA1); // Inicializamos el contexto SHA-1
    mbedtls_sha1_starts_ret(&contextoSHA1);
    mbedtls_sha1_update_ret(&contextoSHA1, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha1_finish_ret(&contextoSHA1, sha1Generado);
    mbedtls_sha1_free(&contextoSHA1); // Limpiamos el contexto SHA-1
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_SHA1 - 1; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = sha1Generado[j + i * LONGITUD_MENSAJE_CAN];
      }
      // Enviar el mensaje CAN
      twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    }
    // Esto es porque no rellenamos entero el último mensaje de SHA-1 porque 20 no es múltiplo de 8
    for (uint8_t j = 0; j < 4; j++)
    {
      mensajeCANTransmitido.data[j] = sha1Generado[j + 2 * LONGITUD_MENSAJE_CAN];
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash SHA-1 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash SHA-1 ha ido MAL\n", k);
    }
    */
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos hasheados con SHA-1 ha sido: %f us\n", media);

  // Empezamos con el hash SHA-224
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar para que luego el receptor tenga la referencia
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = i;
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    // Realizamos el hash con SHA-224
    mbedtls_sha256_init(&contextoSHA224); // Inicializamos el contexto SHA-224
    mbedtls_sha256_starts_ret(&contextoSHA224, 1);
    mbedtls_sha256_update_ret(&contextoSHA224, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha256_finish_ret(&contextoSHA224, sha224Generado);
    mbedtls_sha256_free(&contextoSHA224); // Limpiamos el contexto SHA-224
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_SHA224 - 1; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = sha224Generado[j + i * LONGITUD_MENSAJE_CAN];
      }
      // Enviar el mensaje CAN
      twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    }
    // Esto es porque no rellenamos entero el último mensaje de SHA-224 porque 28 no es múltiplo de 8
    for (uint8_t j = 0; j < 4; j++)
    {
      mensajeCANTransmitido.data[j] = sha224Generado[j + 3 * LONGITUD_MENSAJE_CAN];
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash SHA-224 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash SHA-224 ha ido MAL\n", k);
    }
    */
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos hasheados con SHA-224 ha sido: %f us\n", media);

  // Empezamos con el hash SHA-256
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el campo de datos a enviar para que luego el receptor tenga la referencia
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = i;
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    // Realizamos el hash con SHA-256
    mbedtls_sha256_init(&contextoSHA256); // Inicializamos el contexto SHA-256
    mbedtls_sha256_starts_ret(&contextoSHA256, 0);
    mbedtls_sha256_update_ret(&contextoSHA256, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha256_finish_ret(&contextoSHA256, sha256Generado);
    mbedtls_sha256_free(&contextoSHA256); // Limpiamos el contexto SHA-256
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_SHA256; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = sha256Generado[j + i * LONGITUD_MENSAJE_CAN];
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
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash SHA-256 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash SHA-256 ha ido MAL\n", k);
    }
    */
  }
  // Mostramos cuánto se ha tardado en cada iteración y la media
  sumatorio = 0;
  for (uint8_t i = 0; i < NUM_REP; i++)
  {
    Serial.printf("%d ", tiempoTranscurrido[i]);
    sumatorio += tiempoTranscurrido[i];
  }
  media = (double)sumatorio / NUM_REP;
  Serial.printf("\nLa media del envío de datos hasheados con SHA-256 ha sido: %f us\n", media);

  // Hemos acabado, mandamos al ESP32 a dormir para que no se ejecute infinitamente
  Serial.println("Fin de la ejecución del ESP32 izquierdo");
  esp_deep_sleep_start();
#endif
#ifdef DER // El código para el ESP32 del lado derecho
  // Iniciamos la fase de recibir mensajes sin cifrar
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    mbedtls_aes_init(&cifradorAES); // Inicializamos el cifrador AES
    mbedtls_aes_setkey_dec(&cifradorAES, claveAES128, LONGITUD_128);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_DECRYPT, mensajeCifradoAES, salidaDescifradoAES);
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes cifrados con AES-128");

  // Iniciamos la fase de recibir mensajes cifrados con AES-256
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    mbedtls_aes_init(&cifradorAES); // Inicializamos el cifrador AES
    mbedtls_aes_setkey_dec(&cifradorAES, claveAES256, LONGITUD_256);
    mbedtls_aes_crypt_ecb(&cifradorAES, MBEDTLS_AES_DECRYPT, mensajeCifradoAES, salidaDescifradoAES);
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes cifrados con AES-256");

  // Iniciamos la fase de recibir mensajes firmados con MD5
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    for (uint8_t i = 0; i < MENSAJES_MD5; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosMD5[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_MD5; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        md5Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosMD5[i].data[j];
      }
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_md5_init(&contextoMD5); // Inicializamos el contexto MD5
    mbedtls_md5_starts_ret(&contextoMD5);
    mbedtls_md5_update_ret(&contextoMD5, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_md5_finish_ret(&contextoMD5, md5Generado);
    mbedtls_md5_free(&contextoMD5); // Limpiamos el contexto MD5
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("md5Generado: ");
      for (uint8_t i = 0; i < LONGITUD_MD5; i++)
      {
        Serial.printf("%x ", md5Generado[i]);
      }
      Serial.println();
      Serial.print("md5Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_MD5; i++)
      {
        Serial.printf("%x ", md5Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(md5Recibido, md5Generado, LONGITUD_MD5) == 0)
    {
      // Rellenamos el campo de datos a enviar con los datos originales
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = datosRecibidos[i];
      }
    }
    else
    {
      // Rellenamos el campo de datos a enviar con un dato como error
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = 0xFF;
      }
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes firmados con MD5");

  // Iniciamos la fase de recibir mensajes firmados con SHA-1
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    for (uint8_t i = 0; i < MENSAJES_SHA1; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosSHA1[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_SHA1 - 1; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        sha1Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA1[i].data[j];
      }
    }
    // Esto es porque no rellenamos entero el último mensaje de SHA-1 porque 20 no es múltiplo de 8
    for (uint8_t j = 0; j < 4; j++)
    {
      sha1Recibido[j + 2 * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA1[2].data[j];
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_sha1_init(&contextoSHA1); // Inicializamos el contexto SHA-1
    mbedtls_sha1_starts_ret(&contextoSHA1);
    mbedtls_sha1_update_ret(&contextoSHA1, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha1_finish_ret(&contextoSHA1, sha1Generado);
    mbedtls_sha1_free(&contextoSHA1); // Limpiamos el contexto SHA-1
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("sha1Generado: ");
      for (uint8_t i = 0; i < LONGITUD_SHA1; i++)
      {
        Serial.printf("%x ", sha1Generado[i]);
      }
      Serial.println();
      Serial.print("sha1Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_SHA1; i++)
      {
        Serial.printf("%x ", sha1Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(sha1Recibido, sha1Generado, LONGITUD_SHA1) == 0)
    {
      // Rellenamos el campo de datos a enviar con los datos originales
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = datosRecibidos[i];
      }
    }
    else
    {
      // Rellenamos el campo de datos a enviar con un dato como error
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = 0xFF;
      }
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-1");

  // Iniciamos la fase de recibir mensajes firmados con SHA-224
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    for (uint8_t i = 0; i < MENSAJES_SHA224; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosSHA224[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_SHA224 - 1; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        sha224Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA224[i].data[j];
      }
    }
    // Esto es porque no rellenamos entero el último mensaje de SHA-224 porque 28 no es múltiplo de 8
    for (uint8_t j = 0; j < 4; j++)
    {
      sha224Recibido[j + 3 * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA224[3].data[j];
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_sha256_init(&contextoSHA224); // Inicializamos el contexto SHA-224
    mbedtls_sha256_starts_ret(&contextoSHA224, 1);
    mbedtls_sha256_update_ret(&contextoSHA224, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha256_finish_ret(&contextoSHA224, sha224Generado);
    mbedtls_sha256_free(&contextoSHA224); // Limpiamos el contexto SHA-224
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("sha224Generado: ");
      for (uint8_t i = 0; i < LONGITUD_SHA224; i++)
      {
        Serial.printf("%x ", sha224Generado[i]);
      }
      Serial.println();
      Serial.print("sha224Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_SHA224; i++)
      {
        Serial.printf("%x ", sha224Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(sha224Recibido, sha224Generado, LONGITUD_SHA224) == 0)
    {
      // Rellenamos el campo de datos a enviar con los datos originales
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = datosRecibidos[i];
      }
    }
    else
    {
      // Rellenamos el campo de datos a enviar con un dato como error
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = 0xFF;
      }
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-224");

  // Iniciamos la fase de recibir mensajes firmados con SHA-256
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
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
    for (uint8_t i = 0; i < MENSAJES_SHA256; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosSHA256[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_SHA256; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        sha256Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA256[i].data[j];
      }
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_sha256_init(&contextoSHA256); // Inicializamos el contexto SHA-256
    mbedtls_sha256_starts_ret(&contextoSHA256, 0);
    mbedtls_sha256_update_ret(&contextoSHA256, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha256_finish_ret(&contextoSHA256, sha256Generado);
    mbedtls_sha256_free(&contextoSHA256); // Limpiamos el contexto SHA-256
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("sha256Generado: ");
      for (uint8_t i = 0; i < LONGITUD_SHA256; i++)
      {
        Serial.printf("%x ", sha256Generado[i]);
      }
      Serial.println();
      Serial.print("sha256Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_SHA256; i++)
      {
        Serial.printf("%x ", sha256Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(sha256Recibido, sha256Generado, LONGITUD_SHA256) == 0)
    {
      // Rellenamos el campo de datos a enviar con los datos originales
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = datosRecibidos[i];
      }
    }
    else
    {
      // Rellenamos el campo de datos a enviar con un dato como error
      for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
      {
        mensajeCANTransmitido.data[i] = 0xFF;
      }
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-256");

  Serial.println("Fin de la ejecución del ESP32 derecho");
#endif
}

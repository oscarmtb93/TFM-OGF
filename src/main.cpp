#include <Arduino.h>

/*
El siguiente sketch es el código para analizar la
latencia en una red CAN cifrada.

v1.0 - ESP32-S3
*/

#define IZQ // Si está definido, el código serña el ESP32 del lado izquierdo
// #define DER // Si está definido, el código serña el ESP32 del lado derecho

// Librería para utilizar el controlador CAN del ESP32
#include <driver/twai.h>
// Librerías para utilizar el cifrado y firma integrados en el ESP32
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h> //Esta librería incluye SHA-224 y SHA-256
#include <mbedtls/sha512.h> //Esta librería incluye SHA-384 y SHA-512
// Librerías para RSA
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

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

// Constantes para el hash SHA-256
const uint8_t LONGITUD_SHA256 = 32;
const uint8_t MENSAJES_SHA256 = 4;

// Constantes para el hash SHA-384
const uint8_t LONGITUD_SHA384 = 48;
const uint8_t MENSAJES_SHA384 = 6;

// Constantes para el hash SHA-512
const uint8_t LONGITUD_SHA512 = 64;
const uint8_t MENSAJES_SHA512 = 8;

// Constantes para el hash RSA-2048
const uint16_t LONGITUD_RSA2048 = 256;
const uint8_t MENSAJES_RSA2048 = 32;

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

// Variables para el hash SHA-384
mbedtls_sha512_context contextoSHA384;
uint8_t sha384Generado[LONGITUD_SHA384];

// Variables para el hash SHA-512
mbedtls_sha512_context contextoSHA512;
uint8_t sha512Generado[LONGITUD_SHA512];

// Variables para el cifrado RSA-2048
mbedtls_pk_context contextoClaveRSA2048;
mbedtls_rsa_context *contextoRSA2048;
uint8_t mensajeCifradoRSA2048[LONGITUD_RSA2048];

// A continuación, variables que sólo aplican en el ESP32 izquierdo
#ifdef IZQ
// Los pines para el transceptor CAN del lado izquierdo
const gpio_num_t txCtrl = GPIO_NUM_45; // Pin TxCAN del CAN
const gpio_num_t rxCtrl = GPIO_NUM_48; // Pin RxCAN del CAN
unsigned long tiempoInicial, tiempoFinal, tiempoTranscurrido[NUM_REP], sumatorio;
double media;
uint8_t entradaCifradoAES[LONGITUD_MENSAJE_AES];
uint8_t entradaCifradoRSA2048[LONGITUD_RSA2048];
// Clave privada RSA-2048
static const char CLAVE_PRIVADA_RSA2048[] PROGMEM =
    R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvkyB7cLjZ3Gjzc/rVSCgSkQZFGv1KGl/KsbaMLYNzXUbFa+f
BhGZG+x9+uhrjPN+YAFm4/9NTDsQrnL1KEaxYyS58S4LzghjTU6iQ3bNU6rSucog
xbDjH+K9YvHyApvkaIRqGNxzHQzlukREKb2/lV5UjnTtg4pSdWWLw7vjEChSXKWd
87oYJyJJOFr+67vh0NgrRDhOERgDKE1e3eGh+G4Fq7enLowiFmkQI5T2GF8CRVMe
Qb5hJe3Cd+e3Rp6LUwFq+8WjMKPZrYSkQxd4PrvGCl+92bZMVmS1IYnz7CFpvnZ2
Z5rbsY5IYJHUuRmKtU+Zsgf6gQCoGHm9/60mSwIDAQABAoIBACzv/C6dOv4Og9Py
KWxsy+09r353D+l/IByF4LhoBVJjOQYh9reEKFfDvOwnPl6GkW0yZ42nmCVMPWA0
nVfpebIj1hTx/q+ko256By9POqVrTV+6L4r/fmLlNDvNToz3KzTTMAq25CgUB5u4
yy/gMwGeyPDrA7twSpCWbi7Gi5QgyMt99uyTMixfzB07BCRjMqn1Ok1VVmNn5QYG
M76VIrPIGCQzHoAZvQZSrbcdwQ1R+z4Z77/a3b2MpRDmaqMR9uPcwszI1ipa46+j
Axkb3lUjyOmr8NaH70rZqY4gXeWgOIfJ8EEX81h+iy7HzAyrPqhOwJrurKi3GLj+
ML3O9KECgYEA8SPP1Xnd9cJnrmXy8v1s3ee/V8qirPImXc/msUP05sj75mXB9hTT
876x24IFFa6pnft5jxFMfd5z+1s2O6JzmCqa+zyBTFthtUmxiIiy2Av4W6eW1izb
qFcayMEzzejd8vMqDyiUgABCLiLp+0NzDd+nHIur/sMFek81t5GS9W0CgYEAygai
h6gTVps3yNtrZf523Q0o5n0Y6MR0ty28d6mGjFLuYo9q1C6O380qu4QPcZk7gL0o
y/eQbjkT+D+jVLXj/IX3TFJ+lV/LZ6PUYuv4HwYQzAYz/N+5QyYc7FBK1WNvbe13
R16mNdZzrPoupqK4wsfOUj7rTsqwc9sENiLxD5cCgYB5neMrOmxsj2C1P2u5i4EF
peUGBQfoi7Q36iviSXDRmJobCEU7tCN1sj6Hg9rGpbGcIQGc20+lx7TdF5KRnwwH
ua0yesCHXys3QHSOdMsmVVsr9qkHWdZq34t9pptXBVQzPNqAjKngqMC3/hneBJWZ
cKwapILZWUiA+EQSUhQ5PQKBgBRs603P3nSpKNCz7n3XZmkfBX2YNEaEZlCG3UEz
8JiLYfKxEVn2gxd5hNKEnZMcrPltJozIsN+UAcLdnEPaR/ymBsS+qnGrx8Lou3Zs
6R8p29Tk46izbeWuGsqBq687aG6yzZZ3qVJUJknc2Y6bcRawYNnL5rqGn6R3Bkv6
6GhtAoGBAMjRhZojRb9+w/tn9/qwOnkjVRCsV40K8RUYMFGbkyHQOrWn7o694VP8
upKlaivW/HYpYMhDU1AYi0BDvb+UkKNGM44q3nCzKyaSDVAQN0apSoVhnhOoKCfZ
lgRO3O1V3YrjI9kPn0sVJ4Stv2tMTTiW7spdVOSgyw4w/RP0L30N
-----END RSA PRIVATE KEY-----)";

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
twai_message_t mensajesCanLeidosSHA384[MENSAJES_SHA384];
uint8_t sha384Recibido[LONGITUD_SHA384];
twai_message_t mensajesCanLeidosSHA512[MENSAJES_SHA512];
uint8_t sha512Recibido[LONGITUD_SHA512];
twai_message_t mensajesCanLeidosRSA2048[MENSAJES_RSA2048];
uint8_t salidaDescifradoRSA2048[LONGITUD_RSA2048];
// Clave pública RSA-2048
static const char CLAVE_PUBLICA_RSA2048[] PROGMEM =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkyB7cLjZ3Gjzc/rVSCg
SkQZFGv1KGl/KsbaMLYNzXUbFa+fBhGZG+x9+uhrjPN+YAFm4/9NTDsQrnL1KEax
YyS58S4LzghjTU6iQ3bNU6rSucogxbDjH+K9YvHyApvkaIRqGNxzHQzlukREKb2/
lV5UjnTtg4pSdWWLw7vjEChSXKWd87oYJyJJOFr+67vh0NgrRDhOERgDKE1e3eGh
+G4Fq7enLowiFmkQI5T2GF8CRVMeQb5hJe3Cd+e3Rp6LUwFq+8WjMKPZrYSkQxd4
PrvGCl+92bZMVmS1IYnz7CFpvnZ2Z5rbsY5IYJHUuRmKtU+Zsgf6gQCoGHm9/60m
SwIDAQAB
-----END PUBLIC KEY-----)";
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos sin cifrar ha sido: %f ms\n", media);

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
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos cifrados con AES-128 ha sido: %f ms\n", media);

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
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos cifrados con AES-256 ha sido: %f ms\n", media);

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
    mbedtls_md5_free(&contextoMD5); // Limpiamos el contexto MD5
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con MD5 ha sido: %f ms\n", media);

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
    mbedtls_sha1_free(&contextoSHA1); // Limpiamos el contexto SHA-1
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con SHA-1 ha sido: %f ms\n", media);

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
    mbedtls_sha256_free(&contextoSHA224); // Limpiamos el contexto SHA-224
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con SHA-224 ha sido: %f ms\n", media);

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
    mbedtls_sha256_free(&contextoSHA256); // Limpiamos el contexto SHA-256
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con SHA-256 ha sido: %f ms\n", media);

  // Empezamos con el hash SHA-384
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
    // Realizamos el hash con SHA-384
    mbedtls_sha512_init(&contextoSHA384); // Inicializamos el contexto SHA-384
    mbedtls_sha512_starts_ret(&contextoSHA384, 1);
    mbedtls_sha512_update_ret(&contextoSHA384, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha512_finish_ret(&contextoSHA384, sha384Generado);
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_SHA384; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = sha384Generado[j + i * LONGITUD_MENSAJE_CAN];
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
    mbedtls_sha512_free(&contextoSHA384); // Limpiamos el contexto SHA-384
    // Tiempo empleado en el proceso
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash SHA-384 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash SHA-384 ha ido MAL\n", k);
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con SHA-384 ha sido: %f ms\n", media);

  // Empezamos con el hash SHA-512
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
    // Realizamos el hash con SHA-512
    mbedtls_sha512_init(&contextoSHA512); // Inicializamos el contexto SHA-512
    mbedtls_sha512_starts_ret(&contextoSHA512, 0);
    mbedtls_sha512_update_ret(&contextoSHA512, mensajeCANTransmitido.data, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha512_finish_ret(&contextoSHA512, sha512Generado);
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_SHA512; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = sha512Generado[j + i * LONGITUD_MENSAJE_CAN];
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
    mbedtls_sha512_free(&contextoSHA512); // Limpiamos el contexto SHA-512
    // Tiempo empleado en el proceso
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    if (mensajeCANLeido.data[0] == 0x00)
    {
      Serial.printf("En la iteración %d el hash SHA-512 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el hash SHA-512 ha ido MAL\n", k);
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con SHA-512 ha sido: %f ms\n", media);

  // Empezamos con el cifrado RSA-2048
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    // Inicio el contador
    tiempoInicial = micros();
    // Rellenamos el dato a ser cifrado con RSA-2048
    memset(entradaCifradoRSA2048, 0, sizeof(LONGITUD_RSA2048)); // Padding ya que la entrada del cifrador es de 256 bytes
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      entradaCifradoRSA2048[i] = i;
    }
    // Realizamos el cifrado con RSA-2048
    mbedtls_pk_init(&contextoClaveRSA2048);                                                                                                // Inicializamos el contexto RSA-2048
    mbedtls_pk_parse_key(&contextoClaveRSA2048, (const unsigned char *)CLAVE_PRIVADA_RSA2048, strlen(CLAVE_PRIVADA_RSA2048) + 1, NULL, 0); // Parsear claves
    contextoRSA2048 = mbedtls_pk_rsa(contextoClaveRSA2048);
    mbedtls_rsa_private(contextoRSA2048, NULL, NULL, entradaCifradoRSA2048, mensajeCifradoRSA2048);
    // Rellenamos los mensajes a enviar
    for (uint8_t i = 0; i < MENSAJES_RSA2048; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCANTransmitido.data[j] = mensajeCifradoRSA2048[j + i * LONGITUD_MENSAJE_CAN];
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
    mbedtls_pk_free(&contextoClaveRSA2048); // Limpiamos el contexto de la clave RSA-2048
    mbedtls_rsa_free(contextoRSA2048);      // Limpiamos el contexto RSA-2048
    // Tiempo empleado en el proceso
    if (k > 0)
    {
      tiempoTranscurrido[k - 1] = tiempoFinal - tiempoInicial;
    }
    /* Estas líneas comentadas fueron de debug para comprobar si el receptor generó bien el hash
    uint8_t original[TWAI_FRAME_MAX_DLC] = {0, 1, 2, 3, 4, 5, 6, 7};
    if (memcmp(mensajeCANLeido.data, original, LONGITUD_MENSAJE_CAN) == 0)
    {
      Serial.printf("En la iteración %d el cifrado RSA-2048 ha ido BIEN\n", k);
    }
    else
    {
      Serial.printf("En la iteración %d el cifrado RSA-2048 ha ido MAL\n", k);
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
  media = (double)sumatorio / (NUM_REP * 1000); // Guardo la media en ms
  Serial.printf("\nLa media del envío de datos hasheados con RSA-2048 ha sido: %f ms\n", media);

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
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
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
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoAES[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    mbedtls_aes_free(&cifradorAES); // Limpiamos el cifrador AES
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
    mbedtls_md5_free(&contextoMD5); // Limpiamos el contexto MD5
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
    mbedtls_sha1_free(&contextoSHA1); // Limpiamos el contexto SHA-1
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
    mbedtls_sha256_free(&contextoSHA224); // Limpiamos el contexto SHA-224
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
    mbedtls_sha256_free(&contextoSHA256); // Limpiamos el contexto SHA-256
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-256");

  // Iniciamos la fase de recibir mensajes firmados con SHA-384
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
    for (uint8_t i = 0; i < MENSAJES_SHA384; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosSHA384[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_SHA384; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        sha384Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA384[i].data[j];
      }
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_sha512_init(&contextoSHA384); // Inicializamos el contexto SHA-384
    mbedtls_sha512_starts_ret(&contextoSHA384, 1);
    mbedtls_sha512_update_ret(&contextoSHA384, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha512_finish_ret(&contextoSHA384, sha384Generado);
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("sha384Generado: ");
      for (uint8_t i = 0; i < LONGITUD_SHA384; i++)
      {
        Serial.printf("%x ", sha384Generado[i]);
      }
      Serial.println();
      Serial.print("sha384Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_SHA384; i++)
      {
        Serial.printf("%x ", sha384Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(sha384Recibido, sha384Generado, LONGITUD_SHA384) == 0)
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
    mbedtls_sha512_free(&contextoSHA384); // Limpiamos el contexto SHA-384
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-384");

  // Iniciamos la fase de recibir mensajes firmados con SHA-512
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
    for (uint8_t i = 0; i < MENSAJES_SHA512; i++)
    {
      // Esperamos a que nos llegue los mensajes con el hash
      while (twai_receive(&mensajesCanLeidosSHA512[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido con el hash
    for (uint8_t i = 0; i < MENSAJES_SHA512; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        sha512Recibido[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosSHA512[i].data[j];
      }
    }
    // Realizamos el hash del mensaje recibido inicialmente
    mbedtls_sha512_init(&contextoSHA512); // Inicializamos el contexto SHA-512
    mbedtls_sha512_starts_ret(&contextoSHA512, 0);
    mbedtls_sha512_update_ret(&contextoSHA512, datosRecibidos, LONGITUD_MENSAJE_CAN); // El último parámetro es la longitud de la entrada, se podría hacer con strlen((char*)mensajeCANTransmitido.data)
    mbedtls_sha512_finish_ret(&contextoSHA512, sha512Generado);
    /* Estas líneas comentadas fueron de debug para comprobar el hash recibido y generado
    if (k == 50)
    {
      Serial.print("sha512Generado: ");
      for (uint8_t i = 0; i < LONGITUD_SHA512; i++)
      {
        Serial.printf("%x ", sha512Generado[i]);
      }
      Serial.println();
      Serial.print("sha512Recibido: ");
      for (uint8_t i = 0; i < LONGITUD_SHA512; i++)
      {
        Serial.printf("%x ", sha512Recibido[i]);
      }
      Serial.println();
    }
    */
    // Ahora comparamos el hash calculado con el hash recibido
    if (memcmp(sha512Recibido, sha512Generado, LONGITUD_SHA512) == 0)
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
    mbedtls_sha512_free(&contextoSHA512); // Limpiamos el contexto SHA-512
  }
  Serial.println("Recibidos todos los mensajes firmados con SHA-512");

  // Iniciamos la fase de recibir mensajes cifrados con RSA-2048
  for (uint8_t k = 0; k <= NUM_REP; k++) // Hacemos NUM_REP+1 porque la primera iteración es unos 30 us más lenta
  {
    for (uint8_t i = 0; i < MENSAJES_RSA2048; i++)
    {
      // Esperamos a que nos llegue los mensajes cifrados
      while (twai_receive(&mensajesCanLeidosRSA2048[i], pdMS_TO_TICKS(0)) != ESP_OK)
      {
      }
    }
    // Leemos el campo de datos recibido
    for (uint8_t i = 0; i < MENSAJES_RSA2048; i++)
    {
      for (uint8_t j = 0; j < LONGITUD_MENSAJE_CAN; j++)
      {
        mensajeCifradoRSA2048[j + i * LONGITUD_MENSAJE_CAN] = mensajesCanLeidosRSA2048[i].data[j];
      }
    }
    // Desciframos los mensajes recibidos
    mbedtls_pk_init(&contextoClaveRSA2048); // Parsear claves
    mbedtls_pk_parse_public_key(&contextoClaveRSA2048, (const unsigned char *)CLAVE_PUBLICA_RSA2048, strlen(CLAVE_PUBLICA_RSA2048) + 1);
    contextoRSA2048 = mbedtls_pk_rsa(contextoClaveRSA2048);
    mbedtls_rsa_public(contextoRSA2048, mensajeCifradoRSA2048, salidaDescifradoRSA2048);
    // Rellenamos el campo de datos a enviar
    for (uint8_t i = 0; i < LONGITUD_MENSAJE_CAN; i++)
    {
      mensajeCANTransmitido.data[i] = salidaDescifradoRSA2048[i];
    }
    // Enviar el mensaje CAN
    twai_transmit(&mensajeCANTransmitido, pdMS_TO_TICKS(1000));
    mbedtls_pk_free(&contextoClaveRSA2048); // Limpiamos el contexto de la clave RSA-2048
    mbedtls_rsa_free(contextoRSA2048);      // Limpiamos el contexto RSA-2048
  }
  Serial.println("Recibidos todos los mensajes cifrados con RSA-2048");

  // Hemos acabado, mandamos al ESP32 a dormir para que no se ejecute infinitamente
  Serial.println("Fin de la ejecución del ESP32 derecho");
  esp_deep_sleep_start();
#endif
}

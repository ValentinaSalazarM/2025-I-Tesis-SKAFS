from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter, Histogram

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/SKAFS-device.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Device")

# Configuración del socket
GATEWAY_HOST = "skafs-gateway"  # Dirección IP del Gateway
GATEWAY_PORT = 5000  # Puerto del Gateway

CA_HOST = "skafs-cloud"  # Dirección de la CA
CA_PORT = 5001  # Puerto de la CA

gateway_socket = None

# Retos fijos para el circuito PUF
C_F0 = None
C_F1 = None

# Parámetros de registro
registration_parameters = {}
iot_identity = int.from_bytes(os.urandom(8), "big")

# Parámetros de autenticación con el Gateway
authentication_parameters = {}

#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################


def IoT_registration():
    """
    Registro del dispositivo IoT utilizando comunicación por sockets.
    """
    global registration_parameters, iot_identity, C_F0, C_F1

    try:
        # Configuración del socket para comunicarse con el CA
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((CA_HOST, CA_PORT))
            logger.info(f"[REG] Conectado al CA en {CA_HOST}:{CA_PORT}")

            # Generación de DPUF challenge y estado
            C_1 = int.from_bytes(os.urandom(8), "big")
            state = int.from_bytes(os.urandom(8), "big")

            # Generación de la identidad del IoT
            logger.info(f"[REG] iot_identity generado: {iot_identity}")

            # Paso 1: Solicitar desafíos al CA
            first_payload = {"operation": "register_device"}
            sock.sendall(json.dumps(first_payload).encode("utf-8"))
            logger.info("[REG] Enviada solicitud de registro al CA.")

            # Recibir desafíos C_F0 y C_F1
            first_response = sock.recv(4096)
            if not first_response:
                logger.error("[REG] No se recibieron desafíos del CA.")
                return
            challenges = json.loads(first_response.decode("utf-8"))
            C_F0 = challenges.get("C_F0")
            C_F1 = challenges.get("C_F1")
            if C_F0 is None or C_F1 is None:
                raise KeyError(
                    "[REG] Faltan desafíos C_F0 o C_F1 en la respuesta del CA."
                )
            logger.info("[REG] Desafíos recibidos del CA.")

            # Cálculo de las funciones FPUF y DPUF
            FPUF_Fixed_F0 = FPUF(C_F0)
            FPUF_Fixed_F1 = FPUF(C_F1)
            DPUF_C1 = DPUF(C_1, state)

            # Paso 2: Enviar datos calculados al CA
            second_payload = {
                "operation": "register_device",
                "iot_identity": iot_identity,
                "DPUF_C1": DPUF_C1,
                "FPUF_Fixed_F0": FPUF_Fixed_F0,
                "FPUF_Fixed_F1": FPUF_Fixed_F1,
            }
            sock.sendall(json.dumps(second_payload).encode("utf-8"))
            logger.info("[REG] Datos enviados al CA.")

            # Paso 3: Recibir respuesta del CA
            data = sock.recv(4096)
            if not data:
                logger.error("[REG] No se recibió respuesta del CA.")
                return
            second_response = json.loads(data.decode("utf-8"))
            CA_K_previous = second_response.get("CA_K_previous")
            T_j = second_response.get("IoT_T_j")
            if CA_K_previous is None or T_j is None:
                raise KeyError("Faltan datos en la respuesta del CA.")
            logger.info("[REG] Respuesta recibida del CA.")

            # Inicialización de los parámetros en el IoT device
            K_previous = CA_K_previous

            # Guardar los parámetros de registro
            registration_parameters = {
                "state": state,
                "C_1": C_1,
                "K_previous": K_previous,
                "T_j": T_j,
            }
            logger.info(
                f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}"
            )

    except KeyError as e:
        logger.error(f"[REG] Clave faltante: {e}")
    except socket.error as e:
        logger.error(f"[REG] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado durante el registro: {e}")


#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################


def mutual_authentication():
    """
    Protocolo de autenticación mutua para el dispositivo IoT.
    Este proceso asegura la autenticidad y sincronización de claves entre el dispositivo IoT y el Gateway.
    """

    global registration_parameters, authentication_parameters

    try:
        # Inicializar el socket persistente
        initialize_socket()

        # Paso 1: Enviar mensaje inicial ("hello") al Gateway
        message = {
            "operation": "mutual_authentication",
            "step": "hello",
            "message": "hello",
        }
        response = send_and_receive_persistent_socket(message)
        logger.info("[AUTH] Mensaje 'hello' enviado al Gateway.")

        # Paso 2: Recibir el token de autenticación del Gateway
        if not all(key in response for key in ["G_r_1"]):
            raise KeyError("Faltan argumentos en la respuesta del Gateway.")
        G_r_1 = response["G_r_1"]
        logger.info(f"[AUTH] Token de autenticación recibido: G_r_1={G_r_1}.")

        # Paso 3: Calcular claves y parámetros cifrados al IoT Gateway
        message, r_3, K_i = IoT_obfuscation_for_R_2_ID(G_r_1)

        ## message = (A_M_1, ID_obfuscated, r_2_obfuscated, K_i_obfuscated, r_3_obfuscated)
        payload = {
            "operation": "mutual_authentication",
            "M_1": message[0],
            "ID*": message[1],
            "r_2*": message[2],
            "K_i*": message[3],
            "r_3*": message[4],
        }
        authentication_parameters["ID*"] = message[1]
        response = send_and_receive_persistent_socket(payload)
        logger.info("[AUTH] Mensaje cifrado enviado al Gateway.")

        if response.get("status") == "failed" or response.get("status") == "error":
            error_message = response.get("message")
            raise PermissionError(
                f"El proceso de autenticación ha sido detenido por el Gateway o por el CA: {error_message}" 
            )

        # Paso 4: Recibir claves y sincronización G_M_2, Sync_IoT_G del Gateway
        message, IoT_K_s, state, IoT_C_1 = compute_next_session_key(
            response["G_M_2"],
            G_r_1,
            r_3,
            K_i,
            registration_parameters["C_1"],
            registration_parameters["state"],
        )

        # Paso 5: Enviar claves obfuscadas para la siguiente sesión
        payload = {"operation": "mutual_authentication", "K_i_next_obfuscated": message}
        response = send_and_receive_persistent_socket(payload)
        logger.info("[AUTH] Claves obfuscadas enviadas al Gateway.")
        if response.get("status") == "failed" or response.get("status") == "error":
            error_message = response.get("message")
            raise PermissionError(
                f"El proceso de autenticación ha sido detenido por el Gateway o por el CA: {error_message}" 
            )

        # Paso 6: Recibir mensaje M_4 del Gateway y actualizar parámetros
        if not all(key in response for key in ["M_4"]):
            raise KeyError("[AUTH] Faltan argumentos en la respuesta del Gateway.")
        IoT_K_previous, IoT_C_1, state = updating_challenge_DPUF_configuration(
            response["M_4"],
            IoT_K_s,
            G_r_1,
            r_3,
            registration_parameters["K_previous"],
            K_i,
            IoT_C_1,
            state,
        )

        # Paso 7: Actualizar los parámetros locales
        registration_parameters.update(
            {
                "K_previous": IoT_K_previous,
                "state": state,
                "C_1": IoT_C_1,
            }
        )
        logger.info("[AUTH] Parámetros del dispositivo IoT actualizados correctamente.")
        logger.info("[AUTH] Autenticación mutua culminada.")
    except PermissionError as e:
        logger.error(f"[AUTH] Error de autenticación: {e}")
    except KeyError as e:
        logger.error(f"[AUTH] Error de datos faltantes en la respuesta: {e}")
    except socket.error as e:
        logger.error(f"[AUTH] Error en la comunicación por socket: {e}")
    except Exception as e:
        logger.error(f"[AUTH] Error inesperado: {e}")
    finally:
        close_socket()


def IoT_obfuscation_for_R_2_ID(G_r_1):
    global iot_identity, registration_parameters
    r_2 = int.from_bytes(os.urandom(8), "big")
    r_3 = int.from_bytes(os.urandom(8), "big")

    C_1 = registration_parameters["C_1"]
    state = registration_parameters["state"]
    K_previous = registration_parameters["K_previous"]
    T_j = registration_parameters["T_j"]

    ID_obfuscated = iot_identity ^ Hash(G_r_1, r_2)
    K_i = DPUF(C_1, state)
    K_i_obfuscated = K_i ^ K_previous
    A_M_1 = Hash(K_i, G_r_1, r_3)
    r_2_obfuscated = FPUF(C_F0) ^ r_2
    r_2_obfuscated = r_2_obfuscated ^ FPUF(C_F1) ^ T_j
    r_3_obfuscated = r_3 ^ K_i

    return (
        (A_M_1, ID_obfuscated, r_2_obfuscated, K_i_obfuscated, r_3_obfuscated),
        r_3,
        K_i,
    )


def compute_next_session_key(data, G_r_1, r_3, K_i, C_1, state):
    global authentication_parameters
    # G_M_2, Sync_G
    G_M_2 = data[0]
    Sync_G = data[1]
    assert G_M_2 == Hash(
        K_i, Sync_G, G_r_1, r_3
    ), "[AUTH] La autenticación del Gateway en el dispositivo IoT falló."
    if Sync_G == -1:
        C_1 = Hash(C_1)
        state = Hash(state)
    K_i = DPUF(C_1, state)
    K_i_next = DPUF(Hash(C_1), Hash(state))
    K_i_next_obfuscated = K_i_next ^ K_i

    K_s_int = Hash(G_r_1, r_3, K_i)
    K_s_int = int(str(K_s_int)[:16])
    K_s_bytes = K_s_int.to_bytes(AES.block_size, "big")

    # Almacenar los parámetros de autenticación
    authentication_parameters["session_key"] = K_s_bytes
    logger.info(f"[AUTH] La llave de sesión en el dispositivo IoT es: {K_s_int}")
    return K_i_next_obfuscated, K_s_int, state, C_1


def updating_challenge_DPUF_configuration(
    M_4, K_s, G_r_1, r_3, K_previous, K_i, C_1, state
):
    assert M_4 == Hash(
        K_s, G_r_1, r_3
    ), "[AUTH] Las llaves de sincronización entre el Gateway y el dispositivo IoT no se han actualizado en este último."
    C_1 = Hash(C_1)
    K_previous = K_i
    state = Hash(state)
    return K_previous, C_1, state


#######################################################
#                 INTERCAMBIAR MENSAJES               #
#######################################################


def send_encrypted_metrics():
    """
    Envía métricas cifradas al Gateway utilizando AES en modo CBC.
    """
    global authentication_parameters
    try:
        while True:
            # Verificar que el dispositivo esté autenticado
            if (
                not authentication_parameters
                or "session_key" not in authentication_parameters
            ):
                logger.error("[METRICS] No hay sesión activa. Autenticación requerida.")
                raise ValueError("El dispositivo no está autenticado con el Gateway.")

            # Generar datos simulados del sensor
            sensor_data = {
                "temperature": round(random.uniform(20.0, 30.0), 2),
                "humidity": round(random.uniform(50, 70), 2),
            }

            # Serializar las métricas a JSON
            metrics_json = json.dumps(sensor_data).encode("utf-8")

            # Generar IV aleatorio para CBC
            iv = Random.new().read(AES.block_size)

            # Obtener la clave de sesión
            K_s_bytes = authentication_parameters.get("session_key")
            if not K_s_bytes:
                raise ValueError("[METRICS] Clave de sesión no encontrada.")

            # Cifrar las métricas con AES en modo CBC
            cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)
            encrypted_metrics = cipher.encrypt(pad(metrics_json, AES.block_size))

            # Construir el mensaje a enviar al Gateway
            payload = {
                "operation": "send_metrics",
                "ID_obfuscated": authentication_parameters.get("ID*"),
                "iv": base64.b64encode(iv).decode("utf-8"),
                "encrypted_metrics": base64.b64encode(encrypted_metrics).decode(
                    "utf-8"
                ),
            }

            # Enviar el mensaje al Gateway mediante sockets
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect((GATEWAY_HOST, GATEWAY_PORT))
                    sock.sendall(json.dumps(payload).encode("utf-8"))
                    logger.info(
                        f"[METRICS] Métricas cifradas enviadas al Gateway: {sensor_data}"
                    )

                    # Recibir respuesta del Gateway
                    response = sock.recv(4096)
                    if response:
                        response_message = json.loads(response.decode("utf-8"))
                        logger.info(
                            f"[METRICS] Respuesta recibida del Gateway: {response_message}"
                        )

                        # Si el dispositivo ha sido revocado, detener envío de métricas
                        if response_message.get("status") == "failed" or response_message.get("status") == "error":
                            raise PermissionError(
                                "Dispositivo no autenticado o revocado por el Gateway. Deteniendo envío de métricas."
                            )
                except socket.error as e:
                    logger.error(f"[METRICS] Error de comunicación con el Gateway: {e}")

            # Esperar antes de enviar la siguiente métrica
            time.sleep(60)

    except PermissionError as e:
        logger.error(f"[METRICS] Error de autenticación: {e}")
    except Exception as e:
        logger.error(f"[METRICS] Error inesperado en el envío de métricas: {e}")


#######################################################
#                      AUXILIARES                     #
#######################################################


def initialize_socket():
    """
    Inicializa un socket persistente para comunicarse con el Gateway.
    """
    global gateway_socket
    if gateway_socket is None:
        try:
            gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            gateway_socket.connect((GATEWAY_HOST, GATEWAY_PORT))
            logger.info(f"Conectado al Gateway en {GATEWAY_HOST}:{GATEWAY_PORT}")
        except socket.error as e:
            logger.error(f"Error al conectar con el Gateway: {e}")
            gateway_socket = None
            raise e


def close_socket():
    """
    Cierra el socket persistente.
    """
    global gateway_socket
    if gateway_socket:
        try:
            gateway_socket.close()
            logger.info("Socket con el Gateway cerrado correctamente.")
        except socket.error as e:
            logger.error(f"Error al cerrar el socket: {e}")
        finally:
            gateway_socket = None


def send_and_receive_persistent_socket(message_dict):
    """
    Enviar un mensaje al Gateway utilizando un socket persistente y recibir la respuesta.
    """
    global gateway_socket
    try:
        if gateway_socket is None:
            initialize_socket()
        encoded_message = {}
        for key in message_dict:
            value = message_dict[key]
            if isinstance(value, bytes):
                encoded_message[key] = base64.b64encode(value).decode(
                    "utf-8"
                )  # Convertir bytes a base64 y luego a str
            else:
                encoded_message[key] = value
        # logger.info(f"send_and_receive_persistent_socket- encoded_message={encoded_message}")
        gateway_socket.sendall(
            json.dumps(encoded_message).encode("utf-8")
        )  # Enviar mensaje

        response = gateway_socket.recv(4096)  # Recibir respuesta
        received_message_dict = json.loads(response.decode("utf-8"))
        decoded_message = {}
        for key, value in received_message_dict.items():
            if isinstance(value, str):  # Solo intentar decodificar cadenas
                try:
                    # Decodificar solo si es válido Base64
                    decoded_message[key] = base64.b64decode(value)
                except (ValueError, binascii.Error):
                    # Si no es Base64, mantener el valor original
                    decoded_message[key] = value
            else:
                # No es cadena, mantener el valor original
                decoded_message[key] = value
        # logger.info(f"send_and_receive_persistent_socket- decoded_response={decoded_message}")
        return decoded_message
    except socket.error as e:
        logger.error(f"Error en la comunicación por socket persistente: {e}")
        gateway_socket = None  # Marcar el socket como no válido
        raise e


if __name__ == "__main__":
    time.sleep(15)
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8012.")
    start_http_server(8012)
    # Realiza el registro y la autenticación mutua
    IoT_registration()
    mutual_authentication()
    # Simula el envío de métricas al Gateway
    send_encrypted_metrics()

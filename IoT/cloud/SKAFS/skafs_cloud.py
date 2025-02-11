from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/SKAFS-cloud.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Cloud")

# Configuración del servidor socket para que acepte conexiones desde otros contenedores
HOST = "0.0.0.0"
PORT = 5001

# Generación de la identidad y la clave a largo plazo
CA_Identity = int.from_bytes(os.urandom(8), "big")
K = int.from_bytes(os.urandom(8), "big")

# Generación de desafíos fija (C_F0, C_F1) simulando PUF
C_F0 = int.from_bytes(os.urandom(8), "big")
C_F1 = int.from_bytes(os.urandom(8), "big")

# Diccionario para almacenar variables por IoT_Identity
registered_devices = {}

# Diccionario para almacenar variables por Gateway_Identity
registered_gateways = {}

# Dispositivo y Gateway que se están autenticando actualmente
current_gateway_identity = None
current_iot_identity = None

#######################################################
#                 INICIAR SERVIDORES                  #
#######################################################


def start_cloud_socket():
    """
    Inicia el servidor socket para manejar conexiones del Gateway y del Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logger.info(f"Servidor Cloud escuchando en {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"Conexión aceptada de {addr}")
            handle_client_connection(client_socket)


def handle_client_connection(client_socket):
    """
    Maneja las conexiones entrantes y redirige a la función adecuada.
    """
    try:
        # Recibir datos del cliente
        data = client_socket.recv(4096)
        if not data:
            logger.error("No se recibieron datos del cliente.")
            return

        # Decodificar el mensaje
        message = decode_message(json.loads(data.decode("utf-8")))
        logger.info(f"Mensaje recibido: {message}")

        # Verificar el tipo de operación
        operation = message.get("operation")
        if not operation:
            raise ValueError("Falta el campo 'operation' en el mensaje recibido.")

        # Redirigir a la función correspondiente
        if operation == "register_gateway":
            handle_gateway_registration(client_socket, message)
        elif operation == "register_device":
            handle_IoT_registration(client_socket, message)
        elif operation == "mutual_authentication":
            handle_mutual_authentication(client_socket, message)
        else:
            raise ValueError(f"Operación desconocida: {operation}")

    except ValueError as e:
        logger.error(f"Error en el mensaje recibido: {e}")
    except Exception as e:
        logger.error(f"Error durante el manejo de la conexión: {e}")
    finally:
        client_socket.close()
        logger.info("Conexión con el cliente cerrada.")


#######################################################
#              REGISTRO DISPOSITIVO IOT               #
#######################################################


def handle_IoT_registration(client_socket, message):
    """
    Manejar el registro del dispositivo IoT.
    """
    global registered_devices

    try:
        client_ip, client_port = client_socket.getpeername()

        logger.info(
            "[REG Dispositivo] Enviando desafíos C_F0 y C_F1 al dispositivo IoT."
        )

        # Enviar los desafíos al dispositivo
        challenges = {"operation": "register_device", "C_F0": C_F0, "C_F1": C_F1}
        client_socket.sendall(json.dumps(encode_message(challenges)).encode("utf-8"))

        # Recibir datos del dispositivo IoT
        data = client_socket.recv(4096)
        if not data:
            logger.error(
                "[REG Dispositivo] No se recibieron datos del dispositivo IoT."
            )
            return

        # Decodificar mensaje
        message = decode_message(json.loads(data.decode("utf-8")))
        logger.info(
            f"[REG Dispositivo] Mensaje recibido del dispositivo IoT: {message}"
        )

        # Validar los datos recibidos
        iot_identity = message.get("iot_identity")
        DPUF_C1 = message.get("DPUF_C1")
        FPUF_Fixed_F0 = message.get("FPUF_Fixed_F0")
        FPUF_Fixed_F1 = message.get("FPUF_Fixed_F1")

        if None in (iot_identity, DPUF_C1, FPUF_Fixed_F0, FPUF_Fixed_F1):
            raise KeyError(
                "Faltan datos en el mensaje recibido para el registro del dispositivo IoT."
            )

        # Verificar si el dispositivo ya está registrado
        if iot_identity in registered_devices:
            logger.warning(
                f"[REG Dispositivo] El dispositivo con ID {iot_identity} ya está registrado."
            )
            raise ValueError("El dispositivo ya está registrado.")

        logger.info(
            f"[REG Dispositivo] Recibidos datos del dispositivo IoT: iot_identity={iot_identity}, DPUF_C1={DPUF_C1}, FPUF_Fixed_F0={FPUF_Fixed_F0}, FPUF_Fixed_F1={FPUF_Fixed_F1}"
        )

        # Cálculo de IoT_T_j
        IoT_T_j = K ^ FPUF_Fixed_F0 ^ FPUF_Fixed_F1

        # Generar variables CA_K específicas para este dispositivo
        CA_K_before_previous = int.from_bytes(os.urandom(8), "big")
        CA_K_previous = int.from_bytes(os.urandom(8), "big")
        CA_K_current = DPUF_C1  # Actualización con DPUF_C1 recibido

        # Registrar el dispositivo

        device_keys = {
            "IP": client_ip,
            "IoT_T_j": IoT_T_j,
            "CA_K_before_previous": CA_K_before_previous,
            "CA_K_previous": CA_K_previous,
            "CA_K_current": CA_K_current,
        }

        registered_devices[iot_identity] = device_keys

        logger.info(
            f"[REG Dispositivo] Dispositivo IoT con ID {iot_identity} registrado exitosamente. Claves asociadas: {device_keys}"
        )

        # Preparar y enviar la respuesta al dispositivo IoT
        response = {
            "operation": "register",
            "CA_K_previous": CA_K_previous,
            "IoT_T_j": IoT_T_j,
        }
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode("utf-8"))
        logger.info("[REG Dispositivo] Respuesta enviada al dispositivo IoT.")

    except KeyError as e:
        logger.error(f"Clave faltante en los datos del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except ValueError as e:
        logger.error(f"Error en el registro del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del dispositivo IoT: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        logger.info("[REG Dispositivo] Conexión con el dispositivo IoT cerrada.")

#######################################################
#                   REGISTRO GATEWAY                  #
#######################################################


def handle_gateway_registration(client_socket, message):
    """
    Manejar el registro del Gateway.
    """
    global registered_gateways
    try:
        client_ip, client_port = client_socket.getpeername()

        gateway_identity = message.get("gateway_identity")
        if not gateway_identity:
            raise KeyError("Falta gateway_identity en el mensaje recibido.")

        gateway_identity = message.get("gateway_identity")

        # Generar parámetros específicos para el gateway
        CA_MK_G_CA = int.from_bytes(os.urandom(8), "big")
        CA_Sync_K_G_CA_previous = int.from_bytes(os.urandom(8), "big")
        CA_r_1_previous = int.from_bytes(os.urandom(8), "big")
        CA_Sync_K_G_CA = Hash(CA_Sync_K_G_CA_previous, CA_r_1_previous)

        # Verificar si el gateway ya está registrado
        if gateway_identity in registered_gateways:
            logger.warning(
                f"[REG Gateway] El gateway con ID {gateway_identity} ya se encuentra registrado."
            )
            raise ValueError("El gateway ya se encuentra registrado.")

        # Registrar el gateway
        gateway_keys = {
            "IP": client_ip,
            "CA_MK_G_CA": CA_MK_G_CA,
            "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
            "CA_r_1_previous": CA_r_1_previous,
            "CA_Sync_K_G_CA": CA_Sync_K_G_CA,
        }

        registered_gateways[gateway_identity] = gateway_keys

        logger.info(
            f"[REG Gateway] Gateway con ID {gateway_identity} registrado exitosamente. Claves asociadas: {gateway_keys}"
        )

        # Preparar y enviar la respuesta al Gateway
        response = {
            "operation": "register",
            "CA_Identity": CA_Identity,
            "CA_MK_G_CA": CA_MK_G_CA,
            "CA_Sync_K_G_CA_previous": CA_Sync_K_G_CA_previous,
            "CA_r_1_previous": CA_r_1_previous,
        }

        # Codificar y enviar respuesta al Gateway
        encoded_response = encode_message(response)
        client_socket.sendall(json.dumps(encoded_response).encode("utf-8"))
        logger.info(f"Gateway registrado con éxito: {gateway_identity}")

    except KeyError as e:
        logger.error(f"Clave faltante en los datos del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except ValueError as e:
        logger.error(f"Error en el registro del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error inesperado durante el registro del Gateway: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        logger.info("[REG Gateway] Conexión con el Gateway cerrada.")


#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################


def handle_mutual_authentication(gateway_socket, decoded_message):
    """
    Autenticación mutua del Gateway con la CA.
    """
    global registered_gateways, registered_devices, current_gateway_identity, current_iot_identity
    try:
        socket_gateway_ip, socket_port = gateway_socket.getpeername()
        socket_device_ip = decoded_message.get("device_ip")

        # Encontrar el disposititivo y el Gateway que se están autenticando
        current_gateway_identity = None
        for gateway_identity, gateway_data in registered_gateways.items():
            if gateway_data.get("IP") == socket_gateway_ip:
                current_gateway_identity = gateway_identity

        current_iot_identity = None
        for iot_identity, device_data in registered_devices.items():
            if device_data.get("IP") == socket_device_ip:
                current_iot_identity = iot_identity

        if not current_iot_identity or not current_gateway_identity:
            logger.error("[AUTH] No hay sesión activa. Autenticación requerida.")
            raise PermissionError(
                "El Gateway no está autenticado con el CA, se restringe el acceso."
            )

        logger.info(
            f"Actualmente se está autenticando el Gateway {current_gateway_identity} y el Device {current_iot_identity}"
        )

        # Paso 1: Recibir datos del Gateway
        ReturnData = retrieve_R_2_ID(decoded_message)
        message = ReturnData[:6]
        HashResult = ReturnData[6]
        G_r_1_Decrypted = ReturnData[7]
        iv = ReturnData[8]

        # Paso 2: Enviar el mensaje (CA_sigma_3, Epison_2_1, ..., D_sync_CA_G) al Gateway
        response_payload = {
            "operation": "mutual_authentication",
            "CA_sigma_3": message[0],
            "Epison_2_1": message[1],
            "Epison_2_2": message[2],
            "Epison_2_3": message[3],
            "Epison_2_4": message[4],
            "D_sync_CA_G": message[5],
        }
        encoded_message = encode_message(response_payload)
        gateway_socket.sendall(json.dumps(encoded_message).encode("utf-8"))
        logger.info("[AUTH] Enviado mensaje de sincronización al Gateway.")

        # Paso 3: Recibir Epison_3_1 del Gateway
        data = gateway_socket.recv(4096)
        received_message = json.loads(data.decode("utf-8"))
        decoded_message = decode_message(received_message)
        if "Epison_3_1" not in decoded_message:
            raise KeyError("Falta Epison_3_1 en la solicitud del Gateway.")
        Epison_3_1 = decoded_message["Epison_3_1"]
        logger.info("[AUTH] Recibido Epison_3_1 del Gateway.")

        # Actualizar las claves de sincronización
        CA_K_previous = registered_devices[current_iot_identity]["CA_K_previous"]
        CA_K_current = registered_devices[current_iot_identity]["CA_K_current"]

        CA_Sync_K_G_CA = registered_gateways[current_gateway_identity]["CA_Sync_K_G_CA"]

        M_3 = updating_synchronization_keys(
            Epison_3_1,
            HashResult,
            iv,
            G_r_1_Decrypted,
            CA_K_previous,
            CA_K_current,
            CA_Sync_K_G_CA,
        )
        logger.info("[AUTH] Claves de sincronización actualizadas correctamente.")

        # Paso 4: Enviar M_3 al Gateway
        encoded_message = encode_message(
            {"operation": "mutual_authentication", "M_3": M_3}
        )
        gateway_socket.sendall(json.dumps(encoded_message).encode("utf-8"))
        logger.info("[AUTH] Mensaje M_3 enviado al Gateway.")
        logger.info("[AUTH] Autenticación mutua culminada.")
        
        current_gateway_identity = None
        current_iot_identity = None
    except PermissionError as e:
        logger.error(f"Error de autenticación: {e}")
        response = {"status": "failed", "message": str(e)}
        gateway_socket.sendall(json.dumps(response).encode("utf-8"))
    except KeyError as e:
        logger.error(f"Clave faltante en los datos recibidos: {e}")
        response = {"status": "error", "message": str(e)}
        gateway_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error durante la autenticación mutua: {e}")
        response = {"status": "error", "message": str(e)}
        gateway_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        gateway_socket.close()
        logger.info("[AUTH] Conexión con el Gateway cerrada.")


def retrieve_R_2_ID(data):
    global registered_gateways, registered_devices, current_gateway_identity, current_iot_identity
    G_nonce = data.get("G_nonce")
    G_sigma_1 = data.get("G_sigma_1")
    G_sigma_2 = data.get("G_sigma_2")
    Epison_1_1 = data.get("Epison_1_1")
    Epison_1_2 = data.get("Epison_1_2")
    Epison_1_3 = data.get("Epison_1_3")
    Epison_1_4 = data.get("Epison_1_4")
    Epison_1_5 = data.get("Epison_1_5")
    iv = data.get("iv")

    # Datos del registro del gateway

    CA_MK_G_CA = registered_gateways[current_gateway_identity]["CA_MK_G_CA"]
    CA_Sync_K_G_CA_previous = registered_gateways[current_gateway_identity][
        "CA_Sync_K_G_CA_previous"
    ]
    CA_Sync_K_G_CA = registered_gateways[current_gateway_identity]["CA_Sync_K_G_CA"]

    h1 = hashlib.new("sha256")
    h1.update(CA_Sync_K_G_CA.to_bytes(32, "big"))
    HashResult = bytes(h1.hexdigest(), "utf-8")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_ID_Decrypted = int.from_bytes(DEC.decrypt(Epison_1_1), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_r_2_Decrypted = int.from_bytes(DEC.decrypt(Epison_1_2), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_r_3_Decrypted = int.from_bytes(DEC.decrypt(Epison_1_3), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_r_1_Decrypted = int.from_bytes(DEC.decrypt(Epison_1_4), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    IoT_K_i_Decrypted = int.from_bytes(DEC.decrypt(Epison_1_5), "big")

    assert G_sigma_1 == Hash(
        CA_MK_G_CA, current_gateway_identity, G_nonce
    ), "The authentication of the Gateway by the CA has failed"

    if G_sigma_2 == Hash(CA_Sync_K_G_CA_previous, current_gateway_identity, G_nonce):
        D_sync_CA_G = 1  # it was -1
    elif G_sigma_2 == Hash(CA_Sync_K_G_CA, current_gateway_identity, G_nonce):
        D_sync_CA_G = 0
    CA_r_2_retrieved = IoT_r_2_Decrypted ^ K

    CA_IoT_ID_retrieved = IoT_ID_Decrypted ^ Hash(G_r_1_Decrypted, CA_r_2_retrieved)
    CA_sigma_3 = Hash(CA_MK_G_CA, CA_Identity, D_sync_CA_G, G_nonce + 1)

    # Datos del registro del IoT
    CA_K_before_previous = registered_devices[current_iot_identity][
        "CA_K_before_previous"
    ]
    CA_K_previous = registered_devices[current_iot_identity]["CA_K_previous"]
    CA_K_current = registered_devices[current_iot_identity]["CA_K_current"]

    # Datos del registro del Gateway
    CA_r_1_previous = registered_gateways[current_gateway_identity]["CA_r_1_previous"]

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_1 = ENC.encrypt(CA_K_before_previous.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_2 = ENC.encrypt(CA_K_previous.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_3 = ENC.encrypt(CA_K_current.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_2_4 = ENC.encrypt(CA_r_1_previous.to_bytes(32, "big"))

    return (
        CA_sigma_3,
        Epison_2_1,
        Epison_2_2,
        Epison_2_3,
        Epison_2_4,
        D_sync_CA_G,
        HashResult,
        G_r_1_Decrypted,
        iv,
    )


def updating_synchronization_keys(
    Epison_3_1,
    HashResult,
    iv,
    G_r_1_Decrypted,
    CA_K_previous,
    CA_K_current,
    CA_Sync_K_G_CA,
):
    global registered_gateways, registered_devices
    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    CA_IoT_K_i_next = int.from_bytes(DEC.decrypt(Epison_3_1), "big")

    # Actualizar llaves de sincronización del dispositivo

    registered_devices[current_iot_identity]["CA_K_before_previous"] = CA_K_previous
    registered_devices[current_iot_identity]["CA_K_previous"] = CA_K_current
    registered_devices[current_iot_identity]["CA_K_current"] = CA_IoT_K_i_next
    registered_gateways[current_gateway_identity]["CA_r_1_previous"] = G_r_1_Decrypted

    CA_K_before_previous = registered_devices[current_iot_identity][
        "CA_K_before_previous"
    ]
    CA_K_previous = registered_devices[current_iot_identity]["CA_K_previous"]
    CA_K_current = registered_devices[current_iot_identity]["CA_K_current"]

    # Actualizar llaves de sincronización del gateway y el CA
    CA_Sync_K_G_CA_previous = CA_Sync_K_G_CA
    CA_Sync_K_G_CA = Hash(CA_Sync_K_G_CA, G_r_1_Decrypted)
    M_3 = Hash(CA_K_before_previous, CA_K_previous, CA_K_current, CA_Sync_K_G_CA)
    registered_gateways[current_gateway_identity][
        "CA_Sync_K_G_CA_previous"
    ] = CA_Sync_K_G_CA_previous
    return M_3


#######################################################
#                      AUXILIARES                     #
#######################################################


def encode_message(message_dict):
    """
    Convierte un mensaje en un formato JSON serializable.
    Los objetos de tipo bytes se codifican en base64.
    """
    encoded_message = {}

    # Recorre y codifica cada elemento del mensaje
    for key in message_dict:
        value = message_dict[key]
        if isinstance(value, bytes):
            encoded_message[key] = base64.b64encode(value).decode(
                "utf-8"
            )  # Convertir bytes a base64 y luego a str
        else:
            encoded_message[key] = value
    return encoded_message


def decode_message(encoded_message_dict):
    """
    Decodifica un mensaje que contiene valores codificados en Base64.
    """
    decoded_message = {}
    for key, value in encoded_message_dict.items():
        if isinstance(value, str):  # Solo intentar decodificar cadenas
            try:
                # Intentar decodificar si es válido Base64
                if base64.b64encode(base64.b64decode(value)).decode("utf-8") == value:
                    decoded_message[key] = base64.b64decode(value)
                else:
                    decoded_message[key] = value
            except (ValueError, binascii.Error):
                # Si no es Base64, mantener el valor original
                decoded_message[key] = value
        else:
            # No es cadena, mantener el valor original
            decoded_message[key] = value
    return decoded_message


if __name__ == "__main__":
    time.sleep(5)
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8011.")
    start_http_server(8011, addr="0.0.0.0")
    # Inicia el socket
    start_cloud_socket()

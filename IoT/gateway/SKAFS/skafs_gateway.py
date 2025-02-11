from common.cripto_primitivas import *

# Métricas
from prometheus_client import start_http_server, Counter

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/SKAFS-gateway.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Gateway")

# Configuración del servidor socket
HOST = "0.0.0.0"  # Dirección IP del Gateway
PORT = 5000  # Puerto del Gateway

# Configuración del servidor socket de comunicación para registro con el Cloud
CA_HOST = "skafs-cloud"  # Dirección de la CA
CA_PORT = 5001  # Puerto de la CA
cloud_socket = None

# Identidad única de la CA
CA_Identity = None

# Parámetros de registro
registration_parameters = {}
gateway_identity = int.from_bytes(os.urandom(8), "big")

# Dispositivos IoT autenticados
authenticated_devices = {}


#######################################################
#               SERVIDOR SOCKET GATEWAY               #
#######################################################


def start_gateway_socket():
    """
    Inicia el servidor socket para manejar conexiones del IoT Device.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logger.info(f"Socket Gateway escuchando en {HOST}:{PORT}")

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
        message = json.loads(data.decode("utf-8"))
        logger.info(f"Mensaje recibido: {message}")

        # Verificar el tipo de operación
        operation = message.get("operation")
        if not operation:
            raise ValueError("Falta el campo 'operation' en el mensaje recibido.")

        # Redirigir a la función correspondiente
        if operation == "mutual_authentication":
            handle_mutual_authentication(client_socket, message)
        elif operation == "send_metrics":
            handle_send_metrics(client_socket, message)
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
#                   REGISTRO GATEWAY                  #
#######################################################


def gateway_registration():
    global registration_parameters, CA_Identity, gateway_identity

    try:
        # Inicializar el socket con el CA
        initialize_socket()

        # Paso 1: Generar y enviar ID del gateway
        logger.info(f"[REG] Gateway_Identity: {gateway_identity}")

        # Crear el mensaje a enviar
        first_payload = {
            "operation": "register_gateway",
            "gateway_identity": gateway_identity,
        }
        logger.info("[REG] Enviando Gateway_Identity al CA.")

        # Enviar el mensaje y esperar respuesta
        first_response = send_and_receive_persistent_socket(first_payload)
        logger.info("[REG] Respuesta recibida del CA.")

        # Paso 2: Procesar respuesta del CA
        CA_Identity = first_response.get("CA_Identity")
        CA_MK_G_CA = first_response.get("CA_MK_G_CA")
        CA_Sync_K_G_CA_previous = first_response.get("CA_Sync_K_G_CA_previous")
        CA_r_1_previous = first_response.get("CA_r_1_previous")

        if None in (CA_Identity, CA_MK_G_CA, CA_Sync_K_G_CA_previous, CA_r_1_previous):
            raise ValueError("Datos faltantes en la respuesta del CA.")

        logger.info("[REG] Parámetros recibidos del CA para el Gateway.")

        # Calcular claves derivadas en el Gateway
        G_MK_G_CA = CA_MK_G_CA
        G_Sync_K_G_CA_previous = CA_Sync_K_G_CA_previous
        G_r_1_previous = CA_r_1_previous
        G_Sync_K_G_CA = Hash(G_Sync_K_G_CA_previous, G_r_1_previous)
        logger.info(f"[REG] Claves derivadas calculadas: G_Sync_K_G_CA={G_Sync_K_G_CA}")

        # Paso 3: Guardar los parámetros en la configuración del Gateway
        registration_parameters = {
            "G_MK_G_CA": G_MK_G_CA,
            "G_Sync_K_G_CA_previous": G_Sync_K_G_CA_previous,
            "G_r_1_previous": G_r_1_previous,
            "G_Sync_K_G_CA": G_Sync_K_G_CA,
            "Sync_IoT_G": 0,
        }
        logger.info(
            f"[REG] Registro completado exitosamente con los siguientes parámetros: {registration_parameters}"
        )

    except socket.error as e:
        logger.error(f"[REG] Error de comunicación con el CA: {e}")
    except ValueError as e:
        logger.error(f"[REG] Error en la respuesta del CA: {e}")
    except Exception as e:
        logger.error(f"[REG] Error inesperado: {e}")
    finally:
        close_socket()
        logger.info("[REG] Conexión con el CA cerrada.")


#######################################################
#                 AUTENTICACIÓN MUTUA                 #
#######################################################


def handle_mutual_authentication(client_socket, message):
    """
    Maneja la conexión de un cliente (IoT Device) y ejecuta el protocolo de autenticación mutua con el CA.
    """
    global registration_parameters, authenticated_devices
    try:
        device_ip, device_port = client_socket.getpeername()

        # Paso 1: Recibir mensaje "hello" del dispositivo IoT
        if message.get("step") != "hello":
            raise KeyError("Paso incorrecto recibido del dispositivo.")

        # Paso 2: Generar r_1 y enviarlo al dispositivo IoT
        G_r_1 = int.from_bytes(os.urandom(8), "big")
        payload = {"operation": "mutual_authentication", "G_r_1": G_r_1}
        client_socket.sendall(json.dumps(payload).encode("utf-8"))
        logger.info(f"[AUTH] r_1 generado y enviado al dispositivo IoT: {G_r_1}")

        # Paso 3: Recibir M_1, ID*, r_2*, K_i*, r_3* del dispositivo IoT
        IoT_M1 = json.loads(client_socket.recv(4096).decode("utf-8"))
        if not all(key in IoT_M1 for key in ["M_1", "ID*", "r_2*", "K_i*", "r_3*"]):
            raise KeyError(
                "[AUTH] Faltan argumentos en la respuesta del dispositivo IoT."
            )
        logger.info(f"[AUTH] Datos recibidos del IoT Device: {IoT_M1}")

        # Paso 4: Generar parámetros de autenticación y enviarlos a la CA
        G_nonce = int.from_bytes(os.urandom(8), "big")

        logger.info(f"[AUTH] registration_parameters: {registration_parameters}")

        G_MK_G_CA = registration_parameters.get("G_MK_G_CA")
        G_Sync_K_G_CA = registration_parameters.get("G_Sync_K_G_CA")
        return_data = generate_sigma1_sigma2_epison1(
            G_nonce, G_MK_G_CA, G_Sync_K_G_CA, G_r_1, IoT_M1
        )

        iv = return_data[8]
        HashResult = return_data[9]
        message = return_data[:9]
        payload = {
            "operation": "mutual_authentication",
            "device_ip": device_ip,
            "G_nonce": message[0],
            "G_sigma_1": message[1],
            "G_sigma_2": message[2],
            "Epison_1_1": message[3],
            "Epison_1_2": message[4],
            "Epison_1_3": message[5],
            "Epison_1_4": message[6],
            "Epison_1_5": message[7],
            "iv": iv,
        }

        ca_response = send_and_receive_persistent_socket(payload)

        if (
            ca_response.get("status") == "failed"
            or ca_response.get("status") == "error"
        ):
            raise PermissionError(
                "El proceso de autenticación ha sido detenido por el CA."
            )
        logger.info("[AUTH] Parámetros enviados a la CA para autenticación mutua.")

        # Paso 5: Recibir respuesta de la CA
        if not all(
            key in ca_response
            for key in [
                "CA_sigma_3",
                "Epison_2_1",
                "Epison_2_2",
                "Epison_2_3",
                "Epison_2_4",
                "D_sync_CA_G",
            ]
        ):
            raise KeyError("[AUTH] Faltan argumentos en la respuesta de la CA.")
        CA_sigma_3 = ca_response.get("CA_sigma_3")
        Epison_2_1 = ca_response.get("Epison_2_1")
        Epison_2_2 = ca_response.get("Epison_2_2")
        Epison_2_3 = ca_response.get("Epison_2_3")
        Epison_2_4 = ca_response.get("Epison_2_4")
        D_sync_CA_G = ca_response.get("D_sync_CA_G")
        logger.info("[AUTH] Claves y parámetros de sincronización recibidos de la CA.")

        # Paso 6: Enviar G_M_2 y Sync_IoT_G al dispositivo IoT
        return_data = checking_synchronization_bet_gateway_IoT(
            [CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G],
            G_nonce,
            IoT_M1,
            G_r_1,
            iv,
            HashResult,
        )
        # message=G_M_2, Sync_IoT_G,
        message = return_data[:2]
        G_K_a = return_data[2]
        G_K_previous = return_data[3]
        G_K_current = return_data[4]
        G_r_3 = return_data[5]

        payload = {"operation": "mutual_authentication", "G_M_2": message}
        client_socket.sendall(json.dumps(payload).encode("utf-8"))
        logger.info("[AUTH] Claves de sincronización enviadas al dispositivo IoT.")

        # Paso 7: Recibir la K_i ofuscada del IoT
        data = json.loads(client_socket.recv(4096).decode("utf-8"))
        if "K_i_next_obfuscated" not in data:
            raise KeyError(
                "[AUTH] Falta K_i_next_obfuscated en la respuesta del dispositivo IoT."
            )

        return_data = getting_encrypting_next_session_key(
            data.get("K_i_next_obfuscated"), iv, HashResult, G_K_a
        )
        Epison_3_1 = return_data[0]
        G_IoT_K_i_next = return_data[1]
        logger.info("[AUTH] Recibido IoT_K_i_next_obfuscated del dispositivo IoT.")

        # Paso 8: Enviar Epison_3_1 a la CA
        payload = {"operation": "mutual_authentication", "Epison_3_1": Epison_3_1}
        ca_response = send_and_receive_persistent_socket(payload)
        logger.info(f"[AUTH] Epison_3_1 enviado a la CA.")

        if (
            ca_response.get("status") == "failed"
            or ca_response.get("status") == "error"
        ):
            raise PermissionError(
                "El proceso de autenticación ha sido detenido por el CA."
            )

        # Paso 9: Recibir M_3 de la CA
        if "M_3" not in ca_response:
            raise KeyError("Falta M_3 en la respuesta de la CA.")
        CA_M3 = ca_response.get("M_3")
        logger.info("[AUTH] Recibido M_3 de la CA.")

        # Paso 10: Enviar M_4 al dispositivo IoT
        K_s_int, M_4 = updating_synchronization_keys(
            CA_M3,
            G_r_1,
            G_r_3,
            G_K_previous,
            G_K_current,
            G_IoT_K_i_next,
            G_Sync_K_G_CA,
        )
        K_s_int = int(str(K_s_int)[:16])
        K_s_bytes = K_s_int.to_bytes(AES.block_size, "big")

        unique_identifier = IoT_M1.get("ID*")
        authenticated_devices[unique_identifier] = {"session_key": K_s_bytes}

        client_socket.sendall(
            json.dumps({"operation": "mutual_authentication", "M_4": M_4}).encode(
                "utf-8"
            )
        )
        logger.info("[AUTH] Mensaje M_4 enviado al dispositivo IoT.")
        logger.info(f"[AUTH] Autenticación mutua culminada.")

    except PermissionError as e:
        logger.error(f"[AUTH] Error de autenticación: {e}")
        response = {"status": "failed", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except KeyError as e:
        logger.error(f"[AUTH] Clave faltante en los datos recibidos: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"[AUTH] Error durante la autenticación mutua: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    finally:
        client_socket.close()
        close_socket()
        logger.info("[AUTH] Conexión con el CA cerrada.")


def generate_sigma1_sigma2_epison1(G_nonce, G_MK_G_CA, G_Sync_K_G_CA, G_r_1, IoT_M1):
    global gateway_identity
    G_sigma_1 = Hash(G_MK_G_CA, gateway_identity, G_nonce)
    G_sigma_2 = Hash(G_Sync_K_G_CA, gateway_identity, G_nonce)

    iv = Random.new().read(AES.block_size)
    h = hashlib.new("sha256")
    h.update(G_Sync_K_G_CA.to_bytes(32, "big"))
    HashResult = bytes(h.hexdigest(), "utf-8")

    IoT_ID_obfuscated = IoT_M1.get("ID*")
    IoT_r_2_obfuscated = IoT_M1.get("r_2*")
    IoT_r_3_obfuscated = IoT_M1.get("r_3*")
    IoT_K_i_obfuscated = IoT_M1.get("K_i*")

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_1 = ENC.encrypt(IoT_ID_obfuscated.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_2 = ENC.encrypt(IoT_r_2_obfuscated.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_3 = ENC.encrypt(IoT_r_3_obfuscated.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_4 = ENC.encrypt(G_r_1.to_bytes(32, "big"))

    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_1_5 = ENC.encrypt(IoT_K_i_obfuscated.to_bytes(32, "big"))

    return (
        G_nonce,
        G_sigma_1,
        G_sigma_2,
        Epison_1_1,
        Epison_1_2,
        Epison_1_3,
        Epison_1_4,
        Epison_1_5,
        iv,
        HashResult,
    )


def checking_synchronization_bet_gateway_IoT(
    data, G_nonce, IoT_M_1, G_r_1, iv, HashResult
):
    CA_sigma_3 = data[0]
    Epison_2_1 = data[1]
    Epison_2_2 = data[2]
    Epison_2_3 = data[3]
    Epison_2_4 = data[4]
    D_sync_CA_G = data[5]

    IoT_K_i_obfuscated = IoT_M_1.get("K_i*")
    IoT_A_M_1 = IoT_M_1.get("M_1")
    IoT_r_3_obfuscated = IoT_M_1.get("r_3*")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_before_previous = int.from_bytes(DEC.decrypt(Epison_2_1), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_previous = int.from_bytes(DEC.decrypt(Epison_2_2), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_K_current = int.from_bytes(DEC.decrypt(Epison_2_3), "big")

    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    G_r_1_previous = int.from_bytes(DEC.decrypt(Epison_2_4), "big")

    if D_sync_CA_G == -1:
        registration_parameters["G_Sync_K_G_CA"] = Hash(
            G_Sync_K_G_CA_previous, G_r_1_previous
        )

    G_Sync_K_G_CA_previous = registration_parameters["G_Sync_K_G_CA_previous"]
    G_MK_G_CA = registration_parameters["G_MK_G_CA"]
    assert CA_sigma_3 == Hash(
        G_MK_G_CA, CA_Identity, D_sync_CA_G, G_nonce + 1
    ), "La autenticación del CA en el lado del Gateway falló."

    if IoT_K_i_obfuscated ^ G_K_previous == G_K_current:
        Sync_IoT_G = 0
        G_K_a = G_K_current
        G_r_3 = IoT_r_3_obfuscated ^ G_K_current
        assert IoT_A_M_1 == Hash(
            G_K_current, G_r_1, G_r_3
        ), "El K actual (K_c) no ha sido usado en el primer mensaje de autenticación."
    elif IoT_K_i_obfuscated ^ G_K_before_previous == G_K_previous:
        Sync_IoT_G = -1
        G_K_a = G_K_previous
        G_r_3 = IoT_r_3_obfuscated ^ G_K_previous
        assert IoT_A_M_1 == Hash(
            G_K_previous, G_r_1, G_r_3
        ), "El K anterior (K_p) no ha sido usado en la generación del mensaje de autenticación."
    else:
        logger.error(
            "No coinciden las llaves de sincronización anteriores ni actuales."
        )

    G_M_2 = Hash(G_K_a, Sync_IoT_G, G_r_1, G_r_3)
    registration_parameters["Sync_IoT_G"] = Sync_IoT_G

    return G_M_2, Sync_IoT_G, G_K_a, G_K_previous, G_K_current, G_r_3


def getting_encrypting_next_session_key(IoT_K_i_next_obfuscated, iv, HashResult, G_K_a):
    G_IoT_K_i_next = IoT_K_i_next_obfuscated ^ G_K_a
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_3_1 = ENC.encrypt(G_IoT_K_i_next.to_bytes(32, "big"))

    return Epison_3_1, G_IoT_K_i_next


def updating_synchronization_keys(
    CA_M3,
    G_r_1,
    IoT_r_3,
    G_K_previous,
    G_K_current,
    G_IoT_K_i_next,
    G_Sync_K_G_CA,
):

    G_K_s = Hash(G_r_1, IoT_r_3, G_K_current)
    logger.info(f"[AUTH] La llave de sesión en el Gateway es: {G_K_s}")

    # Actualizar las llaves de sincronización
    G_K_before_previous = G_K_previous
    G_K_previous = G_K_current
    G_K_current = G_IoT_K_i_next
    registration_parameters["G_r_1_previous"] = G_r_1

    # Actualizar las llaves de sincronización entre el CA y el Gateay
    registration_parameters["G_Sync_K_G_CA_previous"] = G_Sync_K_G_CA
    G_Sync_K_G_CA = Hash(G_Sync_K_G_CA, G_r_1)

    assert CA_M3 == Hash(
        G_K_before_previous, G_K_previous, G_K_current, G_Sync_K_G_CA
    ), "[AUTH] Las llaves de sincronización entre el CA y el Gateway no se han actualizado en este último."
    M_4 = Hash(G_K_s, G_r_1, IoT_r_3)

    return G_K_s, M_4


#######################################################
#                 INTERCAMBIAR MENSAJES               #
#######################################################


def handle_send_metrics(client_socket, message):
    """
    Manejar el mensaje 'send_metrics' enviado por el dispositivo IoT.

    Args:
        client_socket: El socket del cliente IoT.
        message (dict): Mensaje recibido del dispositivo IoT.
    """
    try:
        # Extraer los campos necesarios del mensaje
        authentication_id = message.get("ID_obfuscated")
        iv_base64 = message.get("iv")
        encrypted_metrics_base64 = message.get("encrypted_metrics")

        if not authentication_id or not iv_base64 or not encrypted_metrics_base64:
            raise ValueError(
                "Faltan campos en el mensaje recibido ('ID_obfuscated', 'iv' o 'encrypted_metrics')."
            )

        # Verificar si el dispositivo está autenticado
        authentication_parameters = authenticated_devices.get(authentication_id)
        if not authentication_parameters:
            response = {
                "status": "failed",
                "message": "Dispositivo no autenticado. No se aceptan métricas.",
            }
            client_socket.sendall(json.dumps(response).encode("utf-8"))
            raise ValueError(f"Dispositivo con ID: {authentication_id} no autenticado.")

        # Extraer métricas cifradas
        iv_base64 = message.get("iv")
        encrypted_metrics_base64 = message.get("encrypted_metrics")

        if not iv_base64 or not encrypted_metrics_base64:
            raise ValueError(
                "Faltan campos en el mensaje recibido ('iv', 'encrypted_metrics')."
            )

        # Obtener la clave de sesión del dispositivo
        K_s_bytes = authentication_parameters.get("session_key")
        if not K_s_bytes:
            raise ValueError(
                f"No se encontró una llave de sesión para {authentication_id}."
            )

        # Decodificar IV y métricas cifradas desde Base64
        iv = base64.b64decode(iv_base64)
        encrypted_metrics = base64.b64decode(encrypted_metrics_base64)

        # Descifrar y deshacer el padding de las métricas
        cipher = AES.new(K_s_bytes, AES.MODE_CBC, iv)
        decrypted_metrics_json = unpad(
            cipher.decrypt(encrypted_metrics), AES.block_size
        )

        # Convertir las métricas descifradas de JSON a diccionario
        metrics = json.loads(decrypted_metrics_json.decode("utf-8"))
        logger.info(f"[METRICS] Métricas recibidas descifradas: {metrics}")

        # Enviar respuesta de éxito al dispositivo IoT
        response = {
            "status": "success",
            "message": "Métricas recibidas correctamente.",
        }
        client_socket.sendall(json.dumps(response).encode("utf-8"))
        logger.info("[METRICS] Respuesta enviada al dispositivo IoT.")

    except (ValueError, KeyError) as e:
        logger.error(f"[METRICS] Error en el mensaje recibido: {e}")
        response = {"status": "error", "message": str(e)}
        client_socket.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        logger.error(f"[METRICS] Error durante el manejo de métricas: {e}")
        response = {"status": "error", "message": "Error inesperado."}
        client_socket.sendall(json.dumps(response).encode("utf-8"))


#######################################################
#                      AUXILIARES                     #
#######################################################


def initialize_socket():
    """
    Inicializa un socket persistente para comunicarse con el CA.
    """
    global cloud_socket
    if cloud_socket is None:
        try:
            cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cloud_socket.connect((CA_HOST, CA_PORT))
            logger.info(f"Conectado al CA en {CA_HOST}:{CA_PORT}")
        except socket.error as e:
            logger.error(f"Error al conectar con el CA: {e}")
            cloud_socket = None
            raise e


def close_socket():
    """
    Cierra el socket persistente.
    """
    global cloud_socket
    if cloud_socket:
        try:
            cloud_socket.close()
            logger.info("Socket con el CA cerrado correctamente.")
        except socket.error as e:
            logger.error(f"Error al cerrar el socket: {e}")
        finally:
            cloud_socket = None


def send_and_receive_persistent_socket(message_dict):
    """
    Enviar un mensaje al CA utilizando un socket persistente y recibir la respuesta.
    """
    global cloud_socket
    try:
        if cloud_socket is None:
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
        cloud_socket.sendall(
            json.dumps(encoded_message).encode("utf-8")
        )  # Enviar mensaje

        response = cloud_socket.recv(4096)  # Recibir respuesta
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
        cloud_socket = None  # Marcar el socket como no válido
        raise e


if __name__ == "__main__":
    time.sleep(10)
    # Inicia el servidor de métricas Prometheus
    logger.info("Iniciando el servidor de métricas de Prometheus en el puerto 8010.")
    start_http_server(8010)

    # Realiza el registro ante el CA
    gateway_registration()

    # Inicia el socket
    start_gateway_socket()

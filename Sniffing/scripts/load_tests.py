import socket
import json
from locust import User, task, between, events
import logging
import os

# Configuración del logger
logger = logging.getLogger("locust")

class SocketClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def send(self, message):
        self.socket.sendall(json.dumps(message).encode("utf-8"))

    def receive(self):
        data = self.socket.recv(4096)
        return json.loads(data.decode("utf-8"))

    def close(self):
        self.socket.close()

class SocketUser(User):
    wait_time = between(1, 5)
    host = "localhost"
    port = 5000

    def on_start(self):
        self.client = SocketClient(self.host, self.port)
        self.client.connect()

    @task
    def mutual_authentication(self):
        try:
            # Paso 1: Enviar mensaje "hello" al gateway
            hello_message = {
                "operation": "mutual_authentication",
                "step": "hello",
            }
            self.client.send(hello_message)

            # Paso 2: Recibir G_r_1 del gateway
            gateway_response = self.client.receive()
            if "G_r_1" not in gateway_response:
                raise KeyError("Falta G_r_1 en la respuesta del gateway.")
            G_r_1 = gateway_response["G_r_1"]
            logger.info(f"[AUTH] G_r_1 recibido del gateway: {G_r_1}")

            # Paso 3: Enviar M_1, ID*, r_2*, K_i*, r_3* al gateway
            IoT_M1 = {
                "M_1": int.from_bytes(os.urandom(8), "big"),
                "ID*": int.from_bytes(os.urandom(8), "big"),
                "r_2*": int.from_bytes(os.urandom(8), "big"),
                "K_i*": int.from_bytes(os.urandom(8), "big"),
                "r_3*": int.from_bytes(os.urandom(8), "big"),
            }
            self.client.send(IoT_M1)
            logger.info(f"[AUTH] Datos enviados al gateway: {IoT_M1}")

            # Paso 4: Recibir G_M_2 y Sync_IoT_G del gateway
            gateway_response = self.client.receive()
            if "G_M_2" not in gateway_response:
                raise KeyError("Falta G_M_2 en la respuesta del gateway.")
            G_M_2 = gateway_response["G_M_2"]
            logger.info(f"[AUTH] G_M_2 recibido del gateway: {G_M_2}")

            # Paso 5: Enviar K_i_next_obfuscated al gateway
            K_i_next_obfuscated = int.from_bytes(os.urandom(8), "big")
            self.client.send({"K_i_next_obfuscated": K_i_next_obfuscated})
            logger.info(f"[AUTH] K_i_next_obfuscated enviado al gateway: {K_i_next_obfuscated}")

            # Paso 6: Recibir M_4 del gateway
            gateway_response = self.client.receive()
            if "M_4" not in gateway_response:
                raise KeyError("Falta M_4 en la respuesta del gateway.")
            M_4 = gateway_response["M_4"]
            logger.info(f"[AUTH] M_4 recibido del gateway: {M_4}")

            # Registrar la solicitud como exitosa
            events.request.fire(
                request_type="socket",
                name="mutual_authentication",
                response_time=100,  # Tiempo de respuesta en ms (puedes calcularlo)
                response_length=len(str(gateway_response)),
                exception=None,
            )
        except KeyError as e:
            logger.error(f"[AUTH] Clave faltante en los datos recibidos: {e}")
            events.request.fire(
                request_type="socket",
                name="mutual_authentication",
                response_time=0,
                response_length=0,
                exception=str(e),
            )
        except Exception as e:
            logger.error(f"[AUTH] Error durante la autenticación mutua: {e}")
            events.request.fire(
                request_type="socket",
                name="mutual_authentication",
                response_time=0,
                response_length=0,
                exception=str(e),
            )
        finally:
            self.client.close()

    def on_stop(self):
        self.client.close()
import logging
import socket
import time
import json
import os

from locust import User, task, between, events

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="SKAFS time=%(asctime)s level=%(levelname)s msg=\'%(message)s\'",
    handlers=[logging.FileHandler("/logs/locust.log"), logging.StreamHandler()],
)
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
            step_start = time.time()
            hello_message = {
                "operation": "mutual_authentication",
                "step": "hello",
            }
            self.client.send(hello_message)

            # Paso 2: Recibir G_r_1 del gateway
            gateway_response = self.client.receive()
            events.request.fire(
                request_type="socket",
                name="mutual_auth/step_2_G_r_1",
                response_time=(time.time() - step_start)*1000,
                response_length=len(str(gateway_response)),
                exception=None,
            )
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
            events.request.fire(
                request_type="socket",
                name="mutual_auth/step_4_G_M_2",
                response_time=(time.time() - step_start)*1000,
                response_length=len(str(gateway_response)),
                exception=None,
            )
            logger.info(f"Respuesta recibida: {gateway_response}")

            # Paso 5: Enviar K_i_next_obfuscated al gateway
            K_i_next_obfuscated = int.from_bytes(os.urandom(8), "big")
            self.client.send({"K_i_next_obfuscated": K_i_next_obfuscated})
            logger.info(f"[AUTH] K_i_next_obfuscated enviado al gateway: {K_i_next_obfuscated}")

            # Paso 6: Recibir M_4 del gateway
            gateway_response = self.client.receive()
            events.request.fire(
                request_type="socket",
                name="mutual_auth/step_6_M_4",
                response_time=(time.time() - step_start)*1000,
                response_length=len(str(gateway_response)),
                exception=None,
            )
            logger.info(f"Respuesta recibida: {gateway_response}")

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
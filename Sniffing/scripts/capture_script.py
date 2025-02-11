import subprocess
from scapy.all import IP, TCP, rdpcap
from datetime import datetime

import logging
import time
import json
import os


# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/logs/capture.log"), logging.StreamHandler()],
)
logger = logging.getLogger("Sniffer-Capture")

# Configuración
SHARED_DIR = "/shared_data"
CAPTURE_INTERVAL = 30
MIN_FILE_SIZE = 1024

def analyze_pcap(pcap_file):
    """Analiza un archivo pcap y genera metadatos estructurados"""

    analysis = {"comms": {}}
    ip_role_mapping = {}
    try:
        packets = rdpcap(pcap_file)

        for pkt in packets:
            if not IP in pkt or not TCP in pkt:
                continue
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            payload = bytes(pkt[TCP].payload).decode(errors="ignore")
            dst_port = pkt[TCP].dport

            # Parseo básico del payload
            try:
                payload_data = json.loads(payload)
            except json.JSONDecodeError:
                payload_data = payload  # Si no es JSON, guardar como texto
            # Actualizar mapeo de roles según operación
            if payload_data and isinstance(payload_data, dict):
                operation = payload_data.get("operation", "")
                if operation != "":
                    # Registro de dispositivo
                    if operation == "register_device":
                        ip_role_mapping[src_ip] = {"host": "device", "port": ""}
                        ip_role_mapping[dst_ip] = {"host": "cloud", "port": dst_port}
                    # Registro de Gateway
                    elif operation == "register_gateway":
                        ip_role_mapping[src_ip] = {"host": "gateway", "port": ""}
                        ip_role_mapping[dst_ip] = {"host": "cloud", "port": dst_port}

                    if operation.startswith("mutual_authentication"):
                        # Procesar payload
                        parsed_payload = {}
                        for key, value in payload_data.items():
                            # Convertir a entero si es posible
                            if isinstance(value, str) and value.isdigit():
                                parsed_payload[key] = int(value)
                            elif isinstance(value, dict):
                                # Convertir valores dentro de diccionarios anidados
                                parsed_payload[key] = {
                                    k: (int(v) if isinstance(v, str) and v.isdigit() else v)
                                    for k, v in value.items()
                                }
                            else:
                                parsed_payload[key] = value

                        entry = {
                            "timestamp": datetime.fromtimestamp(pkt.time).isoformat(),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "payload": parsed_payload,
                        }
                        
                        # Almacenar en estructuras
                        if len(analysis["comms"]) == 0:
                            ip_role_mapping[src_ip] = {"host": "device", "port": ""}
                            ip_role_mapping[dst_ip] = {"host": "gateway", "port": dst_port}
                        
                        # Determinar nombres basados en el mapeo
                        src_data = ip_role_mapping.get(src_ip)
                        if src_data:
                            src_role = src_data.get("host", src_ip)
                        
                        dst_data = ip_role_mapping.get(dst_ip)
                        if dst_data:
                            dst_role = dst_data.get("host", dst_ip)
                        
                        
                        if src_role == "gateway" and dst_role != "device":
                            dst_role = "cloud"
                            ip_role_mapping[dst_ip] = {"host": dst_role, "port": dst_port}
                            
                        # Construir estructura de datos
                        comm_key = f"{src_role}->{dst_role}"
                        
                        if comm_key not in analysis["comms"]:
                            analysis["comms"][comm_key] = []

                        analysis["comms"][comm_key].append(entry)
        
        if len(analysis["comms"]) > 0:          
            analysis["ip_role_mapping"] = ip_role_mapping
            analysis["comms"] = process_intercepted_data(analysis["comms"])
            # Guardar análisis
            analysis_file = f"{pcap_file}.analysis.json"
            with open(analysis_file, "w") as f:
                json.dump(analysis, f, indent=2)
            logger.info(f"Análisis guardado en {analysis_file}")
            return True
        return False
    except Exception as e:
        logger.error(f"Error analizando {pcap_file}: {str(e)}")
        return False


def process_intercepted_data(intercepted_data):
    """Elimina diccionarios duplicados de una lista comparándolos con '=='."""

    def remove_duplicates(dictionaries_list):
        unique_list = []
        for dic in dictionaries_list:
            if dic not in unique_list:
                unique_list.append(dic)
        return unique_list

    # Recorremos cada llave en "comms" y eliminamos los duplicados en cada lista
    for key, messages in intercepted_data.items():
        intercepted_data[key] = remove_duplicates(messages)
    return intercepted_data


def capture_loop():
    """Bucle principal de captura y análisis"""
    while True:
        try:
            # Generar nombre de archivo con timestamp
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            pcap_file = f"{SHARED_DIR}/capture_{timestamp}.pcap"

            # Iniciar captura con timeout
            logger.info(f"Iniciando captura: {pcap_file}")
            tcpdump = subprocess.Popen(
                ["tcpdump", "-i", "any", "-w", pcap_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Esperar intervalo de captura
            time.sleep(CAPTURE_INTERVAL)

            # Detener captura
            tcpdump.terminate()
            tcpdump.wait()
            logger.info(f"Captura finalizada: {pcap_file}")

            # Analizar captura
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > MIN_FILE_SIZE:
                if analyze_pcap(pcap_file):
                    os.rename(pcap_file, f"{pcap_file}.processed")
                else:
                    os.rename(pcap_file, f"{pcap_file}.error")
            else:
                logger.warning("Captura vacía o no creada, reintentando.")
                os.remove(pcap_file) if os.path.exists(pcap_file) else None

            time.sleep(60)
        except Exception as e:
            logger.error(f"Error en bucle de captura: {str(e)}")
            time.sleep(10)


if __name__ == "__main__":
    # Verificar y crear directorios necesarios
    os.makedirs(SHARED_DIR, exist_ok=True)
    capture_loop()

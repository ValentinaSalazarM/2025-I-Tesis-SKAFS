# Usa la imagen base oficial de Python
FROM python:3.9-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia solo el código del Gateway y el código compartido
COPY common /app/common
COPY gateway/SKAFS /app/gateway
COPY requirements.txt .

# Instala las dependencias de Python y crea la carpeta para almacenar logs
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir /logs && chmod 777 /logs

# Especifica el comando de inicio para el Gateway
CMD ["python", "-m", "gateway.skafs_gateway"]
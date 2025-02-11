# Usa la imagen base oficial de Python
FROM python:3.9-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia solo el código del Device y el código compartido
COPY common /app/common
COPY device/SKAFS /app/device
COPY requirements.txt .

# Instala las dependencias de Python y crea la carpeta para almacenar logs
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir /logs && chmod 777 /logs

# Especifica el comando de inicio para el Device
CMD ["python", "-m", "device.skafs_device"]
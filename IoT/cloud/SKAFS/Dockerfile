# Usa la imagen base oficial de Python
FROM python:3.9-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia solo el código del Cloud y el código compartido
COPY common /app/common
COPY cloud/SKAFS /app/cloud
COPY requirements.txt .

# Instala las dependencias de Python y crea la carpeta para almacenar logs
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir /logs && chmod 777 /logs

# Especifica el comando de inicio para el Cloud
CMD ["python", "-m", "cloud.skafs_cloud"]
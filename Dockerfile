# Gebruik een officiële Python runtime als basisimage
FROM python:3.9-slim

# Stel de werkdirectory in
WORKDIR /app

# Kopieer de requirements.txt vanuit de Frontend/Test_project map naar de container
COPY /project/requirements.txt .

# Installeer de benodigde Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Kopieer de rest van de applicatiecode naar de container
COPY . .

# Expose de poort waar de applicatie op draait
EXPOSE 5000

# Definieer het commando om de applicatie te starten
CMD ["python", "project/app.py"]
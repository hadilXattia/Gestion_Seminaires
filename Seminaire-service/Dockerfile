# Utiliser l'image officielle de Python comme base
FROM python:3.9-slim

# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier requirements.txt et installer les dépendances
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copier l'ensemble du projet dans le conteneur
COPY . .

# Exposer le port 5000
EXPOSE 5000

# Lancer l'application Flask
CMD ["python", "run.py"]

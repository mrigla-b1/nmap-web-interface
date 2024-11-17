# Use Python base image
FROM python:3.11-slim

# Install Nginx and nmap
RUN apt-get update && apt-get install -y nginx nmap && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy application files and directories
COPY app5.py /app/
COPY requirements.txt /app/
COPY static /app/static
COPY templates /app/templates

# Install Flask and other dependencies from requirements.txt
RUN pip install -r requirements.txt

# Configure Nginx to reverse proxy to Flask
RUN echo "server { \
    listen 80; \
    location / { \
        proxy_pass http://127.0.0.1:5000; \
        proxy_set_header Host \$host; \
        proxy_set_header X-Real-IP \$remote_addr; \
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto \$scheme; \
    } \
}" > /etc/nginx/sites-available/default

# Expose port 80 for external access
EXPOSE 80

# Start both Nginx and the Flask app
CMD service nginx start && python /app/app5.py
 

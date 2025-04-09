#!/bin/bash
echo "Setting up Day 2: Input Validation and Preventing Injection Attacks"

# Stop services but preserve volumes
docker compose down

# Start the database first
docker compose up -d db

# Wait for database to be ready
echo "Waiting for database to initialize..."
sleep 10

# Start the web application
docker compose up -d web-security-lab

docker exec -i web-security-lab-db /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "P@ssw0rd!" -C -N -t 30 -b -e -i /docker-entrypoint-initdb.d/init.sql
USE VulnerableApp;
# Setup specific SQL injection examples in the database
-- Add a product with SQL injection payload
INSERT INTO Products (Name, Description, Price, Category, ImageUrl)
VALUES ('Malicious Product', 'This product has a description with an SQL injection payload: '' OR 1=1 --', 19.99, 'Hacking', '/images/malicious.jpg');


echo "Day 2 environment is ready!"
echo "Access the vulnerable web application at: http://localhost:8080"
echo "Today's focus: SQL Injection in Products search and Command Injection in Admin panel"

echo "Try searching for products with: ' OR 1=1 --"
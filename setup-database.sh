#!/bin/bash
echo "Now creating db when sa has failed error"

docker exec -i web-security-lab-db /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "P@ssw0rd!" -C -N -t 30 -b -e -i /docker-entrypoint-initdb.d/init.sql

echo "Database successfully created"
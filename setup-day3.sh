#!/bin/bash
echo "Setting up Day 3: Authentication, Authorization, and Session Management"

# Stop services but preserve volumes
docker-compose down

# Start the database
docker-compose up -d db

# Wait for database to be ready
echo "Waiting for database to initialize..."
sleep 10

# Start the web application
docker-compose up -d web-security-lab

# Add users with weak passwords for authentication exercises
docker exec -i web-security-lab_db_1 /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P P@ssw0rd! -d VulnerableApp -Q "
-- Add users with weak passwords
IF NOT EXISTS (SELECT * FROM Users WHERE Username = 'weakuser')
BEGIN
    INSERT INTO Users (Username, Password, Email, FullName, IsAdmin)
    VALUES ('weakuser', '123456', 'weak@example.com', 'Weak Password User', 0);
END

-- Add a user with administrative privileges for privilege escalation exercises
IF NOT EXISTS (SELECT * FROM Users WHERE Username = 'manager')
BEGIN
    INSERT INTO Users (Username, Password, Email, FullName, IsAdmin)
    VALUES ('manager', 'manager2023', 'manager@example.com', 'Department Manager', 0);
END
"

echo "Day 3 environment is ready!"
echo "Access the vulnerable web application at: http://localhost:8080"
echo "Today's focus: Authentication vulnerabilities, session management, and authorization flaws"
echo "Additional test accounts:"
echo "  Weak password: weakuser / 123456"
echo "  Manager (for privilege escalation): manager / manager2023"
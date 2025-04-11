FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["vulnerable-app/VulnerableApp.csproj", "vulnerable-app/"]
RUN dotnet restore "vulnerable-app/VulnerableApp.csproj"
COPY . .
WORKDIR "/src/vulnerable-app"
RUN dotnet build "VulnerableApp.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "VulnerableApp.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Add tools for security demos and analysis
RUN apt-get update && apt-get install -y \
    curl \
    vim \
    wget \
    iputils-ping \
    procps \
    net-tools \
    nmap \
    tcpdump \
    whois \
    dnsutils \
    telnet \
    sqlite3 \
    # For Day 2 (Input Validation & Injection)
    sqlmap \
    # For Day 4 (ASP.NET Security)
    openssl \
    # Utility tools
    unzip \
    python3 \
    python3-pip

# Install .NET security analysis tools
RUN dotnet tool install --global dotnet-sca --version 0.1.2 || true
RUN dotnet tool install --global security-scan --version 5.6.3 || true

# Add PATH for dotnet tools
ENV PATH="${PATH}:/root/.dotnet/tools"

# Create directory for exercise solutions
RUN mkdir -p /exercises/solutions
COPY certificates/server.pfx /app/server.pfx

# Create a welcome message with instructions
RUN echo 'echo "Welcome to the Web Security Lab!\n\nThis environment contains a deliberately vulnerable application for learning.\nAccess the application at http://localhost:8080\n\nFor security tools, access OWASP ZAP at http://localhost:8090\n\nType \"help\" for more commands."' > /root/.bashrc

ENTRYPOINT ["dotnet", "VulnerableApp.dll"]
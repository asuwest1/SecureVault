# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build React frontend
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /frontend

# Install dependencies with exact lock file
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts

# Build production assets
COPY frontend/ .
RUN npm run build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Build .NET application
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS dotnet-build
WORKDIR /app

# Restore dependencies (cached layer)
COPY SecureVault.sln global.json ./
COPY src/SecureVault.Core/SecureVault.Core.csproj src/SecureVault.Core/
COPY src/SecureVault.Infrastructure/SecureVault.Infrastructure.csproj src/SecureVault.Infrastructure/
COPY src/SecureVault.Api/SecureVault.Api.csproj src/SecureVault.Api/
RUN dotnet restore src/SecureVault.Api/SecureVault.Api.csproj --use-lock-file

# Copy source and build
COPY src/ src/
RUN dotnet publish src/SecureVault.Api/SecureVault.Api.csproj \
    -c Release \
    -o /publish \
    --no-restore

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime
WORKDIR /app

# Create non-root user
RUN addgroup -S securevault && adduser -S securevault -G securevault

# Copy published app
COPY --from=dotnet-build /publish .

# Copy frontend build into wwwroot
COPY --from=frontend-build /frontend/dist ./wwwroot/

# Security: set proper permissions
RUN chown -R securevault:securevault /app && chmod -R 500 /app

USER securevault

# Bind to non-root port
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/setup/status || exit 1

ENTRYPOINT ["dotnet", "SecureVault.Api.dll"]

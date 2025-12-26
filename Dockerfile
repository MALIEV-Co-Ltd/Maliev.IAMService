# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

# Copy solution and project files
COPY ["Maliev.IAMService.Api/Maliev.IAMService.Api.csproj", "Maliev.IAMService.Api/"]
COPY ["Maliev.IAMService.Data/Maliev.IAMService.Data.csproj", "Maliev.IAMService.Data/"]
COPY ["Maliev.IAMService.Contracts/Maliev.IAMService.Contracts.csproj", "Maliev.IAMService.Contracts/"]
COPY ["nuget.config", "."]

# Restore dependencies
RUN dotnet restore "Maliev.IAMService.Api/Maliev.IAMService.Api.csproj"

# Copy remaining source files
COPY . .

# Build application
WORKDIR "/src/Maliev.IAMService.Api"
RUN dotnet build "Maliev.IAMService.Api.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "Maliev.IAMService.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime
WORKDIR /app

# Install curl for health checks
RUN apk add --no-cache curl

# Set ownership with chown -R app:app /app BEFORE the USER app directive
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Copy published files
COPY --chown=app:app --from=publish /app/publish .

# Expose ports
EXPOSE 8080
EXPOSE 8443

# Environment variables
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_EnableDiagnostics=0

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/iam/liveness || exit 1

# Entry point
ENTRYPOINT ["dotnet", "Maliev.IAMService.Api.dll"]

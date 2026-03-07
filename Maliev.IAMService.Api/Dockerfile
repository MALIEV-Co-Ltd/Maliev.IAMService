# syntax=docker/dockerfile:1.4
# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081


# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy nuget.config and project files
COPY ["nuget.config", "."]
COPY ["Maliev.IAMService.Api/Maliev.IAMService.Api.csproj", "Maliev.IAMService.Api/"]
COPY ["Maliev.IAMService.Application/Maliev.IAMService.Application.csproj", "Maliev.IAMService.Application/"]
COPY ["Maliev.IAMService.Domain/Maliev.IAMService.Domain.csproj", "Maliev.IAMService.Domain/"]
COPY ["Maliev.IAMService.Infrastructure/Maliev.IAMService.Infrastructure.csproj", "Maliev.IAMService.Infrastructure/"]

# Restore with GitHub Packages authentication using BuildKit secrets
RUN --mount=type=secret,id=nuget_username \
    --mount=type=secret,id=nuget_password \
    NUGET_USERNAME=$(cat /run/secrets/nuget_username) \
    NUGET_PASSWORD=$(cat /run/secrets/nuget_password) \
    dotnet restore "./Maliev.IAMService.Api/Maliev.IAMService.Api.csproj"

COPY . .
WORKDIR "/src/Maliev.IAMService.Api"
RUN dotnet build "./Maliev.IAMService.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Maliev.IAMService.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app

# Ensure 'app' owns the workdir (app user already exists in ASP.NET runtime image)
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Copy published application (now owned by app)
COPY --chown=app:app --from=publish /app/publish .

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/iam/liveness || exit 1

ENTRYPOINT ["dotnet", "Maliev.IAMService.Api.dll"]

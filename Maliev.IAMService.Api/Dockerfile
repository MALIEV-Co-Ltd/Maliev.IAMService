# syntax=docker/dockerfile:1.7

ARG dependency_restore_stage=restore-private

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build-base
ARG SERVICE_DEFAULTS_VERSION=1.0.81-alpha
ARG MESSAGING_CONTRACTS_VERSION=1.0.91-alpha
WORKDIR /src

COPY ["nuget.config", "."]
COPY ["NuGet.PRValidation.Config", "."]
COPY ["Directory.Build.props", "."]
COPY ["Maliev.IAMService.Api/Maliev.IAMService.Api.csproj", "Maliev.IAMService.Api/"]
COPY ["Maliev.IAMService.Application/Maliev.IAMService.Application.csproj", "Maliev.IAMService.Application/"]
COPY ["Maliev.IAMService.Domain/Maliev.IAMService.Domain.csproj", "Maliev.IAMService.Domain/"]
COPY ["Maliev.IAMService.Infrastructure/Maliev.IAMService.Infrastructure.csproj", "Maliev.IAMService.Infrastructure/"]
COPY [".ci-packages/", ".ci-packages/"]

FROM build-base AS restore-private
RUN --mount=type=secret,id=nuget_username,required=true \
    --mount=type=secret,id=nuget_password,required=true \
    NUGET_USERNAME="$(cat /run/secrets/nuget_username)" \
    NUGET_PASSWORD="$(cat /run/secrets/nuget_password)" \
    dotnet restore "Maliev.IAMService.Api/Maliev.IAMService.Api.csproj" \
      /p:GITHUB_ACTIONS=true \
      /p:ServiceDefaultsVersion="$SERVICE_DEFAULTS_VERSION" \
      /p:MessagingContractsVersion="$MESSAGING_CONTRACTS_VERSION"

FROM build-base AS restore-local
RUN dotnet restore "Maliev.IAMService.Api/Maliev.IAMService.Api.csproj" \
      --configfile "NuGet.PRValidation.Config" \
      /p:GITHUB_ACTIONS=true \
      /p:ServiceDefaultsVersion="$SERVICE_DEFAULTS_VERSION" \
      /p:MessagingContractsVersion="$MESSAGING_CONTRACTS_VERSION"

FROM ${dependency_restore_stage} AS build
ARG BUILD_CONFIGURATION=Release
COPY . .
WORKDIR "/src/Maliev.IAMService.Api"
RUN dotnet build "Maliev.IAMService.Api.csproj" \
    --configuration "$BUILD_CONFIGURATION" \
    --output /app/build \
    --no-restore \
    /p:GITHUB_ACTIONS=true \
    /p:ServiceDefaultsVersion="$SERVICE_DEFAULTS_VERSION" \
    /p:MessagingContractsVersion="$MESSAGING_CONTRACTS_VERSION"

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Maliev.IAMService.Api.csproj" \
    --configuration "$BUILD_CONFIGURATION" \
    --output /app/publish \
    --no-restore \
    /p:GITHUB_ACTIONS=true \
    /p:ServiceDefaultsVersion="$SERVICE_DEFAULTS_VERSION" \
    /p:MessagingContractsVersion="$MESSAGING_CONTRACTS_VERSION" \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --chown=app:app --from=publish /app/publish .

USER app
EXPOSE 8080
EXPOSE 8081
ENV ASPNETCORE_HTTP_PORTS=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_EnableDiagnostics=0

ENTRYPOINT ["dotnet", "Maliev.IAMService.Api.dll"]

FROM mcr.microsoft.com/dotnet/aspnet:6.0-bullseye-slim AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0-bullseye-slim AS build
WORKDIR /src
COPY ["Web/Cve.Net.Search.Web/Cve.Net.Search.Web.csproj", "Web/Cve.Net.Search.Web/"]
COPY ["Application/Cve.Net.Search.Application/Cve.Net.Search.Application.csproj", "Application/Cve.Net.Search.Application/"]
COPY ["Domain/Cve.Net.Search.Domain.Database/Cve.Net.Search.Domain.Database.csproj", "Domain/Cve.Net.Search.Domain.Database/"]
COPY ["Domain/Cve.Net.Search.Domain.Common/Cve.Net.Search.Domain.Common.csproj", "Domain/Cve.Net.Search.Domain.Common/"]
COPY ["Domain/Cve.Net.Search.Domain.ViewModels/Cve.Net.Search.Domain.ViewModels.csproj", "Domain/Cve.Net.Search.Domain.ViewModels/"]
COPY ["Infrastructure/Cve.Net.Search.Infrastructure/Cve.Net.Search.Infrastructure.csproj", "Infrastructure/Cve.Net.Search.Infrastructure/"]
RUN dotnet restore "Web/Cve.Net.Search.Web/Cve.Net.Search.Web.csproj"
COPY . .
WORKDIR "/src/Web/Cve.Net.Search.Web"
RUN dotnet build "Cve.Net.Search.Web.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Cve.Net.Search.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Cve.Net.Search.Web.dll"]
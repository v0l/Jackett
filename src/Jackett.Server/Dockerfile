FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src
COPY . .
RUN cd src/Jackett.Server && dotnet publish -c Release -f net9.0 --self-contained false -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS runtime
WORKDIR /app
RUN addgroup -S jackett && adduser -S -G jackett -h /app jackett
COPY --from=build /app/publish .
RUN chown -R jackett:jackett /app
USER jackett

EXPOSE 9117
ENV ASPNETCORE_URLS=http://+:9117

ENTRYPOINT ["./jackett"]

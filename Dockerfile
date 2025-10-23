FROM golang:1.21-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o nodehost

FROM alpine:3.18
RUN apk add --no-cache nodejs npm ca-certificates
WORKDIR /app
COPY --from=build /app/nodehost /app/nodehost
COPY templates templates
COPY data.db .
EXPOSE 8080
CMD ["/app/nodehost"]

# syntax=docker/dockerfile:1
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/henbane ./cmd/henbane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/henbane /usr/bin/henbane
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/henbane"]

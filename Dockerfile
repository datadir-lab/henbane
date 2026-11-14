# syntax=docker/dockerfile:1
FROM golang:1.26@sha256:978e0a4e3d953662577d784471db27742f543ab09eead06839a838188c73314b AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/henbane ./cmd/henbane

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/henbane /usr/bin/henbane
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/henbane"]

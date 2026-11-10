# The AOS engine as a container: a static binary on a distroless base,
# running as a non-root user.
FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/flash-software-technology/aos/initiator.BuildVersion=${VERSION}" -o /out/aos ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aos /aos
USER nonroot:nonroot
EXPOSE 8080
ENV AOS_LISTEN_ADDR=:8080
HEALTHCHECK NONE
ENTRYPOINT ["/aos"]
CMD ["serve"]

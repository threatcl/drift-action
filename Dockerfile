FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /drift-action ./cmd/drift-action

FROM gcr.io/distroless/static-debian12
COPY --from=build /drift-action /drift-action
ENTRYPOINT ["/drift-action"]

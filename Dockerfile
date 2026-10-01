# syntax=docker/dockerfile:1
FROM golang:1.24.3-alpine AS build

# Install git for go modules
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go files
COPY go.mod go.sum ./

# Force correct versions to fix cryptographic library conflicts
RUN rm -f go.sum && \
    go mod edit -replace=github.com/consensys/gnark-crypto=github.com/consensys/gnark-crypto@v0.12.1 && \
    go mod edit -replace=github.com/IBM/mathlib=github.com/IBM/mathlib@v0.0.3-0.20231011094432-44ee0eb539da && \
    go mod tidy && \
    go get github.com/consensys/bavard@v0.1.30 && \
    go get google.golang.org/genproto/googleapis/rpc@v0.0.0-20250721164621-a45f3dfb1074 && \
    go mod download

# Copy source code
COPY . .

# Build with optimizations and dependency fixes
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o blockchain_api .

FROM alpine:3.21

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata openssl && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Copy only necessary files from build stage
COPY --from=build /app/blockchain_api ./
COPY --from=build /app/README.md ./
COPY --from=build /app/generate_session_keys.sh ./
COPY --from=build /app/client ./client
COPY --from=build /app/standard_credentials.json ./

# Create identities directory (optional copy follows)
RUN mkdir -p ./identities

# Expose the API port
EXPOSE 3000

# Run the application
CMD ["./blockchain_api"]

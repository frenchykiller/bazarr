# Multi-stage Docker build for Bazarr with native OIDC support
# Stage 1: Build the Vite + Mantine React frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build

# Copy frontend dependencies and package files
COPY frontend/package*.json ./
RUN npm ci --no-audit

# Copy source code and build
COPY frontend/ ./
RUN npm run build

# Stage 2: LinuxServer Bazarr base image with updated code
FROM lscr.io/linuxserver/bazarr:latest

LABEL maintainer="frenchykiller"
LABEL org.opencontainers.image.title="Bazarr with Native OIDC Support"
LABEL org.opencontainers.image.description="Bazarr companion application with native OpenID Connect (OIDC) authentication support"
LABEL org.opencontainers.image.source="https://github.com/frenchykiller/bazarr"

# Copy updated backend python source files into linuxserver app directory
COPY bazarr/ /app/bazarr/bin/bazarr/
COPY bazarr.py /app/bazarr/bin/bazarr.py
COPY custom_libs/ /app/bazarr/bin/custom_libs/

# Copy compiled frontend from frontend-builder stage into /app/bazarr/bin/frontend/build
COPY --from=frontend-builder /build/build /app/bazarr/bin/frontend/build

# Set permissions for linuxserver execution
RUN chown -R 911:911 /app/bazarr/bin

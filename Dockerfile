# syntax=docker/dockerfile:1

# Build: docker build -t stellar-toml-lint .
# Run:
#   docker run --rm -v "$(pwd):/work" stellar-toml-lint stellar.toml
#
# Pre-commit:
#   - repo: local
#     hooks:
#       - id: stellar-toml-lint
#         name: Lint stellar.toml
#         entry: stellar-toml-lint
#         language: docker_image
#         files: (?:.*/)?\.?stellar\.toml$

# `dist/` is generated rather than shipped in the build context (it is git- and
# docker-ignored), so the image builds it in a throwaway stage.
FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts

RUN npm ci && npm run build

FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node dist ./dist
COPY --from=build --chown=stellar-toml-lint:stellar-toml-lint /app/dist ./dist

USER node

ENTRYPOINT ["node", "dist/cli.js"]

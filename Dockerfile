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
FROM --platform=$BUILDPLATFORM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts

RUN npm ci && npm run build && npm prune --omit=dev

FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist

USER node

ENTRYPOINT ["node", "dist/cli.js"]

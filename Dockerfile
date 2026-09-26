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

ARG USER_ID=1000
ARG GROUP_ID=1000

# Newer node:20-alpine bases already occupy uid/gid 1000 (the bundled `node`
# user), so honour the requested ids when free and fall back to fresh ones
# instead of failing the build.
RUN (addgroup -g "$GROUP_ID" stellar-toml-lint || addgroup stellar-toml-lint) && \
    (adduser -u "$USER_ID" -G stellar-toml-lint -S stellar-toml-lint || \
     adduser -G stellar-toml-lint -S stellar-toml-lint)

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build --chown=stellar-toml-lint:stellar-toml-lint /app/dist ./dist

USER stellar-toml-lint

ENTRYPOINT ["node", "dist/cli.js"]

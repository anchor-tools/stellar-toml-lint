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

FROM node:20-alpine

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN addgroup -g "$GROUP_ID" stellar-toml-lint && \
    adduser -u "$USER_ID" -G stellar-toml-lint -S stellar-toml-lint

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=stellar-toml-lint:stellar-toml-lint dist ./dist

USER stellar-toml-lint

ENTRYPOINT ["node", "dist/cli.js"]

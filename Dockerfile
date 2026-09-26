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

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node dist ./dist

USER node

ENTRYPOINT ["node", "dist/cli.js"]

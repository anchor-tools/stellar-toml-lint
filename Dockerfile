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
FROM --platform=$BUILDPLATFORM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts

# ESM rather than CJS: the package is `"type": "module"` and some dependencies
# (dohdec) use top-level await, which a CJS bundle cannot contain. The banner
# gives bundled CommonJS dependencies a working `require`.
RUN npm ci && npm run build \
	&& npx esbuild src/cli.ts --bundle --platform=node --target=node20 --format=esm \
		--outfile=dist/cli.bundle.mjs \
		--banner:js="import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);"

FROM gcr.io/distroless/nodejs20-debian12:nonroot

COPY --from=build --chown=nonroot:nonroot /app/dist/cli.bundle.mjs /app/cli.mjs

# Files to lint are mounted at /work (see the usage above), so relative paths
# resolve there; the entrypoint is absolute so it works from any directory.
WORKDIR /work

USER nonroot

ENTRYPOINT ["/nodejs/bin/node", "/app/cli.mjs"]

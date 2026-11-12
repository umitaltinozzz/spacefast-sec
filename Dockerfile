# Node/Railway deployment of spacefast-sec-mcp (same handler as the Cloudflare Worker).
# esbuild compiles + bundles the TypeScript directly, so no full dependency install is needed.
FROM node:22-alpine AS build
WORKDIR /app
RUN npm install --no-save --no-audit --no-fund esbuild@0.25.10
COPY src ./src
RUN npx esbuild src/node.ts --bundle --platform=node --target=node22 --format=esm --outfile=dist/node.mjs

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# The bundle has no runtime dependencies.
COPY --from=build /app/dist/node.mjs ./node.mjs
USER node
EXPOSE 3000
CMD ["node", "node.mjs"]

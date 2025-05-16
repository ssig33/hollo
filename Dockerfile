FROM node:24

LABEL org.opencontainers.image.title="Hollo"
LABEL org.opencontainers.image.description="Federated single-user \
microblogging software"
LABEL org.opencontainers.image.url="https://docs.hollo.social/"
LABEL org.opencontainers.image.source="https://github.com/fedify-dev/hollo"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt update && apt install -y libstdc++6 ffmpeg jq
RUN npm install -g pnpm

COPY pnpm-lock.yaml package.json /app/
WORKDIR /app/
RUN pnpm install --frozen-lockfile --prod

COPY . /app/

ARG VERSION
LABEL org.opencontainers.image.version="${VERSION}"
RUN \
  if [ "$VERSION" != "" ]; then \
    jq --arg version "$VERSION" '.version = $version' package.json > .pkg.json \
    && mv .pkg.json package.json; \
  fi

EXPOSE 3000
CMD ["pnpm", "run", "prod"]

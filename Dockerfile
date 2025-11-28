FROM nimlang/nim:2.2.0-alpine AS builder

RUN apk add --no-cache git gcc musl-dev postgresql-dev libsecp256k1-dev

WORKDIR /app

COPY nim_nostr_relay.nimble .

RUN nimble install -y --depsOnly || nimble install -y -d

COPY src ./src
COPY public ./public

RUN nimble build -d:release --opt:size

FROM alpine:latest
RUN apk add --no-cache libpq libsecp256k1 libgcc libstdc++
WORKDIR /app
COPY --from=builder /app/nim-nostr-relay .
COPY public ./public
EXPOSE 9001
CMD ["/app/nim-nostr-relay"]

# Package

version       = "0.0.1"
author        = "Yasuhiro Matsumoto"
description   = "nim_nostr_relay is simple nostr relay server"
license       = "MIT"
srcDir        = "src"
bin           = @["nim_nostr_relay"]

namedBin = {
  "nim_nostr_relay": "nim-nostr-relay"
}.toTable

# Dependencies

requires "nim >= 2.2.6"

requires "db_connector >= 0.1.0"
requires "jsony >= 1.1.6"
requires "nimcrypto >= 0.7.2"
requires "results >= 0.5.1"
requires "secp256k1 >= 0.6.0.3.2"
requires "stew >= 0.4.2"
requires "ws >= 0.5.0"

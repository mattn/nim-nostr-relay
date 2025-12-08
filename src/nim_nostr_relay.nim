import asyncdispatch, asynchttpserver, ws
import uri
import strutils
import json, jsony, options, sequtils
import secp256k1
import nimcrypto/[sha2, hash]
import db_connector/db_postgres
import std/strformat
from std/times import getTime, toUnix
from std/os import parentDir, `/`, splitFile, fileExists, getEnv

when defined(posix):
  from std/posix import onSignal, SIGINT, SIGTERM

from std/mimetypes import getExt, getMimeType, newMimetypes

type
  RequestKind = enum
    kEVENT = "EVENT"
    kREQ = "REQ"
    kCLOSE = "CLOSE"

  ResponseKind = enum
    kOK = "OK"
    kCLOSED = "CLOSED"
    kNOTICE = "NOTICE"
    kEOSE = "EOSE"

  Event = object
    id*: string
    pubkey*: string
    created_at*: int64
    kind*: int
    tags*: seq[seq[string]]
    content*: string
    sig*: string

  Filter = object
    ids*: Option[seq[string]]
    authors*: Option[seq[string]]
    kinds*: Option[seq[int]]
    `e`*: Option[seq[string]]
    `p`*: Option[seq[string]]
    `t`*: Option[seq[string]]
    tags*: Option[seq[seq[string]]]
    since*: Option[int64]
    until*: Option[int64]
    limit*: Option[int]

  MsgRequest = ref object
    case kind*: RequestKind
    of kEVENT:
      event*: Event
    of kREQ:
      subscriptionId*: string
      filters*: seq[Filter]
    of kCLOSE:
      closeSubscriptionId*: string

  MsgResponse = ref object
    case kind*: ResponseKind
    of kOK:
      id*: string
      `result`*: bool
      message*: string
    of kNOTICE:
      notice*: string
    of kEOSE:
      eoseSubscriptionId*: string
    of kCLOSED:
      reason*: string

  Subscription = object
    ws: WebSocket
    id: string
    filters: seq[Filter]


var
  subscriptions{.threadvar.}: seq[Subscription]
  mimedb{.threadvar.}: mimetypes.MimeDB
  db{.threadvar.}: DbConn


const SCHEMA_SQLS = [
  """
CREATE OR REPLACE FUNCTION tags_to_tagvalues(jsonb) RETURNS text[]
    AS 'SELECT array_agg(t->>1) FROM (SELECT jsonb_array_elements($1) AS t)s WHERE length(t->>0) = 1;'
    LANGUAGE SQL
    IMMUTABLE
    RETURNS NULL ON NULL INPUT
""",
  """
CREATE TABLE IF NOT EXISTS event (
  id text NOT NULL,
  pubkey text NOT NULL,
  created_at integer NOT NULL,
  kind integer NOT NULL,
  tags jsonb NOT NULL,
  content text NOT NULL,
  sig text NOT NULL,

  tagvalues text[] GENERATED ALWAYS AS (tags_to_tagvalues(tags)) STORED
)
""",
  "CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event USING btree (id text_pattern_ops)",
  "CREATE INDEX IF NOT EXISTS pubkeyprefix ON event USING btree (pubkey text_pattern_ops)",
  "CREATE INDEX IF NOT EXISTS timeidx ON event (created_at DESC)",
  "CREATE INDEX IF NOT EXISTS kindidx ON event (kind)",
  "CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC)",
  "CREATE INDEX IF NOT EXISTS arbitrarytagvalues ON event USING gin (tagvalues)"
]

proc parseRequest(jsonStr: string): MsgRequest =
  let node = jsonStr.parseJson()
  if node.kind != JArray:
    raise newException(ValueError, "Nostr message must be an array")

  let tag = node[0].getStr()
  case tag
  of "EVENT":
    let ev = node[1].to(Event)
    return MsgRequest(kind: kEVENT, event: ev)
  of "REQ":
    let subId = node[1].getStr()
    var filters: seq[Filter]
    for i in 2 ..< node.len:
      filters.add node[i].to(Filter)
    return MsgRequest(kind: kREQ, subscriptionId: subId, filters: filters)
  of "CLOSE":
    return MsgRequest(kind: kCLOSE, closeSubscriptionId: node[1].getStr())


proc toResponseJson(response: MsgResponse): string =
  case response.kind
  of kOK:
    return toJson(%*["OK", response.id, response.result, response.message])
  of kNOTICE:
    return toJson(%*["NOTICE", response.notice])
  of kEOSE:
    return toJson(%*["EOSE", response.eoseSubscriptionId])
  of kCLOSED:
    return toJson(%*["CLOSED", response.reason])


proc filterMatch(event: Event, filter: Filter): bool =
  var match = true
  if filter.ids.isSome:
    match = event.id in filter.ids.get()
  if filter.authors.isSome:
    match = match and (event.pubkey in filter.authors.get())
  if filter.kinds.isSome:
    match = match and (event.kind in filter.kinds.get())
  if filter.since.isSome:
    match = match and (event.created_at >= filter.since.get())
  if filter.until.isSome:
    match = match and (event.created_at <= filter.until.get())
  if filter.e.isSome:
    var foundE = false
    for tag in event.tags:
      if tag.len > 1 and tag[0] == "e" and tag[1] in filter.e.get():
        foundE = true
        break
    match = match and foundE
  if filter.p.isSome:
    var foundP = false
    for tag in event.tags:
      if tag.len > 1 and tag[0] == "p" and tag[1] in filter.p.get():
        foundP = true
        break
    match = match and foundP
  if filter.t.isSome:
    var foundT = false
    for tag in event.tags:
      if tag.len > 1 and tag[0] == "t" and tag[1] in filter.t.get():
        foundT = true
        break
    match = match and foundT

  if filter.tags.isSome:
    for reqTag in filter.tags.get():
      var foundTag = false
      for eventTag in event.tags:
        if eventTag.len > 1 and eventTag[0] == reqTag[0] and eventTag[1] ==
            reqTag[1]:
          foundTag = true
          break
      match = match and foundTag

  return match


proc verifyEvent(event: Event): bool =
  try:
    # Nostr event ID calculation: sha256 hash of serialized event data
    let serialized = toJson(%*[
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ])

    # Calculate event ID
    let hash = sha256.digest(serialized)
    var calculatedId = ""
    for b in hash.data:
      calculatedId.add(b.toHex(2).toLowerAscii())

    # Verify event ID matches
    if calculatedId != event.id:
      return false

    # Parse Schnorr signature and x-only public key from hex
    let sigResult = SkSchnorrSignature.fromHex(event.sig)
    if sigResult.isErr:
      return false
    let sig = sigResult.get()

    let pubkeyResult = SkXOnlyPublicKey.fromHex(event.pubkey)
    if pubkeyResult.isErr:
      return false
    let pubkey = pubkeyResult.get()

    # Verify Schnorr signature
    return sig.verify(hash.data, pubkey)
  except:
    return false

proc isValidEvent(event: Event): bool =
  # Placeholder for actual event validation logic
  return event.id.len > 0 and event.pubkey.len > 0 and event.sig.len > 0

proc deleteEventByIdAndPubkey(id: string, pubkey: string): bool =
  try:
    db.exec(sql"DELETE FROM event WHERE id = ? AND pubkey = ?", id, pubkey)
    return true
  except DbError:
    return false

proc deleteEventByKindAndPubkey(kind: int, pubkey: string,
    created_at: int): bool =
  try:
    db.exec(sql"DELETE FROM event WHERE kind = ? AND pubkey = ? AND created_at <= ?",
        kind, pubkey, created_at)
    return true
  except DbError:
    return false

proc deleteEventByKindAndPubkeyAndDtag(kind: int, pubkey: string, dtag: string,
    created_at: int): bool =
  try:
    db.exec(sql"DELETE FROM event WHERE kind = ? AND pubkey = ? AND tags @> ?::jsonb AND created_at <= ?",
        kind, pubkey, ["d", dtag].toJson(), created_at)
    return true
  except DbError:
    return false

proc deleteEventByIdAndKindAndPtag(id: string, kind: int, ptag: string): bool =
  try:
    db.exec(sql"DELETE FROM event WHERE id = ? AND kind = ? AND tags @> ?::jsonb",
        id, kind, ["p", ptag].toJson())
    return true
  except DbError:
    return false

proc saveEvent(event: Event): bool =
  try:
    db.exec(sql"""
      INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig)
      VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)
      ON CONFLICT (id) DO NOTHING
    """, event.id, event.pubkey, event.created_at, event.kind,
        toJson(event.tags), event.content, event.sig)
    return true
  except DbError:
    return false

proc getEventById(id: string): Option[Event] =
  var row = db.getRow(sql("SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE id = ?"), [id])
  if row[0] != "":
    return option(Event(
      id: row[0],
      pubkey: row[1],
      created_at: parseInt(row[2]),
      kind: parseInt(row[3]),
      tags: fromJson(row[4], seq[seq[string]]),
      content: row[5],
      sig: row[6]
    ))
  return none(Event)

proc buildQueryFromFilter(filter: Filter): (string, seq[string]) =
  var whereClauses: seq[string] = @[]
  var params: seq[string] = @[]

  if filter.ids.isSome:
    let ids = filter.ids.get()
    var idConditions: seq[string] = @[]
    for id in ids:
      params.add(id)
      idConditions.add("id LIKE ? || '%'")
    if idConditions.len > 0:
      whereClauses.add("(" & idConditions.join(" OR ") & ")")

  if filter.authors.isSome:
    let authors = filter.authors.get()
    var authorConditions: seq[string] = @[]
    for author in authors:
      params.add(author)
      authorConditions.add("pubkey LIKE ? || '%'")
    if authorConditions.len > 0:
      whereClauses.add("(" & authorConditions.join(" OR ") & ")")

  if filter.kinds.isSome:
    let kinds = filter.kinds.get()
    whereClauses.add("kind IN (" & kinds.mapIt($it).join(",") & ")")

  if filter.since.isSome:
    whereClauses.add("created_at >= " & $filter.since.get())

  if filter.until.isSome:
    whereClauses.add("created_at <= " & $filter.until.get())

  if filter.e.isSome:
    let etags = filter.e.get()
    for etag in etags:
      params.add(etag)
      whereClauses.add("? = ANY(tagvalues)")

  if filter.p.isSome:
    let ptags = filter.p.get()
    for ptag in ptags:
      params.add(ptag)
      whereClauses.add("? = ANY(tagvalues)")

  var query = "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event"
  if whereClauses.len > 0:
    query &= " WHERE " & whereClauses.join(" AND ")

  query &= " ORDER BY created_at DESC"

  if filter.limit.isSome:
    query &= " LIMIT " & $filter.limit.get()
  else:
    query &= " LIMIT 500"

  return (query, params)

proc doEVENT(ws: WebSocket, msg: MsgRequest) {.async.} =
  if not isValidEvent(msg.event):
    await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
        result: false, message: "invalid: event is invalid")))
    return

  if not verifyEvent(msg.event):
    await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
        result: false, message: "invalid: signature verification failed")))
    return

  if msg.event.kind == 5:
    for tag in msg.event.tags:
      if tag.len > 1 and tag[0] == "e":
        var x = getEventById(tag[1])
        if x.isSome():
          var ev = x.get()
          if ev.kind == 1059:
            if not deleteEventByIdAndKindAndPtag(tag[1], 1059, msg.event.pubkey):
              await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
                  result: false, message: "error: failed to delete event")))
              return
          else:
            if not deleteEventByIdAndPubkey(tag[1], msg.event.pubkey):
              await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
                  result: false, message: "error: failed to delete event")))
              return
  elif msg.event.kind >= 20000 and msg.event.kind < 30000:
    # Ephemeral events: broadcast only, don't save to database
    discard
  else:
    if msg.event.kind == 0 or msg.event.kind == 3 or (msg.event.kind >=
        10000 and msg.event.kind < 20000):
      if not deleteEventByKindAndPubkey(msg.event.kind, msg.event.pubkey,
          msg.event.created_at):
        await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
            result: false, message: "error: failed to delete event")))
        return
    elif msg.event.kind >= 30000 and msg.event.kind < 40000:
      for tag in msg.event.tags:
        if tag.len > 1 and tag[0] == "d" and tag[1].len > 0:
          if not deleteEventByKindAndPubkeyAndDtag(msg.event.kind,
              msg.event.pubkey, tag[1], msg.event.created_at):
            await ws.send(toResponseJson(MsgResponse(kind: kOK,
                id: msg.event.id, result: false,
                message: "error: failed to delete event")))
            return
      discard

    if not saveEvent(msg.event):
      await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
          result: false, message: "error: failed to save event")))
      return

  await ws.send(toResponseJson(MsgResponse(kind: kOK, id: msg.event.id,
      result: true, message: "")))
  for sub in subscriptions:
    for filter in sub.filters:
      if filterMatch(msg.event, filter):
        let eventJson = toJson(%*["EVENT", sub.id, msg.event])
        if sub.ws.readyState == Open:
          asyncCheck sub.ws.send(eventJson)


proc doREQ(ws: WebSocket, msg: MsgRequest) {.async.} =
  subscriptions.add Subscription(ws: ws, id: msg.subscriptionId,
      filters: msg.filters)
  let now = getTime().toUnix()
  for filter in msg.filters:
    try:
      let (query, params) = buildQueryFromFilter(filter)
      for row in db.rows(sql(query), params):
        let tags = fromJson(row[4], seq[seq[string]])

        var expired = false
        for tag in tags:
          if tag.len > 0 and tag[0] == "expiration" and parseInt(tag[1]) <=
              getTime().toUnix():
            expired = true
            break
        if expired:
          continue
        let event = Event(
          id: row[0],
          pubkey: row[1],
          created_at: parseInt(row[2]),
          kind: parseInt(row[3]),
          tags: tags,
          content: row[5],
          sig: row[6]
        )

        let eventJson = toJson(%*["EVENT", msg.subscriptionId, event])
        await ws.send(eventJson)
    except:
      echo "Failed to query events from database: ", getCurrentExceptionMsg()

  await ws.send(toResponseJson(MsgResponse(kind: kEOSE,
      eoseSubscriptionId: msg.subscriptionId)))


proc doCLOSE(ws: WebSocket, msg: MsgRequest) =
  subscriptions.keepItIf(it.ws != ws or it.id != msg.closeSubscriptionId)


proc process(ws: WebSocket) {.async, gcsafe.} =
  try:
    let packet = await ws.receiveStrPacket()
    let msg = packet.parseRequest()

    case msg.kind:
    of kEVENT:
      await doEVENT(ws, msg)
    of kREQ:
      await doREQ(ws, msg)
    of kCLOSE:
      doCLOSE(ws, msg)

  except JsonParsingError:
    await ws.send(toResponseJson(MsgResponse(kind: kNOTICE,
        notice: "Unknown payload format")))


proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/" and req.headers.getOrDefault("Upgrade") == "websocket":
    try:
      var ws = await newWebSocket(req)
      while ws.readyState == Open:
        await process(ws)
    except WebSocketClosedError:
      return
    except:
      echo "Unexpected error: ", getCurrentExceptionMsg()
      return

  elif req.headers.getOrDefault("accept") == "application/nostr+json":
    await req.respond(Http200, "{}")
  else:
    var filename = decodeUrl(req.url.path)
    if filename == "/":
      filename = "/index.html"

    filename = currentSourcePath().parentDir / "public" / filename
    if fileExists(filename):
      await req.respond(Http200, readFile(filename), newHttpHeaders({
          "Content-Type": getMimeType(mimedb, splitFile(filename).ext)}))
      return
    await req.respond(Http404, "Not Found\n")

let dbUrl = getEnv("DATABASE_URL", "")
if dbUrl.len > 0:
  # Parse DATABASE_URL (format: postgres://user:password@host:port/dbname)
  db = open("", "", "", dbUrl)
else:
  let dbHost = getEnv("DB_HOST", "localhost")
  let dbUser = getEnv("DB_USER", "postgres")
  let dbPass = getEnv("DB_PASS", "")
  let dbName = getEnv("DB_NAME", "nostr")
  db = open(dbHost, dbUser, dbPass, dbName)

echo "Connected to PostgreSQL database"

# Initialize database schema
try:
  for sqlStmt in SCHEMA_SQLS:
    db.exec(sql(sqlStmt))
  echo "Database schema initialized"
except:
  echo "Warning: Failed to initialize schema: ", getCurrentExceptionMsg()

mimedb = newMimetypes()
var server = newAsyncHttpServer()

# Signal handler for graceful shutdown
var keepRunning = true

when defined(posix):
  proc handleSignal(signal: cint) {.noconv.} =
    echo "\nReceived shutdown signal, stopping..."
    keepRunning = false

  onSignal(SIGINT):
    handleSignal(SIGINT)

  onSignal(SIGTERM):
    handleSignal(SIGTERM)

when defined(windows):
  import std/widestrs

  proc consoleCtrlHandler(dwCtrlType: int32): int32 {.stdcall.} =
    if dwCtrlType == 0 or dwCtrlType == 2: # CTRL_C_EVENT or CTRL_CLOSE_EVENT
      echo "\nReceived shutdown signal, stopping..."
      keepRunning = false
      return 1
    return 0

  proc SetConsoleCtrlHandler(handler: pointer, add: int32): int32
    {.importc: "SetConsoleCtrlHandler", dynlib: "kernel32", stdcall.}

  discard SetConsoleCtrlHandler(cast[pointer](consoleCtrlHandler), 1)

echo "Starting server on port 9001..."

# Start server in async manner
asyncCheck server.serve(Port(9001), cb)

# Main loop that can be interrupted
while keepRunning:
  poll(100)

echo "Server stopped."
db.close()

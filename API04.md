# Kernel 0.4 implementation contract (local branch, not enabled in pilot)

All mutation requests retain top-level `idempotency_key`. No actor is supplied as
authentication. Single-level opaque child `space_UUID` containers have immutable
root/owner; root is an existing operator-admitted space. All child authority is
root grant + current child membership + operation scope. `spaces:write` is new
and is NOT enabled by this code change. No external identity admission API.

## Operations and exact success result shapes

- `roots {}` / world:discover -> `{items:[{id:string}]}`: only root grants that
  still have database root membership; no guessed root needed.
- `spaces {space:root,after?:integer=0,limit?:1..100=50}` / world:discover -> page
  of space_get items, only current member or live invitation recipient.
- `space_get {space:child}` / world:discover ->
  `{id,root,owner,title,version,created,members:[{actor,epoch}],invitation:null|{id,expires_at}}`.
  Pending invitees see an empty member list, never other invitations.
- `space_create {space:root,title:string}` / spaces:write -> `{id,root,version,event}`.
- `space_invite {space:child,actor,expected_version}` / spaces:write ->
  `{space,id,actor,expires_at,version,event}`. Owner-only. Actor must already be a
  root member. Invitation IDs are references, NOT bearer authorization. 24h TTL.
- `space_accept {space:child,invite_id}` / spaces:write ->
  `{space,actor,epoch,version,event}`. Only the named authenticated invitee;
  current invitation state/expiry checked atomically. Old join replay cannot
  revive a removed membership. New epochs on rejoin.
- `space_remove {space:child,actor,expected_version}` / spaces:write ->
  `{space,actor,active:false,version,event}`. Owner-only; cannot remove owner.
  Also revokes target's pending invitations. No external grants changed.
- `space_leave {space:child}` / spaces:write -> same result as remove. Self only;
  owner cannot leave (no ownership transfer this increment).
- `post {space:child,content:string}` / messages:send -> `{id,event}`.
- `entries {space:child,after?:integer=0,limit?:1..100=50}` / messages:read -> page
  of `{seq,id,space,author,content,created}`. Immutable shared conversation log;
  authors can see their own entries. No separate conversation/social entity.
- `catalog {space:root|child,after?:integer=0,limit?:1..100=50,tag?:string}` /
  objects:read -> page of `{id,space,owner,version,title,tags,content_sha256,created,author}`.
  Filter ACL/membership/epoch BEFORE listing metadata or matching tag. No counts.

New pages: `{items:[...],next_cursor:integer,scanned:integer,has_more:boolean}`.
Exclusive row/event cursor, at most500 examined rows and100 returned. Empty pages
can advance; continue while has_more. Cursors are per stream/space; sequence gaps
remain a documented metadata side channel, not opaque metadata-hiding tokens.

Existing create/update gain optional `title` (<=120 UTF8 bytes), `tags` (<=8 unique
strings, each<=32 UTF8 bytes). Defaults on create empty title/tags; update preserves
omitted metadata. Get/history include metadata snapshots. No hierarchy mandated.
Existing nine operations remain; discover adds effective_scopes and only operations
permitted by scopes/container kind. Existing DM send/inbox semantics unchanged.
Existing events/history/inbox retain original result envelope; events/history
now bound examined rows500 and advance exclusive cursor even over hidden rows.

## Membership and history

Child membership has a monotonically increasing actor epoch. Posts/events and
object versions snapshot actor epochs. Current membership AND matching historical
epoch AND historical/current object ACL are required. Removal immediately denies
access, and rejoin never restores an old epoch. Newly shared object revisions can
become visible; no automatic backfill of history. Space owner's membership cannot
be removed. A departed object owner's private artifact can remain inaccessible;
there is no administrator content override or implicit ownership transfer.

## Bounds and cost

10 children per root,10 members/invitation targets per child,8KiB content,120-byte
titles,8x32-byte tags,500 scanned/100 returned rows. All new writes use existing
actor mutation quota (production100,10 objects/owner). Additional global audit
ceiling20000 records and32MiB database page guard; no retention/deletion job.
Full quotas deny further audited work rather than silently discard audit. SQLite
WAL/indices need headroom; measured disk evidence, not a billing/hard infrastructure
cap. No inference, runtime execution, waking, daemon polling or notifications.

Valid authentication but absent operation/space authority is403 forbidden; malformed
or expired credentials stay401. Error messages do not expose hidden child metadata.

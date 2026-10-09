# Z2Z V1 P2P Protocol Specification — Candidate Construction

**Updated:** 2026-10-06  
**Purpose:** Candidate discovery/gossip/coordination contract for P0.05–P0.07. Section7 is the exact **owner-approved P0.07 network design freeze (2026-10-06)**; design approval is not implemented network, qualified backed-order market or release approval. The [active prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [delivery matrix](V1-DELIVERY-MATRIX.md) and [microplan](V1-MICRO-IMPLEMENTATION-PLAN.md) govern scope/dependencies; [BLOCKERS](BLOCKERS.md) and the [native checkpoint](NATIVE-IMPLEMENTATION-STATUS.md) own readiness/evidence.

**The audience for order terms is the selected bilateral counterparty only** (owner decision). Gossip carries neutral availability beacons, never order terms. The [2026-10-06 research](research/2026-10-06-phase0-private-discovery-network.md) remains proposal provenance; owner approval now covers the exact P0.07 freeze in§7, not every research construction or P0.05/P0.06 financial relation/state machine. This document does not approve publishing real owner orders and does not reduce acceptance to unverified hints. Bilateral disclosure is minimization, **not a GD2 waiver**: strict GD2 is unmet (§8).

## 1. Protocol Stack

Pinned base: `libp2p =0.56.0` (`crates/runtime/Cargo.toml`). It runs today with TCP + Noise XX + yamux, ping, identify (`/z2z/transport/1.0.0`), the bounded vendored peer-only Kademlia and configured reconnect. Planned additions:

- **QUIC** (libp2p-quic 0.13.1) with its own TLS, never Noise layered on QUIC. Section 7 selects reduced windows and a required pre-handshake admission patch; upstream defaults are not the selected policy.
- **request-response 0.29.0** for `/z2z/session/1`, with global admission before request submission or inbound body allocation.
- **GossipSub 0.49.0** for neutral beacons only, with the explicit configuration and required internal cardinality/decoder patches in §7.
- **mDNS 0.48.0** for LAN address introduction only, followed by authenticated protocol/beacon validation. Its generic DNS discovery is not itself a Z2Z beacon. Section 7 requires a bounded vendored patch and separate LAN-multicast permission; current checks are loopback-only.
- **Optional independent relay 0.21.0 + DCUtR 0.14.0 + AutoNAT 0.15.0**, off by default, for introduction and hole punching only. Relay defaults are 128KiB/2-minute circuits, so fill sessions run direct with resumable exact-byte messages, not financial traffic over a relay circuit.

Adding any of these needs a reviewed lock update. GossipSub, request-response and relay are absent from the current lock.

Separate peer identity from owner financial identity. A PeerId/signature authenticates a peer message, not wallet control, note ownership, deposit backing or settlement authority. Keep peer keys separate from spending/owner-consent keys.

Protocol IDs:

- `/z2z/beacon/1`: exact GossipSub stream ID, using its v1.1 control semantics; fixed neutral application payload in §7. mDNS is address discovery, not a second application codec.
- `/z2z/session/1`: direct request-response carrying the signed `Z2Z_SESSION` v1 envelope in §7. It binds lane id, chain-context digest, deployment digest, session id, both coordination keys, role map, two challenges, a strictly increasing seq, kind, advisory timestamp and body. A future cross-lane session must additionally bind both lane descriptors, hashlock commitment and native-unit deadlines; no samechain kind implicitly enables cross-chain execution.
- `/z2z/backing-check` is **dropped**: a peer RPC answer is never backing.
- The former order-gossip/order-query/fill-coord responsibilities are replaced by the beacon and session protocols.

Codec and exact owner-approved design ceilings are in§7: fixed-width binary with full exhaustion, no JSON/compression/chunked bypass, distinct beacon/control/backing/packet/certificate bounds. Embedded financial frames retain their existing canonical versions and encodings; implementation is not claimed.

## 2. Discovery and Bootstrap

Use owner-selected bootstrap/direct peer addresses, optional company-operated seeds and mDNS/Kademlia as candidates. No mandatory paid VPS/service or company endpoint. Existing peers may continue when seeds are down; a fresh internet node still needs a reachable independent peer/address. mDNS is not internet discovery, and pure P2P does not establish NAT/firewall reachability.

Section 7 selects finite discovery/reconnect/cache/query budgets and keeps owner-explicit listen/bootstrap addresses (no compiled-in company seed or silently opened port). Reconnect, seed replacement, partition healing and startup sync still require actual qualification. Seeds discover peers only: no private witness access, money authority, required prover/relay or new exit signature.

## 3. Neutral Availability Gossip (no order terms)

Beacons advertise only that a peer offers a lane and protocol version. Topic membership and timing still leak lane interest and IP/PeerId; that leak is recorded, not waived. Terms, commitments, NFs, tree/index hints and amounts go **only** to the selected counterparty inside `/z2z/session/1`. Every session frame binds the protocol version, the exact lane/chain/deployment/asset domain, the message identity and the authenticating key.

### Field audience — session to selected counterparty only

| Content | Audience | Residual leak |
|---|---|---|
| Lane/chain/authority/schema/asset | beacon carries lane+version only; full identity goes in the session | lane interest from topic/query |
| Side, quantity, price, fee caps | session only | the counterparty learns the full terms; own-result inference (GD2) |
| Input identity, NF, order/generation, tree/index | session only (needed for the BackingClaim current-state check) | onchain locator linking the maker's note history and identity after settlement |
| Coordination key/PeerId/signature | session (fresh coordination key per session) | PeerId/IP/timing are not hidden |
| Timestamp/session/seq | session | peer clocks are advisory (±300s) and never set financial validity |

Note openings, secrets and private witnesses never enter any frame. The beacon cache is bounded and rebuildable; losing it removes a candidate only. A signed cancel/fill notice cannot mark an order consumed or free local backing without authenticated chain reconciliation.

## 4. Order Advertisement Trust Model

Authenticate the exact advertising key's claim. A signature cannot prove maker ownership, backed amount/asset, membership or current spendability. A known root/count, seen commitment, vault token balance or aggregate deposit does not bind terms to an exclusively owned unspent right.

**Proposed construction (P0.05, PROPOSED-MECHANISM):** a dedicated **non-executable** `BackingClaim` relation, with its own domain `Z2Z_DISCOVERY_BACKING` v1, program, VKey and journal. It binds:

- lane, chain context and deployment
- asset, side, remaining amount, limit and fee cap
- lane input identity and stable NF
- order id and generation
- a verifier-selected anchor hash/height
- a receiver challenge and both coordination keys

The verifier independently reads root/count and `spent(NF)` (or the lane equivalent) at the anchor and selects the insertion from its own complete history. The result is `BACKED_AT(anchor, TRUSTED_NODE)`: capacity at a block, not an exclusive reservation, guaranteed settlement or consensus proof. The relation never emits or accepts financial certificates or OwnerJournals.

Its negative corpus must reject each of the following:

- copied commitment with an arbitrary NF
- wrong opening
- substituted amount, asset or side
- spent NF at the anchor
- omitted NF-only spend
- stale anchor or replayed challenge
- swapped keys
- a financial certificate offered as backing
- lane substitution

Hints, labels, reputation or deferral do not close P2.17.

## 5. Fill Coordination Protocol

### Exact public packet assembly precedes both role proofs

V1 requires both owners online for each **new** full/partial fill and fresh consent to one exact packet. Map maker/taker to canonical roles A/B explicitly; network role labels do not change relation roles.

1. **Bind the session and independent pins.** Negotiate only permitted public order/quantity claims under exact session, chain, authority/code, verifier/program/schema, asset and role identities. An availability acceptance is coordination, not a consent/proof/backing fact.
2. **Prepare owner outputs locally.** Each recipient constructs, decrypts, recomputes and backs up its own proceeds/change/partial successor using its own recovery capability and authentic input state. Retain openings, encryption keys and proving material locally. Wrong-key/unrecoverable output blocks consent even if totals conserve value.
3. **Exchange permitted public descriptors/E/leaves and assemble one common packet.** Reuse canonical `InputDescriptor`, `OutputDescriptor`, `PublicPacket` and [FillExecution/hash implementation](../crates/protocol/src/samechain/fill.rs), not a second financial packet. Agree byte-identical validated packet body B without terminal C, complete deployment/expiry, ordered input/output manifests and independently selected canonical E frame2. Each owner computes only its own salted policy leaf from authenticated input order; exchange ordered opaque leafA/leafB, then compute the same aggregate C and complete packet. Public note outputs bind role/commitment/recovery-key commitment/ciphertext version/bytes; Exit/Fee descriptors bind role/payer/asset/recipient/amount. Recompute after any B/E mutation before either role proof. Public quantities/nullifiers/owners/recipients/leaves require disclosure review, not “unlinkable” or GD2-secret labels.
4. **Review and freshly consent owner-locally.** [OwnerWitness frame2](../crates/proofs/src/samechain.rs) holds frozen packet, E, ordered leaves and independent `own_salt`, own input/path/seed/consent/output openings, never counterparty policy/salt or whole Terms/common blind. Use `review-fill --packet FILE --execution FILE --role a|b --witness-stdin`; independently select canonical execution frame2 rather than deriving approval from witness stdin. Review requires exact expected E/packet equality and own policy leaf, ownership, conservation/net-price/fees, successor/recovery semantics. Persist recovery generation, reservation and exact authorization/release intent before any signed artifact escapes. Durable/session integration still needs P0.06/P3.04 qualification; no private witness exchange, even encrypted.
5. **Generate role proofs locally, then release certificates.** Each owner proves only its own role on the assembled packet using controlled owner-local resources. Exchange bounded public proof/certificate/consent artifacts with session/domain/role/packet binding; never merge two private witnesses into a network job. Independently verify counterparty bytes against caller-selected pins and full expected journals. A role/session mismatch, changed descriptor or stale consent rejects, not a peer-triggered re-sign.
6. **Build and optionally preview the exact bilateral call.** Reuse existing chains call builders with both verified certificates and unchanged packet. An ACK/preview is user coordination only, not a last financial authorization or relay veto. Obtain specific owner-local fee-payer transaction approval; persist exact signed transaction/nonce/fee/submission identity before authorized independent submission.
7. **Reconcile actual atomic outcome.** Target verifies both journals/proofs, consumes both eligible backing rights, appends complete recoverable outputs and applies all asset effects atomically or reverts. Both owners observe exact assets/proceeds/residual rights under the selected finality policy; proof/preview/ACK/send/receipt alone is not `Completed`.

### Certificate release is irrevocable exposure

`SamechainAuthority.fill` is permissionless: whoever holds a complete valid packet and both role certificates can submit while the exact packet remains eligible. Exporting one's certificate therefore exposes an authorization that can combine with a counterparty's retained certificate, without a final ACK or the designated taker/fee payer broadcasting. Once both are released, one owner going offline does not revoke the existing packet. This is not maker-offline creation of **new** fills.

Record exposure before export; retain exact bytes and backing fences across restart. Exposure persists until the **chain-enforced packet expiry** or finalized consumption/invalidation of the shared backing capability. Negotiation timer, peer disconnect, timeout, ACK refusal, process cancellation or deletion of a local certificate is **not revocation or an unlock**. A third party may keep copies. An eligible included cancel competes on the same input generation/nullifier; requesting cancel does not invalidate outstanding fills. Multiple packet digests on that generation remain a race until actual chain consumption resolves it.

Packet expiry ends that packet's prospective eligibility, not the order's backing or an already submitted/`Unknown` outcome. Reconcile chain time/current consumption and pending outcomes under the finality policy before freeing any local reservation; previously included effects may exist. Existing retained historical roots do not expire merely from unrelated appends/tree rollover and do not revoke a released packet.

### Full, partial and remainder are V1 requirements

Every settled portion succeeds independently. Outputs must conservatively allocate correct proceeds/fees and only disjoint authorized residual capacity; spent predecessor generation cannot return. Each further V1 fill requires new exact bilateral consent. Cancel/exit operates only on an eligible unfilled/residual right, cannot undo paid fills, and withdrawal must deliver actual correct assets. Company-off recovery covers unfilled, proceeds, partial remainder and pending/`Unknown` states.

## 6. Order Book Synchronization

Late-joining nodes receive bounded advertisements/query responses and revalidate their permitted contents locally. Peer signatures authenticate responses but do not guarantee completeness, freshness, consistent order books or backing. Partitions, omissions, stale/spent advertisements and offline makers are expected adverse cases, not invented terminal outcomes.

Use a bounded volatile cache for rebuildable public hints only. Durable intents/reservations/released bytes and pending outcomes cannot be recovered by asking peers for advertisements. [Storage decision](V1-P2P-STORAGE-DECISION.md) separates existing PostgreSQL public journals, owner-private encrypted files and the unresolved complete node durable design; it neither mandates a DB for every node nor authorizes local SQL/SQLite.

## 7. Resource Limits and Message Validation

### 7.1 Owner-approved freeze and source basis — 2026-10-06

**OWNER-APPROVED NETWORK DESIGN; IMPLEMENTATION NOT CLAIMED.** The owner approved this exact written freeze on2026-10-06, including the financial-expiry agreement in§7.2. These choices supersede the provisional bounds in [research §3–4](research/2026-10-06-phase0-private-discovery-network.md). P0.07's written-design review gate is satisfied; bounded dependency patches, codecs and network qualification are still implementation work. Numeric ceilings are finite admission policies, **not measured RAM, throughput, proof latency or Internet availability**. No code, dependency lock, network permission or financial acceptance changes in this document.

Keep `libp2p =0.56.0` and its current enabled features. Proposed added features are `quic`, `request-response`, `gossipsub`, `mdns`, and optional `relay`, `dcutr`, `autonat`; no DNS, UPnP, floodsub fallback or extra money crate. Source baselines are request-response **0.29.0**, GossipSub **0.49.0**, relay **0.21.0**, DCUtR **0.14.0**, AutoNAT **0.15.0**. These are selected upstream baselines, **not entries already in Cargo.lock**. QUIC **0.13.1**, mDNS **0.48.0**, TLS **0.6.2**, Quinn **0.11.12** and Quinn-proto **0.11.19** are in the current lock, but QUIC/mDNS are inactive. Required bounded patches below follow the existing vendored-Kad convention; their revision/checksum will be recorded in the actual reviewed dependency change, never invented here.

Source facts inspected 2026-10-06:

- [Runtime features](../crates/runtime/Cargo.toml), [lock](../Cargo.lock), [transport](../crates/runtime/src/node/network.rs), [config](../crates/runtime/src/node/config.rs), [bounded peer-only Kad](../crates/runtime/src/node/discovery.rs).
- [libp2p-v0.56.0 workspace versions](https://github.com/libp2p/rust-libp2p/blob/libp2p-v0.56.0/Cargo.toml), [GossipSub config](https://github.com/libp2p/rust-libp2p/blob/libp2p-v0.56.0/protocols/gossipsub/src/config.rs) and [internal collections](https://github.com/libp2p/rust-libp2p/blob/libp2p-v0.56.0/protocols/gossipsub/src/behaviour.rs): `Strict`, manual validation and mesh/queue setters exist; time-based duplicate/backoff retention is not a hard cardinality bound.
- Installed `libp2p-request-response-0.29.0/src/lib.rs:310–372,438–470` ([versioned source](https://docs.rs/libp2p-request-response/0.29.0/src/libp2p_request_response/lib.rs.html)): timeout/stream setters exist; pending outbound map has no global cap.
- Installed `libp2p-mdns-0.48.0/src/behaviour.rs:122–180,283–371` and `behaviour/iface.rs:89–105,266–315` ([versioned source](https://docs.rs/libp2p-mdns/0.48.0/src/libp2p_mdns/behaviour.rs.html)): interface tasks, discovered nodes and queues can grow; the 4096-byte receive buffer alone does not bound retained state or DNS decoding.
- Installed `libp2p-quic-0.13.1/src/config.rs:28–183,transport.rs:590–595` ([config](https://docs.rs/libp2p-quic/0.13.1/src/libp2p_quic/config.rs.html)): stream/window/timeout fields exist, but the wrapper does not expose Quinn server admission settings and calls `incoming.accept()` before Swarm admission. Installed Quinn-proto `0.11.19/src/config/mod.rs:313–358` ([source](https://docs.rs/quinn-proto/0.11.19/src/quinn_proto/config/mod.rs.html)) exposes `max_incoming`, `incoming_buffer_size`, `incoming_buffer_size_total`; Quinn `0.11.12/src/incoming.rs` exposes `retry`, `refuse`, `ignore`, `remote_address_validated` ([source](https://docs.rs/quinn/0.11.12/src/quinn/incoming.rs.html)).
- [Canonical samechain limits/codecs](../crates/protocol/src/samechain.rs), [FillExecution frame2](../crates/protocol/src/samechain/fill.rs), [release capsule bounds](../crates/runtime/src/samechain/release.rs), [wrapped verifier](../crates/proofs/src/artifacts.rs): packet ≤65536 bytes, ≤8 outputs, ciphertext ≤4096 bytes/output, ≤4 fee entries; existing release journal ≤1024 bytes, wrapped owner proof exactly356 bytes. No inference that a discovery relation already exists.

### 7.2 Wire identities and canonical framing

Transport identify stays `/z2z/transport/1.0.0`; peer-only Kad retains its existing source protocol ID. GossipSub negotiates **only** `/z2z/beacon/1` via `protocol_id(..., Version::V1_1)`, not a prefix that silently appends another version. Exactly five allowed topic strings: `/z2z/beacon/1/base`, `/z2z/beacon/1/hevm`, `/z2z/beacon/1/sol`, `/z2z/beacon/1/near`, `/z2z/beacon/1/zec`. Lane IDs are respectively `u16BE(1..5)`; zero and other IDs reject. Topic/lane must agree. This is a discovery namespace, not proof that any lane is implemented. Cross-chain execution requires a separate reviewed message-kind/domain extension; advertising two lanes grants no cross-chain authority.

Beacon payload is exactly `"Z2Z_BEACON\0" || u16BE(1) || lane_id:u16BE || coordination_key_commitment[32]` (**47 bytes**). Commitment is SHA256 of `"Z2Z_BEACON_KEY\0" || coordination_public_key[32]`; it announces a rendezvous key, never a wallet/owner key. No amount, asset, side, order/input/NF, extra field or application timestamp. GossipSub's required author/sequence/signature authenticates the transport publisher. Message ID is SHA256 of `"Z2Z_BEACON_MSG\0" || canonical_author_PeerId_bytes || payload`; authors are Ed25519 PeerIds and canonical bytes must round-trip. A session may use fresh independent coordination keys; the beacon commitment is not proof of their financial authority. mDNS carries only libp2p address records; it cannot manufacture a validated beacon.

Each request/response stream carries one `u32BE(length) || envelope`, then EOF; length excludes the four-byte prefix and includes the signature. Reject excess/trailing bytes, truncation, noncanonical integer/enum encodings, unsupported domain/version/kind and count overflow. No compression, arbitrary extension map, serde/JSON/bincode, proof chunking or private-witness kind. Lengths/counts are u32BE, amounts U256 big-endian fixed32 bytes, other fields fixed as below. Embedded existing financial frames are **unchanged bytes** with their own domain/version/full-exhaustion checks, not serialized again under transport rules.

```
"Z2Z_SESSION\0" || u16BE(1) || lane_id:u16BE
|| chain_context_digest[32] || deployment_digest[32] || session_id[32]
|| initiator_coord_key[32] || responder_coord_key[32] || role_map:u8
|| challenge_i[32] || challenge_r[32] || seq:u32BE || kind:u8
|| sent_at_unix_seconds:u64BE || body_len:u32BE || body || signature[64]
```

`role_map=0` means initiator A; `1` means initiator B; other values reject. The sender's coordination Ed25519 key signs every byte from domain through body, excluding only the stream length prefix and signature. Envelope overhead is **322 bytes** (12-byte domain, two u16, seven32-byte fields, role/kind bytes, seq/length u32, timestamp u64, signature64). `session_id` and each challenge are independently random nonzero32; fresh per session. Bind this transcript to the authenticated direct connection/expected PeerId. The sole bootstrap exception is Hello request: initiator seq0, responder key/challenge all-zero, empty body. Hello response uses responder seq0, fills both responder fields, echoes all initiator/context pins and is signed by the responder. The initiator's next signed message confirms the complete transcript; before that, neither side accepts backing/terms/certificates or starts private work. Established messages have both keys/challenges, unchanged role/context pins and strictly next seq per sender; no wrap. Any changed pin ends negotiation, never triggers re-signing.

| Kind byte | Body contract | Maximum complete envelope |
|---|---|---:|
| 0 Hello | Empty; request/response bootstrap above | 322 bytes |
| 1 BackingChallenge | Exact verifier-selected anchor digest32 + height u64BE; challenge already in header | 362 bytes |
| 2 BackingClaim | Dedicated P0.05 non-executable relation frame; neither OwnerJournal nor financial certificate accepted | 4096 bytes |
| 3 Terms | One existing canonical `FillExecution` frame2; full private Terms/salts prohibited | 131072 bytes |
| 4 Descriptors | Nonzero `expiry:u64BE`, then u32 input count≤2, each u32-length canonical `InputDescriptor`; u32 output count≤8, each u32-length canonical `OutputDescriptor`; canonical role/order and existing ciphertext/fee limits | 131072 bytes |
| 5 Leaf | Role u8 (A=0/B=1) + opaque leaf32 | 355 bytes |
| 6 PacketDigestAck | SHA256 of exact agreed canonical packet32 + exact E-frame digest32 | 386 bytes |
| 7 Certificate | Expected program VKey32 + u32 journal length + canonical journal≤1024 + u32 proof length + wrapped proof exactly356; packet was frozen separately | 1742 bytes |
| 8 Abort | Reason u8: 0 local-stop, 1 invalid-peer-data, 2 capacity, 3 timeout; no free text | 323 bytes |
| 9 Ack | SHA256 of the complete acknowledged signed envelope32 | 354 bytes |
| 10 DKGRound1 | `context_digest[32]` + serialized `dkg::round1::Package` (measured 135 B postcard; complete envelope 489 B) | 512 bytes |
| 11 DKGRound2 | `context_digest[32]` + serialized `dkg::round2::Package` (measured 37 B postcard; per-recipient secret) | 512 bytes |
| 12 DKGFinalCommit | `SHA256(PublicKeyPackage)[32]` | 354 bytes |
| 13 NativeQuote | Exact3244-byte `QuoteV1` coordination body; known domain/version/ID/context framing only, remaining economic layout opaque | 3566 bytes |
| 14 NativeAcceptance | Exact181-byte `Z2Z_NATIVE_ACCEPT\0` v1, role + quote/proposal/intent/predecessor hashes | 503 bytes |

**DKG kinds (amendment approved 2026-10-07, §12.1 of the settlement research; review-fixed):** kinds 10–12 carry the route-1a fresh-J 2-of-2 DKG ceremony and are valid only as established messages (both keys/challenges present, unchanged pins, strictly next per-sender seq; any changed pin ends negotiation). Rules: (1) §7.2's transcript-confirmation gate is clarified to an explicit step for **every** established kind (this refines the 2026-10-07 amendment; it does not change the wire format): the initiator's first established message MUST be the `Ack` carrying `SHA256(signed bytes)` of the signed Hello response — any other first established kind (including kinds 10–12) rejects and ends the negotiation — and only after that confirmation is accepted does either side proceed (the responder performs its first private DKG step only then); (2) each party sends at most one DKGRound1 per session id and an *exact retry* is a byte-identical complete envelope; a second **different** DKGRound1 for the same session id aborts; at N=2 there is no cross-recipient equivocation, the binding that matters is the session/context commitment; (3) DKGRound2 travels only over the direct authenticated connection, is never relayed, and is never persisted to any durable store, retry journal or event stream — session-memory only, zeroized after delivery or abort, and refused unless the peer's DKGRound1 for this session id was received; (4) no dealer kind exists (`generate_with_dealer` stays out); (5) after finalize each side sends kind 12 and both must observe the same digest before any signing session starts; (6) `context_digest = SHA256("Z2Z_DKG_CTX\0" \|\| lane_id:u16BE \|\| session_id[32] \|\| initiator_coord_key[32] \|\| responder_coord_key[32] \|\| chain_context_digest[32] \|\| pool_id:u8 \|\| canonical J-param bytes)`, with the **receiver recomputing and comparing** it on kinds 10–12 and aborting with reason 1 on mismatch — this requires the pool pin and J parameters to be frozen before DKGRound1; (7) the embedded packages are the pinned cohort's postcard encoding (frost-core 3.0.0 `serialization`), the measured lengths above are asserted by tests, and the embedded package must exhaust the body remainder (postcard does not reject trailing bytes; the validator must). Larger cohorts/encodings require a reviewed re-pin.

**Implemented request/response DKG profile:** explicit owner selection of one Ed25519 transport PeerId plus exact caller-supplied pool byte, J-parameter bytes and nonzero chain/deployment digests. Matching exact bytes is not proof of a qualified pool/J/financial construction. Request/response `(kind,seq)` pairs are `Hello(0,0)→Ack(9,0)`, confirming `Ack(9,1)→DKGRound1(10,1)`, `DKGRound1(10,2)→DKGRound2(11,2)`, `DKGRound2(11,3)→DKGFinalCommit(12,3)`, `DKGFinalCommit(12,4)→Ack(9,4)`. The terminal Ack is never acknowledged again. The responder starts private DKG work only after confirmation and selected-peer/context checks; both peers compare final package digests. Up to five signed response frames are cached in guarded session memory for byte-identical retries, without re-running crypto or incrementing sequence. DKG state/private shares are destroyed after final agreement; the retry cache expires after 30s idle and at the 1800s session lifetime. Completion is ephemeral keygen only, not note creation, arming or settlement. Failure closes the session; unspecified/unsolicited responses do not advance it. Local owned buffers are guarded/wiped where ownership permits; libp2p-internal buffer erasure remains unqualified.


**Native quote integration — 2026-10-09:** kinds13/14 now pass the existing codec/body validator and selected-session receiving dispatch. Each frame pins independently retained confirmed-session challenges and exact admitted per-sender slots; no quote-local counter reset. With no DKG, native proposal/user acceptance/solver acceptance occupy S1/U3/S3, with ACKs U2/S2/U4; after the implemented DKG profile they occupy S5/U6/S7. ACK means admitted coordination bytes, never acceptance or financial authority; exact retries reuse guarded signed ACKs, terminal ACK is not re-ACKed. `NativeQuoteSessions` exposes explicit owner-selected registration/outbound/receiving APIs. The ordinary run-node has no owner quote control bridge yet, so unselected quote traffic rejects. No economic source/beneficiary/grant interpretation of the opaque quote layout, source-authority release, proof/finality or financial completion follows.

**Financial expiry agreement:** each owner independently selects/approves the exact nonzero packet expiry under its local financial policy, never derives it from the advisory session timestamp or negotiation timeout. Both roles exchange and agree byte-identical `expiry:u64BE` in Descriptors **before Leaf or PacketDigestAck**. Reject zero, any mismatch with locally selected expiry, or any later changed expiry; do not choose min/max, silently amend it or re-sign. Each owner reconstructs the existing canonical `PublicPacket` with that exact expiry, independently selected deployment, ordered inputs/outputs and agreed E; its body B (without terminal C) therefore commits expiry before the salted leaves/aggregate C are computed. Reconstruct the complete packet with C and require exact packet/E digests from both roles before backup/readback or consent. Reuse [PublicPacket validation/encoding](../crates/protocol/src/samechain.rs) and [Fill2 context binding](../crates/protocol/src/samechain/fill.rs), not a second expiry rule. A matching transport ACK cannot replace this financial agreement or change chain-enforced expiry/release-reconciliation semantics.

BackingClaim's 4096-byte envelope is a **transport ceiling**, not an asserted proof size or approved P0.05 relation codec. Disabled until its own reviewed dedicated codec/verifier fits that ceiling; unsupported lanes/kinds reject rather than send unverifiable placeholders. The global 131072-byte ceiling also bounds Terms/Descriptors, whose individual existing canonical frame cap is65536 bytes. Certificate does not concatenate packet+E+two proofs: reuse the previously agreed packet and send each role certificate separately. Larger future proof systems require reviewed versioned bounds, never a fallback accepting arbitrary blobs. Transport ACK is not consent, backing, revocation or settlement.

### 7.3 Application admission, clocks, caches and queries

All rates below are token buckets using monotonic elapsed time, initially full, with no accumulating credit beyond burst. Byte counts include length prefixes. Reserve capacity **before** allocating the body, spawning work, admitting a session or calling `send_request`; release permits on success/error/timeout/cancellation/drop. Saturation rejects/drops new work; it never evicts financial fences or waits in an unbounded queue.

| Resource | Selected policy |
|---|---|
| Connected peers | Existing `max_peers`: default8, allowed1–64; same lifetime distinct-peer cohort, one established connection per PeerId, pending incoming/outgoing each≤max_peers. No unbounded historical-peer map or automatic rotation. |
| Sessions | 4 global, 1 per PeerId including Hello; no waiting sessions. 30s Hello/message timeout, 1800s total monotonic negotiation lifetime. Proof work does not extend it; expiration stops networking, not release fences. |
| Request-response | `with_request_timeout(30s)`, `with_max_concurrent_streams(8)` per handler; global outbound16, inbound unanswered8. Custom codec shares an 8-slot inbound permit pool acquired by non-waiting admission before body allocation, held through response closure. Responses stay charged to outbound permits. No arbitrary-peer auto-dial through `send_request`; only admitted connected peers. |
| Framing/work queues | At most24 request/response frame buffers globally (8 inbound+16 outbound), each≤131076 bytes; associated pending events≤32. Validation queue32, 2 active public signature/proof verifications; reserve before enqueue. Maximum32 network events per poll before yielding. Library events/handler queues must be patched if these limits cannot be enforced before insertion. |
| Request rate | Per admitted peer 4 frames/s burst8, global16/s burst32; bytes per peer262144/s burst524288, global1048576/s burst2097152. Global pre-session admission1 Hello/s burst4; peer Hello1/30s burst1. Reject before signature/proof work. Rate maps are restricted to the finite cohort; no attacker-IP map. |
| Private work | Peer input cannot invoke secret reads/signing/proving. Owner-selected local action only; at most1 owner prover job, no peer-triggered prover queue. Existing resource/privacy gates still apply. |
| Timestamp | Mandatory session u64 Unix seconds; checked absolute difference≤300s without overflow for new messages. Invalid local wall clock fails new session admission. Wall clock is advisory coordination filtering only; monotonic timers govern retention. It never sets packet expiry, finality, claim/refund eligibility or release unlock. |
| Session dedup | SHA256(envelope); at most1024 unique envelopes total per session, including ACK/control. Keep sequence/digest entries until session end; no eviction that permits old seq acceptance. Exact retry is idempotent, not new owner work. At most16 exact outbound retry frames/session; maximum3 retries/message, all within the30s message deadline. ACKs are not recursively ACKed. Replay of an already known digest remains idempotent even if its advisory timestamp aged; unknown stale frames reject. At1024 unique frames close negotiation rather than forgetting history. |
| Beacon hint cache | ≤256 (author,lane) entries; local monotonic TTL120s from first validated admission, no duplicate-based extension. New valid content replaces that key. Expire first; at capacity evict earliest expiry, tie-break canonical(author,lane). This is a hint cache, never a backing/release journal. Local publish at most1/lane/60s; cap all lanes at5. |
| Gossip admission rate | Per connected forwarder2 RPC/s burst4; global16/s burst32, before protobuf decode/signature validation. Cache/queue admission must precede retained clones. |
| Queries and sync | No public order-term query or inventory download. Public synchronization is bounded beacon propagation plus peer-only Kad. Keep one active owner-selected Kad query, parallelism1, result≤min(max_peers,20), candidate set≤max_peers, one address≤256 bytes/peer,4096-byte packet,10s query/5s substream. No records/providers, periodic bootstrap or auto-refresh. Subsequent lookup requires explicit local selection, at most1/30s; no peer-triggered recursive queries. Inbound FIND_NODE budget per peer1/s burst2 and global8/s burst16, before result assembly; vendor patch required if not enforceable at that point. |
| Reconnect | Preserve configured expected-peer policy: three accepted lifetime retries per configured peer, delays1/2/4s, at mostone pending direct attempt per peer. Kad, mDNS and relay candidates share cohort/admission accounting; no alternate retry loop. |

### 7.4 Required dependency hardening, not configuration claims

**GossipSub:** configure mesh target6/low4/high8/outbound-min2, retained-score count4, gossip-lazy6, heartbeat1s, history5/gossip3, duplicate TTL120s, fanout TTL60s, prune backoff60s, unsubscribe backoff10s, retransmission3, max messages/RPC4, IHAVE lists≤32 IDs and≤4 IHAVE messages/heartbeat/peer, handler queue16. Use `Strict`, signed transport author, manual validation, identity transform, allowlisted five topics, no PX, flood-publish or floodsub fallback. RPC encoded body≤4096 bytes; application beacon payload exactly47 (1024 is only a rejected-shape/control upper guard, never permission for extra fields).

**Required vendored GossipSub patch before enablement:** byte cap at the frame reader before allocation; bounded protobuf decoding before repeated-field allocation:≤4 published messages,≤5 subscriptions,≤16 control records total/RPC,≤32 IDs/control record, exactly32 bytes/ID, topic≤32 bytes from the allowlist. Reject whole malformed/oversized RPC, not parse then truncate. Bound duplicate and published-ID caches independently to1024 entries, message cache≤256 payloads across all history buckets, validation pending32, behavior events32, gossip promises≤1024 entries with≤64 recipients each. Evict earliest-expiry duplicate/publication/message entries before inserting (lost hints are acceptable); reject new validation/promise work at capacity. Peer-keyed state only for the lifetime cohort≤64; mesh/fanout each≤8 peers/topic **before insertion**, backoff≤5×64(topic,peer) entries, retained subscriptions≤5/peer. GRAFT oversubscription is rejected/pruned immediately, not temporarily admitted until heartbeat. No TTL-only memory-bound claim; all internal queues, IDONTWANT/IWANT bookkeeping and failure counters share these caps before growth.

**mDNS:** select a focused vendored0.48.0 patch, not a claim that `Config` has these setters. Default off; separate owner LAN permission plus an explicit allowlist of at most4 local interface addresses. Check that allowlist and reserve one of4 task slots **before** `InterfaceState::new` opens sockets or `P::spawn`; remove/abort on interface-down and drop. Ignore excess interface notifications without spawning. Keep its fixed4096-byte receive buffer; reject truncated/oversized datagrams and preflight DNS header counts (≤32 total questions/resource records), decoded name≤255 bytes, compression jumps≤16 with cycle rejection, returned peer addresses≤8/datagram and≤256 bytes/address **before** collecting/cloning. Per-interface discovered/send queues≤16, send datagram≤4096, shared result queue≤16 including sender-reserved slots, listen addresses≤4, behavior events≤32. Retain≤64 peer/address entries, one selected address per peer; conflicting extra addresses reject. TTL is `min(remote TTL,120s)`; refresh sets at most now+120s. Expire then evict earliest expiry (tie canonical peer/address) before inserting. Global receive32datagrams/s burst32 and transmit8/s burst8; per-interface receive8/s burst8 and transmit2/s burst2, checked before decoding/response generation. Drain at most16 items/poll, never unbounded drain/extend. Apply cohort/candidate/address admission before dialing; authenticate the expected PeerId via Noise/TLS+identify before using the connection. LAN address acceptance is a separately enabled local-scope policy, not a relaxation of the existing public Kad address filter. No financial terms or custom DNS-record wire extension.

**QUIC:** configure `max_concurrent_stream_limit=8`, `max_stream_data=131072`, `max_connection_data=262144`, `handshake_timeout=10s`, `max_idle_timeout=30000`ms, `keep_alive_interval=10s`; unidirectional streams/datagrams/migration remain disabled. Its TLS authenticates PeerId; never add Noise on top. **Required vendored wrapper patch:** set Quinn server `max_incoming(8)`, `incoming_buffer_size(4096)`, `incoming_buffer_size_total(32768)` and endpoint `max_udp_payload_size(1200)` (disable MTU discovery for this initial bounded profile); cap transport send window262144 and crypto buffer16384. The incoming-buffer limits exclude the first packet, so account for up to8×1200 first-packet bytes separately, not as a full-process memory bound. Before `incoming.accept()`, reserve a shared transport admission slot:≤8 concurrent QUIC handshakes, all transport pending work still within global peer limits. At capacity `ignore()` without allocating handshake state; require Retry/address validation first for unvalidated addresses. Permit remains owned through the handshake's success/failure/drop, and established state stays in the shared cohort. Accept budget global4/s burst8, no per-source unbounded map. Swarm connection limits alone are too late for this path; UDP/kernel buffers, crypto and task overhead still require qualification.

**Relay/DCUtR/AutoNAT:** optional client use only, at most2 owner-configured independent relay peers (each counts in the peer cohort), one reservation/relay, global2 concurrent introductions, one hole-punch attempt/target and3 attempts/target/process,10s attempt deadline. Do not serve relay or AutoNAT dial-back requests in this node profile. AutoNAT client probes only the configured independent peers, at mostone active, one/minute,10s deadline; no behavior-provided arbitrary dial addresses. Any internal task/list/queue must share those permits before allocation/spawn; focused patch required where upstream behavior cannot expose that admission point. Limit each introduction circuit locally to120s/131072 bytes or the relay's smaller negotiated allowance; close on either ceiling. These are client policies, not settings we can impose on an independent relay. Direct authenticated transport is required before `/z2z/session/1`; reconnect resumes exact retained message bytes only while session lifetime/bindings remain valid. No direct path means explicitly unreachable, never mandatory paid/company relay or universal NAT reachability.

### 7.5 Review and implementation acceptance boundary

Owner approved the finite freeze above, including required vendored bounds rather than pretending upstream configuration closes them. Before enabling each behavior, its implementation must demonstrate boundary/overflow/trailing-byte rejection **before allocation**, saturation before task creation, deterministic cache eviction, no historical-map growth, timer expiry/cancellation releasing permits, and malformed/adversarial burst handling with generated peers. Golden wire bytes must cover every kind and unknown versions, Hello pin/challenge substitution, seq replay/idempotency, clock skew, oversized packet/certificate separation and no witness/financial-key access. mDNS task churn/DNS compression bombs, GossipSub collection/control floods and QUIC unvalidated-Initial floods require the patched admission seams, not merely successful two-peer exchange. These are required future checks, **none run here**. LAN/WAN/UDP/multicast/relay actions still need explicit permission; strict GD2, durable release/restart, genuine proof/target/resource and funded journey gates remain unchanged.

## 8. Privacy Considerations

**Strict GD2 is an unmet gate in the current design.** Three channels each break content and accepted-identity noninference against a matcher colluding with a legitimate trader:

1. The counterparty receives the exact terms.
2. Public NF, order and tree locators identify the accepted maker onchain.
3. Own-result delivery distinguishes adjacent worlds.

Cross-chain HTLC adds a public shared hash linking both chains, which is a privacy cost, not acceptable leakage. Bilateral-only audience is data minimization, **not a privacy waiver** and not a substitute privacy product. Closure requires a reviewed construction that passes the finite adjacent-world experiment (kill criteria K1–K3) under the unchanged adversary.

Signatures, transport encryption, separate coordination keys and decentralization establish no anonymity or unlinkability. A fresh coordination key per session limits cross-session linkage only. Keys, FVK/spend/nullifier secrets, note openings, private policy, recovery capabilities and proof witnesses stay owner-local. There is **no witness exchange, even encrypted**, and no paid/cloud/shared-prover fallback.

## 9. Failure Modes and Financial Lifetimes

| Failure | Required behavior |
|---|---|
| Seed/NAT/partition/unreachable peer | Bounded discovery/reconnect using independent reachable peers; no promise of fresh internet discovery without an address. |
| Maker offline before fresh consent | Cannot create a new V1 fill. Previously released exact authorizations retain their eligibility/exposure; going offline is not cancel. |
| Negotiation timeout/ACK refusal | Stop bounded coordination work only; retain release records and financial fences. |
| RPC/history unavailable or contradictory/reorged | Keep pending/`Unknown`, require independent pinned reconciliation; do not unlock or fabricate cancellation/payment. |
| First proof valid, second invalid / transfer fails | Roll back both consumption/output/payment legs; preserve only actually eligible unchanged retry rights. |
| Crash/stale backup after certificate export or send | Restore exact bytes, reservations and release/submission state; reconcile current NF/generation/outcome before new use. |
| Competing fills/cancel or replay | At most one shared capability consumption wins; retain correct successor rights, never revive predecessor backing. |

## 10. Implementation Ownership

Compose the existing five crates per [MODULES](MODULES.md): protocol canonical rules/descriptors; proofs owner-local relations/artifacts; chains pinned inspection/call construction; runtime node lifecycle/coordination/storage/CLI. Prefer focused runtime node modules; no speculative sixth `crates/p2p` or second financial runtime is required.

P0.07 owns dependencies/features and future module/config/wire decisions; §7 records their exact owner-approved design freeze. It does not claim required dependency patches, config flags or codecs are installed, select public RPC services, or authorize opening peer ports. Existing journals/private files and funded program/setup/verifier identities must remain usable.

## 11. Required Qualification Scenarios — Not Run Here

Microplan acceptance includes bounded authenticated gossip/query/sync, reconnect/partition/seed replacement, malformed/replayed frames, independently reviewed backing/disclosures, exact public descriptor assembly **before** both role proofs, private-owner isolation, full/partial/remainder/cancel/withdraw and independent company-off recovery. Adverse cases must include certificate export before ACK, withheld ACK, offline owner after full authorization, timeout/crash/restart/`Unknown`, competing fills/cancel, wrong-role/packet/domain proofs, valid-first/invalid-second proof, transfer failure and valid retry.

Use actual generated-key crypto for permitted tests, then genuine wrapping/exact target qualification and separately approved real testnet assets for funded acceptance. A mock verifier, CPU journal, cache label or network simulation does not replace real proof/asset/recovery evidence. SQL runs require approved private URI/scope; no local SQL checks. This document reports no run or passed check.

## 12. Scope and Active Parallel Obligations

The first passing journey (samechain; Base Sepolia is the engineering default) requires:

- a long-running P2P node/CLI with neutral beacon and direct RFQ
- independently checked `BackingClaim` backing
- both owners online with fresh exact consent for new fills
- genuine owner-local proofs
- atomic full/partial/proceeds/remainder, cancel and withdraw
- durable restart/`Unknown`
- full company-off recovery

**Active parallel obligations, not V2:**

- **L-ZEC** native (S1–S7/M1–M5 unchanged; wrapped ZEC never substitutes).
- **L-HEVM, L-SOL and L-NEAR** sessions, using the same envelope with lane-specific chain context, replay, finality and release adapters.
- **X.CROSSCHAIN** across all pairs: HTLC first, which is **not atomic**. The responder's exposure window, per-pair deadline inequality, durable preimage fence and claim/refund exclusion are in the research report §5.1.

Standing-maker offline fills, GUI, Intents/1Click and mainnet remain V2. Strict GD2 remains an unmet active gate.

## 13. Relation to Existing Code and Evidence

Existing canonical descriptors/owner relations, public call builders, pinned inspection, immutable authority and owner prover are reusable primitives; their detailed exercised limits belong to [native status](NATIVE-IMPLEMENTATION-STATUS.md), not a new network completion claim here. Relevant sources include `crates/protocol/src/samechain.rs`, `crates/proofs/src/samechain.rs`, `crates/chains/src/samechain.rs` and `contracts/evm/src/SamechainAuthority.sol`.

Current primitives do not by themselves implement reviewed private/backed discovery, public bilateral packet negotiation, full durable node state, qualified wrapped/funded lifecycle or cold recovery. Trace exact existing relation/call contracts before extending them; preserve deployed/funded versions and action permissions.

**Historical pre-cutover common-opening gap:** fill1 required both complete Terms policies and a common blind in each OwnerWitness, so public descriptors alone could not construct independent witnesses. This describes preserved legacy source/artifacts, **not current Fill2**; no fresh reviewer or encrypted exchange was an acceptable workaround.

**Current implemented Fill2 native contract, qualified only within the checkpoint's scope:** [reviewed construction](superpowers/specs/2026-10-06-independent-owner-fill-design.md) and actual [protocol hashes](../crates/protocol/src/samechain/fill.rs), [witness/relation](../crates/proofs/src/samechain.rs), [CLI](../crates/runtime/src/samechain.rs), [guest](../crates/proofs/methods/samechain/src/main.rs) and [target codec](../contracts/evm/src/SamechainCodec.sol) replace the whole fill opening with owner-only salted policy leaves and the common B/E/ordered-leaf aggregate. Current source has completed independent relation/consumer reviews with no findings; [native status](NATIVE-IMPLEMENTATION-STATUS.md) exclusively owns actual independent-process/new-guest CPU/program/target correspondence evidence and limits. Mode0 is byte0 + one embedded-packet OwnerWitness frame2, not an old redundant packet prefix. Only Fill witness/relation changes to2; outer journal/packet/schema, note/order/policy/tree/AEAD/ciphertext and creation/single-owner/withdrawal/blinds remain1. Preserve original fill1 artifact identities; separately pinned new ELF/program requires authorized new immutable authority and genuine all-mode wrapping/target/recovery qualification, no conversion or asset migration. Independent source/setup/program qualification remains UNVERIFIED. Native counterparty-private-opening availability is addressed, not full P2P negotiation/durable backup, GD2, advertised backing, genuine proofs or funded/company-off acceptance; opaque leaves do not prove backing or quantity secrecy.

## 14. Open Construction Prerequisites and References

- **P0.04:** complete durable node/release/restart contract spanning bounded hints, PostgreSQL public journals and encrypted owner files; SQL URI/scope remains held.
- **P0.05:** proposed `BackingClaim` relation and field-by-field disclosure (research §2). Strict GD2 is unmet; the finite K1–K3 experiment is defined.
- **P0.06 / P3.03–P3.08:** proposed `Z2Z_SESSION` envelope and durable state machine (research §3) over the implemented Fill2 assembly. Durability is held behind P0.04.
- **P0.07:** exact freeze in§7 supersedes provisional research§4 bounds; **owner approved written network design on2026-10-06**. Required bounded dependency patches/feature/lock additions are future reviewed implementation; no implementation/readiness claim and LAN/WAN/UDP/multicast/relay hosting remains held.
- **Lanes / X.CROSSCHAIN:** per-lane contracts and the CX-1 HTLC with kill criteria XK1–XK4 and model check V1–V3 (research §5). CX-2 proof-verified release is research.
- **P1.23 / P4.05:** all-mode genuine local wrapping/exact target/privacy/resource qualification and pre-funding backup/cold restore.
- **P0.03 / P0.09–P0.11 / P5.01–P5.03:** exact public testnet/assets/finality/deployment pins and specific network/SQL/secret-use/deployment/signing/funds permissions.

Use the [active prompt](Z2Z-V1-IMPLEMENTATION-SYSTEM-PROMPT.md), [microplan](V1-MICRO-IMPLEMENTATION-PLAN.md), [architecture decisions](V1-ARCHITECTURE-DECISIONS.md), [storage decision](V1-P2P-STORAGE-DECISION.md), [SERVER-INDEPENDENCE](SERVER-INDEPENDENCE.md) and [SQL-VERIFICATION](SQL-VERIFICATION.md). External [libp2p documentation](https://docs.libp2p.io/) and [GossipSub specification](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/README.md) are research references, not installed-version or performance evidence.

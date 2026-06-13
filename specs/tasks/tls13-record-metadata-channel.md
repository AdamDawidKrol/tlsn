# Task: TLS 1.3 record metadata channel + prover inner-plaintext recovery (`tlsn`)

Parent spec: `specs/tls13-proxy.md` §6.1, §7.3, open-question §5.
Work-breakdown **item 8b** — the prover→verifier per-record metadata channel that
makes the item-8 finalize flows produce a *correctly framed* TLS 1.3 application
transcript on both sides. This is the last functional gap before TLS 1.3 proxy
sessions work end-to-end; item 9 then only owns the 1.3-enabled fixture, the
client version-list flip, e2e/negotiation tests, and the bench.

Scope: `crates/tlsn` (`src/proxy/prover.rs`, `src/proxy/verifier.rs`,
`src/prover/client/proxy/keylog.rs`, `src/msg.rs`, `src/prover/prove.rs`,
`src/verifier.rs`, `src/verifier/verify.rs`, `src/transcript_internal/auth.rs`)
plus the 1.3 record parser in `crates/core`
(`src/transcript/tls/builder.rs`, `src/transcript/tls.rs`).

## 0. Problem statement (why this is needed)

In TLS 1.3 every application-epoch record is wire-typed `application_data(23)`;
the **real** content type is the last non-zero byte of the *decrypted inner
plaintext* `content || inner_type(1) || zero_padding`, and the content length is
hidden by the padding. Three concrete consequences are unhandled today:

1. **Prover feeds the wrong bytes.** `ProxyProver::finalize_v1_3`
   (`crates/tlsn/src/proxy/prover.rs`) passes rustls's *content-only*
   `traffic.app_sent` / `traffic.app_recv` to the builder, but
   `parse_records_tls13` (`crates/core/src/transcript/tls/builder.rs`) expects
   the **inner plaintext** stream (each record's slice has length `ct_len =
   inner_len`, i.e. content + type + padding). Content-only data desynchronizes
   the per-record split and the build fails / is wrong.
2. **Verifier has no framing.** With `app_data = None`, `parse_records_tls13`
   emits every app-epoch record as `typ = ApplicationData`, `plaintext = None`,
   and no content length. So the verifier cannot (a) tell `NewSessionTicket`
   (inner type `0x16`) apart from real app data, nor (b) know where content ends
   per record. `verify::content_len` (`crates/tlsn/src/verifier/verify.rs`)
   therefore returns the wire-ciphertext length (an over-estimate), and
   `RecordParams::from_records` (`crates/tlsn/src/transcript_internal/auth.rs`)
   falls back to `content_len = inner_len`.
3. **Suffix proof assumes app-data only.** Item 7's `alloc_suffix`
   (`auth.rs`) hardcodes the inner-type byte as
   `APPLICATION_DATA = 0x17`. A `NewSessionTicket` (or alert) record's suffix
   would be `0x16 || 0x00*` and **fail** the consistency proof. The suffix
   mechanism must carry the *declared* inner type.

This task supplies the missing per-record metadata `(inner_type, content_len)`
on both sides and makes the prover recover the inner plaintexts it needs.

## 1. Prover side: recover inner plaintexts

The prover must decrypt the app-epoch records to obtain, per record, the inner
plaintext `content || type || padding`, then feed the **concatenated inner
plaintext stream** (per direction) to the builder instead of rustls's
content-only stream.

### 1.1 Where the app keys come from

Two options; **recommended: capture the application traffic secrets** (smallest,
reuses item 1's `KeyLog` hook):

- **(Recommended) Extend item 1's `SecretLog`** (`prover/client/proxy/keylog.rs`)
  to also record `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0` (rustls
  *does* export these via `KeyLog`, unlike `handshake_secret`). Add them to
  `CapturedSecrets::V1_3` (e.g. `client_ap_traffic_secret`,
  `server_ap_traffic_secret: [u8; 32]`). The prover derives the 1.3 application
  write keys/IVs from these with the existing cleartext HKDF-Expand-Label helper
  in `crates/core/src/transcript/tls/tls13.rs` (`traffic_keys`) and decrypts.
- **(Alternative) Re-derive in cleartext** from the already-captured
  `handshake_secret`: `master_secret = HKDF-Extract(Derive-Secret(hs,"derived",
  ""), 0)`, then `c_ap/s_ap = Derive-Secret(master_secret, "c/s ap traffic",
  h3)`. The prover has `handshake_secret` and `h3`. This avoids touching item 1
  but duplicates a few HKDF steps already done in ZK.

Either way the **ZK** path is unchanged — the application keys used for the
proofs are still the ZK-derived `refs.keys13` from `KeySchedule13`. The captured
/ re-derived cleartext keys are used **only** by the prover to decrypt records so
it can frame the transcript. (A consistency check is automatic: the inner
plaintexts must AEAD-match the wire ciphertext, else decryption fails.)

### 1.2 Decrypt and feed the builder

Add a cleartext helper (next to `tls13::decrypt_record` from item 5, which
already does AES-128-GCM-in-the-clear for the handshake epoch) that decrypts the
application-epoch records with the app keys, yielding each record's inner
plaintext. In `finalize_v1_3`, build the concatenated inner-plaintext streams and
pass them as `app_sent`/`app_recv` so `parse_records_tls13` frames `Record.typ`
(inner type), `Record.plaintext` (content), and the content boundary correctly.

> Note on epochs/seq: app-epoch sequence numbers restart at 0 per direction
> (parent §6.1). `decrypt_record` builds the nonce from `write_iv XOR (0^4 ||
> seq_be64)`. Reuse item 5's `app_start` boundary so the handshake-epoch records
> are excluded.

## 2. The metadata channel (prover → verifier)

The verifier cannot decrypt (its app keys are blind in ZK), so the prover must
**declare** the per-record framing. Define:

```rust
// crates/tlsn/src/msg.rs (or a small module reachable by proxy + verify)
pub(crate) struct Tls13RecordMeta {
    pub typ: u8,          // inner content type (RFC 8446 §5.1): 0x17 app data,
                          // 0x16 handshake (NewSessionTicket/KeyUpdate), 0x15 alert
    pub content_len: u32, // inner content length (== inner_len - 1 - padding)
}

pub(crate) struct Tls13Metadata {
    pub sent: Vec<Tls13RecordMeta>,  // app-epoch records, sent direction, in order
    pub recv: Vec<Tls13RecordMeta>,  // app-epoch records, recv direction, in order
}
```

`inner_len` is already known to the verifier from the wire (`record.ciphertext.
len()`), so `padding_len = inner_len - 1 - content_len` is derived, not sent.

### 2.1 Delivery

The verifier frames its transcript in `finalize` (before the `verify` exchange),
so the metadata must arrive **before/at finalize**. Deliver it over the existing
prover↔verifier mux stream that proxy mode already uses for traffic
(`crates/tlsn/src/verifier.rs`, `Verifier<CommitAccepted<Proxy>>::run`): after
the copy loop closes, have the prover send one framed `Tls13Metadata` message and
the verifier read it before calling `verifier.finalize(..)`. Only send it when
the negotiated version is 1.3 (the prover knows from `conn.protocol_version()`;
the verifier knows from `peek_tls_version_and_sh_hash`, so it only *expects* the
message for 1.3).

> Alternative seam: piggyback on `ProveRequestMsg` (`src/msg.rs`, already carries
> `request, handshake, transcript`) and reframe records at `verify` time. This is
> viable because nothing before `verify` needs `content_len` — `verify_tags`
> covers full ciphertext+tag and is content-length-agnostic. Choose this if
> threading a message into the finalize seam proves awkward; it keeps the change
> inside `verify.rs`. **Pick one and document it.** The finalize-time delivery is
> cleaner (records are correct everywhere downstream); the `ProveRequestMsg`
> delivery is a smaller diff. Recommended: finalize-time.

## 3. Verifier side: frame records from metadata

Thread `Tls13Metadata` into the 1.3 builder path so the verifier's records carry
the right `typ` and a known content length even though `plaintext` stays `None`:

- Add an optional metadata input to `TlsTranscriptBuilder` (e.g.
  `.tls13_record_meta(meta)`), consumed by `parse_records_tls13` when
  `app_data` is `None`: set `Record.typ = inner_content_type(meta.typ)` and store
  the content length.
- **Carry content length on the record.** `from_records` currently derives
  `content_len` from `record.plaintext` (None on the verifier). Add
  `content_len: Option<usize>` to `Record` (`crates/core/src/transcript/tls.rs`),
  set by the prover (`= plaintext.len()`) and by the verifier (`= meta.content_len`).
  Update `RecordParams::from_records` to prefer `record.content_len` when present
  (keeping the `plaintext`/`inner_len` fallbacks for 1.2 and existing unit tests).

This makes `verify::content_len`, `collect_ciphertext`, the `typ ==
ApplicationData` filters, and `PartialTranscript::new` sizing all consistent on
the verifier (replace the over-estimate `content_len()` TODO with the metadata
sum over app-data records).

## 4. Generalize the suffix proof to the declared type (item 7 follow-up)

In `auth.rs`, `alloc_suffix` must assert the *declared* inner-type byte rather
than the hardcoded `0x17`:

- Thread the per-record inner type into `RecordParams` (new field `inner_type:
  u8`, defaulted to `0x17` for the existing 1.2/test constructors) and have
  `build_cipher_refs` pass `record.inner_type` to `alloc_suffix`, which assigns
  the public suffix `inner_type || 0x00*padding`.
- The software reference path (`tls13` arm of the keystream/consistency check,
  ~`auth.rs:715`) already reconstructs `content || APPLICATION_DATA || padding`;
  change it to use the record's `inner_type`.
- Result: a `NewSessionTicket` record (declared `0x16`) gets a suffix
  `0x16 || 0x00*` that matches its wire ciphertext; a prover that mis-declares
  the type or content boundary fails the consistency proof.

## 5. Classification & soundness — DECISION (locked)

The verifier classifies app-epoch records by inner type: `ApplicationData(0x17)`
counts toward the transcript; `Handshake(0x16)` (NewSessionTicket, post-handshake
KeyUpdate) and `Alert(0x15)` are excluded from the application transcript (parent
§6.1).

**Decision (locked): the verifier ZK-proves the inner type of _every_ app-epoch
record and classifies on the proven value.** Rationale: TLSNotary guarantees
*authenticity of revealed bytes*, not *completeness*, but record classification
feeds the attested transcript **length and byte positions** — a prover that
mislabels a real `application_data` record as `handshake` could drop it and shift
positions. Proving each record's true inner type removes that lever entirely; the
prover cannot mislabel a record without failing its suffix consistency proof.

Implementation consequences:

- Run the `type || padding` suffix proof over the **full** app-epoch record list
  per direction, not only the records declared `application_data`. Item 7 invokes
  the suffix mechanism only for the `typ == ApplicationData`-filtered set in
  `verify.rs`; extend it so non-app-data records (NSTs, KeyUpdates, alerts) also
  get their `inner_type || padding` suffix allocated, publicly assigned, and
  checked against the wire ciphertext.
- The verifier sets each record's `typ` from the **proven** suffix type byte (the
  metadata `Tls13RecordMeta.typ` is a prover *hint* that the proof validates, not
  trusted input). The application transcript and the app-data plaintext-proof set
  are then derived from the proven classification.
- Cost is a handful of extra public-suffix bytes per non-app-data record; NSTs
  are few (typically ≤2 per session), so the overhead is negligible.

This is recorded in parent open-question §5.

## 6. Tests

Land hermetic unit/integration coverage that does **not** need the item-9 fixture:

- **Prover inner-plaintext recovery**: given known app keys + synthetic 1.3 app
  records (incl. a NewSessionTicket and a padded record), the decrypt helper
  yields the right inner plaintexts; the builder frames `typ`/`content_len`
  correctly.
- **Metadata round-trip**: `Tls13Metadata` (de)serialization; verifier framing
  from metadata reproduces the prover's `typ`/`content_len` per record.
- **Generalized suffix**: extend the existing `auth.rs` 1.3 tests
  (`test_verify_plaintext_with_key_tls13`) with a record whose `inner_type =
  0x16` — passes with the correct declared type, fails when mis-declared
  (mirrors the existing `BadType`/`BadPadding` defect cases).
- **content_len wiring**: `verify::content_len` over metadata-framed records
  equals the sum of declared content lengths (not the wire length).
- **NST filtering**: a recv stream with an interleaved NewSessionTicket is
  excluded from the application transcript and from the plaintext proof's
  app-data set, while still tag-verified by `verify_tags` (which covers all
  records).

Full live 1.3 e2e (real fixture, version-list flip, negotiation matrix) stays in
**item 9**.

## 7. Acceptance criteria

- `cargo build -p tlsn -p tlsn-core`, `cargo clippy -p tlsn -p tlsn-core
  --all-targets` clean; `cargo fmt` applied. (`mpz-circuits-data` build script
  writes outside the workspace — build/test may need unsandboxed permissions.)
- TLS 1.2 behavior unchanged: `cargo test -p tlsn`, `-p tlsn-core` pass; the
  ignored `test_proxy` (1.2 e2e) still passes; `Record`'s new field defaults
  leave 1.2 framing identical.
- The prover recovers inner plaintexts and frames a correct 1.3 transcript; the
  verifier frames an equivalent transcript from the metadata channel alone (no
  plaintext); the generalized suffix proof validates per-record `type` +
  content boundary, including NewSessionTickets.
- `verify::content_len` reflects validated content lengths; the `content_len()`
  TODO in `verify.rs` and the `from_records` 1.3 fallback comment in `auth.rs`
  are resolved.
- Parent open-question §5 (padding/classification) is updated with the chosen
  soundness model (§5 above). The work-breakdown row 8b is marked done; item 9's
  row no longer claims the metadata channel.

## 8. Out of scope (item 9)

- Enabling TLS 1.3 in `tls-server-fixture` and flipping the client
  `with_protocol_versions` to `&[&TLS13, &TLS12]`.
- The live prover↔verifier 1.3 e2e test and the negotiation matrix.
- The dual-allocation cost bench (parent open-question §2).

# Domain identity and replay

Accepted convergence contract. The event signing domain KDF, ADR-036 bytes,
bech32 HRP, event body codec and native H(compressed public key) are unchanged.
An analytics graph is a derived multi-subject index, not a Cell or a signer.
The event-only library uses mudra's small ID/authentication boundary and never
depends on neuron execution, a GUI or a provider.

New encrypted stored events retain their exact public key, signature, nonce,
client difficulty, accepted server work target and signer HRP alongside the
original body. Replay verifies body hash, frame owner, address/signature binding
and accepted proof-of-work before deriving the same native subject as ingestion.
Server attribution stays an observation and is not client-signed.

Old payload rows without that provenance stay in analytics history under their
original bech32 subject. Their native public key was not persisted and cannot be
recovered by hashing the address. They are counted as legacy/unresolved in the
graph provenance report and do not fabricate a native signal chain. No old file,
address, key or encrypted frame is rewritten or dropped by this migration.
Even when a later event supplies a valid key, it does not retroactively sign old
payloads. The native projection includes only provenance-verified rows.

Malformed decrypted payloads, mismatched frame subjects, changed hashes and
invalid retained signatures fail replay before the server starts accepting new
events. Existing intentionally crypto-shredded frames remain unreadable under
the payload store's erasure profile. Replay constructs temporary indexes and
publishes them only after all readable rows validate; it is idempotent.

The local native index is an observation derived from verified events, with its
existing local network label and ordering codec. It is not a fresh NSIG1 action
on behalf of a visitor and is never automatically relayed as such. Cohort table
cells in inf report formulas are ordinary table terminology and remain unchanged.

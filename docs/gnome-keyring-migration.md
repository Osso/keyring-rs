# One-Shot Migration from gnome-keyring-daemon

This guide migrates secrets from a running `gnome-keyring-daemon` (Secret Service on `org.freedesktop.secrets`) into keyring-rs redb storage in one shot.

## Prerequisites

1. `keyring-ctl` is built and available:
   ```bash
   cargo run --bin keyring-ctl -- --help
   ```
2. `gnome-keyring-daemon` currently owns Secret Service on your session bus.
   ```bash
   busctl --user get-name-owner org.freedesktop.secrets
   ```
3. Source collections are unlocked (Seahorse or a `secret-tool lookup` that unlocks them).
4. Pick destination password for keyring-rs and export it:
   ```bash
   export KEYRING_PASSWORD='choose-a-strong-password'
   ```
5. Optional custom destination database path:
   ```bash
   export KEYRING_DB_PATH="$XDG_STATE_HOME/keyring-rs/secrets.db"
   ```

## Collision Policy

`import-gnome` supports deterministic collision handling when an item with the same `label + attributes` already exists in the destination collection:

- `skip` (default): keep existing item, do not import colliding source item.
- `replace`: delete colliding destination item(s), then import source item.
- `rename`: import with suffix `" (imported N)"` where `N` is deterministic.

## One-Shot Import

Dry-run first:

```bash
cargo run --bin keyring-ctl -- import-gnome --dry-run --on-collision skip
```

Run import:

```bash
cargo run --bin keyring-ctl -- import-gnome --on-collision rename
```

Import only selected source collections:

```bash
cargo run --bin keyring-ctl -- import-gnome \
  --collection default \
  --collection login \
  --on-collision replace
```

## Read the Migration Audit Output

`import-gnome` prints:

- scanned/imported/skipped/failed item counts
- collision outcomes (replaced/renamed)
- per-item failure reasons

Treat migration as incomplete if `failed > 0`.

## Locked Collection Handling

If a selected source collection is locked, import fails with guidance.

Typical flow:

1. Unlock listed collections (Seahorse or `secret-tool lookup ...`).
2. Re-run the same `keyring-ctl import-gnome ...` command.

## Post-Migration Verification

Use a known `(attributes -> secret)` pair and verify round-trip after switching Secret Service provider to keyring-rs.

1. Before switching providers, note a known lookup key (example):
   ```bash
   secret-tool lookup service my-app user alice
   ```
2. Stop/disable `gnome-keyring-daemon` Secret Service ownership for the session.
3. Start keyring-rs service (example):
   ```bash
   systemctl --user start keyring-daemon.service
   ```
4. Verify keyring-rs now owns Secret Service:
   ```bash
   busctl --user get-name-owner org.freedesktop.secrets
   ```
5. Run the same lookup and compare secret value:
   ```bash
   secret-tool lookup service my-app user alice
   ```

If lookup values match and migration audit had `failed=0`, migration is complete.

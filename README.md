# n4acl

A small TUI editor for NFSv4 ACLs on **illumos ZFS** (built for OmniOS).

<img width="1841" height="950" alt="image" src="https://github.com/user-attachments/assets/a03a3330-60ea-4761-9f19-61366dffbda1" />


```
n4acl /tank/zones/web01/root/data/www
```

It shows each entry in `ls -V` notation, explains the selected one in plain words, and checks the list for
mistakes as you edit. You can add, edit, delete, reorder and duplicate entries, preview inheritance, and test
what a given user can actually do. Changes are written to one item or recursively, with a backup you can replay.

## Build (OmniOS)

```sh
pkg install ooce/developer/rust          # from the OmniOS extra repository
cargo build --release
cp target/release/n4acl /usr/local/bin/
```

The only native dependency is `acl(2)` from libc (`ACE_GETACLCNT` / `ACE_GETACL` / `ACE_SETACL`).
libsec is not used.

## Usage

```
n4acl [options] PATH
n4acl --restore BACKUP

  -z ZONE             resolve names with ZONE's /etc/passwd and /etc/group
  -p PASSWD -g GROUP  resolve names with these files
  -G                  global zone
  -n                  numeric ids only
  --dump              print the ACL in chmod A= syntax (numeric ids unless
                      names are resolved in the global zone)
  --explain           explain every entry and run the checks
  --test WHO          effective access for name | uid | uid:gid,gid…
  --restore FILE      re-apply ACLs from a backup
```

### Numeric ids and zones

Typing a number (or `#number`) as the principal stores exactly that uid/gid without any lookup.
Use this for zone users who reach a dataset through lofs or as a delegated dataset.

Names are resolved in an **id context**, shown in the header and changed with `Z`. The context can be:

- the global zone (including nsswitch sources such as LDAP)
- a non-global zone; its `etc/passwd` and `etc/group` are read from the zonepath, so halted zones work too
- numeric only

If the path is under a zone's root, or its dataset is `zoned=on` and delegated to a zone, that zone is picked
automatically. When an id has a different name in the zone than in the global zone, n4acl says so.

Ids ≥ 2147483648 are idmap ephemeral (SID-mapped) ids. They are shown read-only: you can move or delete
those entries but not edit them.

## Keys

| key | action | key | action |
|---|---|---|---|
| ↑↓ j k g G | select | J K, Shift-↑↓ | move entry |
| a / A | add after / at top | e, Enter | edit |
| x, Del | delete | y | duplicate |
| u / Ctrl-r | undo / redo | r | reload from disk |
| t | test access | i | inheritance preview |
| v | edit as text in `$EDITOR` | N | id/name display |
| Z | id context | w | write |
| ? | help | q | quit |

In the entry editor:

- Arrow keys move between fields and Space toggles.
- Permission letters (`rwxpdDaARWcCos`) toggle their permission directly.
- `1`–`7` apply presets: full, modify, read+exec, read, write, traverse, none.
- In the id field, Tab completes names from the current id context. Backspace (or ^H), Ctrl-u (clear) and
  Ctrl-w (delete word) work in all text fields.
- Editing an inherited (`I`) entry turns it into an explicit one, so a later "refresh inherited" keeps it.

## Writing

The write dialog shows a diff and offers three scopes:

- **this item only**
- **same ACL everywhere:** directories get the ACL as-is; files get it without `f`/`d`/`n`/`i` and without inherit-only entries.
- **refresh inherited:** each child keeps its own entries, and its `I` entries are recomputed from the new parent ACL according to `aclinherit`.

Recursion never follows symlinks and never crosses into another dataset; such entries are counted as
skipped. Dry run is available. Backups go to `~/.n4acl/` (override with `N4ACL_BACKUP_DIR`):

- They contain numeric ids and byte-exact paths, and are created with mode 0600.
- Each entry is flushed before that item's ACL is changed, so an interrupted run can still be undone.
- A backup with nothing in it is removed.

Before writing, n4acl re-reads the ACL and warns if someone else changed it after it was loaded.
If this item could not be written, your edits stay in the editor so you can fix them and retry.

## Checks

The checks pane flags:

- entries that have no effect because earlier entries for the same principal already decide those bits
  (for example, a deny placed after an allow)
- duplicate entries
- inheritance flags on files
- `i` without `f`/`d`
- empty entries
- ids with no name in the current context
- id names that differ between the zone and the global zone
- audit/alarm entries, which ZFS stores but does not act on
- interactions with `aclinherit` (`discard`, `noallow`, `restricted`) and `aclmode`
  (`discard`, `groupmask`, `restricted`)

## Known approximations

- The **test access** evaluation walks the ACL in order (first match per bit), as ZFS does. It also treats the
  owner as always able to read the ACL and attributes and to chmod. It does not model privileges
  (root, `file_dac_*`), deletion through the parent's `D`, or `aclmode` effects at creation time.
- The **inheritance preview** follows `aclinherit`. It does not apply the creation mode that ZFS also applies,
  and `passthrough-x` is treated like `passthrough`.

## Development on other systems

Set `N4ACL_MOCK=<dir>` to use a simulated backend that stores ACLs as text in that directory.
`<dir>/zones` (in `zoneadm list -cp` format) and `<dir>/zfsprops` can simulate zones and dataset properties.
Run the tests with `cargo test`.

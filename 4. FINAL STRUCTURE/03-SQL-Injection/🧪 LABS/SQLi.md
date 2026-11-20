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


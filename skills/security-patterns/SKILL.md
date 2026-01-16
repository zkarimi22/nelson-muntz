# Security Patterns Skill

This skill provides knowledge of common security vulnerabilities for adversarial code review.

## OWASP Top 10 Vulnerabilities

### 1. Injection (A03:2021)

**What it is:** Untrusted data sent to an interpreter as part of a command or query.

**How to detect:**
- String concatenation in SQL queries
- User input in shell commands
- Template injection in rendering engines
- LDAP, XPath, or NoSQL query construction with user input

**Vulnerable code examples:**

```javascript
// SQL Injection - Ha-ha! Classic rookie mistake!
db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
db.query("SELECT * FROM users WHERE name = '" + username + "'");

// Command Injection - Oh, this is too easy!
exec(`ls ${userInput}`);
spawn('bash', ['-c', `grep ${searchTerm} file.txt`]);

// NoSQL Injection - MongoDB isn't magic, dummy!
db.users.find({ username: req.body.username, password: req.body.password });
```

**Attack:** Inject malicious payloads like `'; DROP TABLE users; --` or `{$gt: ''}` for NoSQL.

**Fix:**
```javascript
// Parameterized queries
db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);

// Input validation and escaping
const safeInput = shellEscape([userInput]);

// Explicit field comparison for NoSQL
db.users.find({ username: String(req.body.username) });
```

---

### 2. Broken Authentication (A07:2021)

**What it is:** Flaws that allow attackers to compromise passwords, keys, or session tokens.

**How to detect:**
- Passwords stored in plaintext or weak hashes (MD5, SHA1)
- Missing rate limiting on login
- Session tokens in URLs
- No session invalidation on logout
- Weak password requirements
- Missing multi-factor authentication for sensitive operations

**Vulnerable code examples:**

```javascript
// Plaintext password storage - Are you serious?!
const user = { email, password: req.body.password };
db.insert(user);

// Weak hashing - Ha-ha! MD5 is not encryption!
const hash = crypto.createHash('md5').update(password).digest('hex');

// No rate limiting - Free brute force for everyone!
app.post('/login', (req, res) => {
  const user = await db.findUser(req.body.email);
  if (user.password === req.body.password) { /* ... */ }
});

// Session in URL - Thanks for the free session!
res.redirect(`/dashboard?sessionId=${session.id}`);
```

**Attack:** Brute force passwords, steal sessions from URLs/logs, crack weak hashes.

**Fix:**
```javascript
// Use bcrypt with proper cost factor
const hash = await bcrypt.hash(password, 12);

// Add rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.post('/login', limiter, loginHandler);

// Use secure, httpOnly cookies for sessions
res.cookie('sessionId', session.id, { httpOnly: true, secure: true, sameSite: 'strict' });
```

---

### 3. Cross-Site Scripting / XSS (A03:2021)

**What it is:** Untrusted data included in web pages without proper validation or escaping.

**How to detect:**
- User input rendered directly in HTML
- `innerHTML` or `dangerouslySetInnerHTML` with user data
- Template literals inserting user data without escaping
- `eval()` or `Function()` with user input

**Vulnerable code examples:**

```javascript
// Reflected XSS - Ha-ha! I'll inject whatever I want!
app.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${req.query.q}</h1>`);
});

// Stored XSS - The gift that keeps on giving!
element.innerHTML = userComment;

// DOM XSS - Client-side foolishness!
document.getElementById('output').innerHTML = location.hash.slice(1);

// React XSS - dangerously is right!
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

**Attack:** Inject `<script>alert(document.cookie)</script>` or event handlers like `<img onerror="...">`.

**Fix:**
```javascript
// Escape HTML output
const escaped = escapeHtml(userInput);

// Use textContent instead of innerHTML
element.textContent = userComment;

// Use proper templating with auto-escaping
res.render('search', { query: req.query.q }); // Template auto-escapes

// Sanitize if HTML is required
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```

---

### 4. Insecure Direct Object References / IDOR (A01:2021)

**What it is:** Direct access to objects based on user-supplied input without authorization checks.

**How to detect:**
- Database IDs exposed in URLs without ownership verification
- File paths constructed from user input
- Missing authorization checks on resource access

**Vulnerable code examples:**

```javascript
// IDOR - Just change the ID and access anyone's data!
app.get('/api/users/:id/profile', (req, res) => {
  const profile = await db.getProfile(req.params.id);
  res.json(profile);
});

// File access IDOR - Path traversal bonus!
app.get('/files/:filename', (req, res) => {
  res.sendFile(`/uploads/${req.params.filename}`);
});
```

**Attack:** Change `/api/users/123/profile` to `/api/users/456/profile` to access other users.

**Fix:**
```javascript
// Always verify ownership
app.get('/api/users/:id/profile', (req, res) => {
  if (req.params.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const profile = await db.getProfile(req.params.id);
  res.json(profile);
});

// Use indirect references
app.get('/api/profile', (req, res) => {
  const profile = await db.getProfile(req.user.id); // Always use session user
  res.json(profile);
});
```

---

### 5. Security Misconfiguration (A05:2021)

**What it is:** Insecure default configurations, incomplete setups, or verbose error messages.

**How to detect:**
- Debug mode enabled in production
- Default credentials
- Unnecessary features/services enabled
- Missing security headers
- Verbose error messages exposing internals

**Vulnerable code examples:**

```javascript
// Debug mode in production - Thanks for the free debugger!
app.use(errorhandler()); // Full stack traces in responses

// Missing security headers - No helmet, no protection!
// (absence of security headers)

// Default credentials - admin:admin, classic!
const dbConnection = mysql.connect({
  user: 'root',
  password: 'password'
});

// Exposed stack traces - Tell me more about your internals!
catch (error) {
  res.status(500).json({ error: error.stack });
}
```

**Fix:**
```javascript
// Use helmet for security headers
app.use(helmet());

// Environment-specific error handling
if (process.env.NODE_ENV === 'production') {
  app.use((err, req, res, next) => {
    console.error(err); // Log internally
    res.status(500).json({ error: 'Internal server error' }); // Generic message
  });
}

// Use environment variables for credentials
const dbConnection = mysql.connect({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});
```

---

### 6. Sensitive Data Exposure (A02:2021)

**What it is:** Lack of protection for sensitive data in transit or at rest.

**How to detect:**
- Sensitive data in logs
- Missing HTTPS
- Weak encryption algorithms
- Secrets in source code
- PII returned in API responses unnecessarily

**Vulnerable code examples:**

```javascript
// Logging sensitive data - Check the logs for passwords!
console.log(`User login attempt: ${email}, ${password}`);
logger.info('Payment processed', { cardNumber, cvv });

// Hardcoded secrets - Git history says thanks!
const API_KEY = 'sk_live_abc123secretkey';
const JWT_SECRET = 'mysupersecret';

// Returning too much data - Data minimization? Never heard of it!
app.get('/api/user', (req, res) => {
  const user = await db.getUser(req.user.id);
  res.json(user); // Includes password hash, SSN, etc.
});
```

**Fix:**
```javascript
// Redact sensitive data in logs
console.log(`User login attempt: ${email}, [REDACTED]`);

// Use environment variables
const API_KEY = process.env.API_KEY;

// Return only necessary fields
app.get('/api/user', (req, res) => {
  const user = await db.getUser(req.user.id);
  res.json({
    id: user.id,
    email: user.email,
    name: user.name
  });
});
```

---

### 7. Missing Function Level Access Control (A01:2021)

**What it is:** Failure to restrict access to functions based on user roles.

**How to detect:**
- Admin functions accessible without role checks
- API endpoints missing authentication middleware
- Client-side only authorization checks

**Vulnerable code examples:**

```javascript
// Missing auth check - Admin panel for everyone!
app.get('/admin/users', async (req, res) => {
  const users = await db.getAllUsers();
  res.json(users);
});

// Client-side auth only - Ha-ha! I'll just call the API directly!
// Frontend: if (user.isAdmin) showAdminButton();
// Backend: No corresponding check

// Role check after action - Too late, damage done!
app.delete('/api/posts/:id', async (req, res) => {
  await db.deletePost(req.params.id);
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' }); // Already deleted!
  }
});
```

**Fix:**
```javascript
// Middleware for authentication
const requireAuth = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// Middleware for authorization
const requireAdmin = (req, res, next) => {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// Apply to routes
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await db.getAllUsers();
  res.json(users);
});
```

---

### 8. Cross-Site Request Forgery / CSRF (A01:2021)

**What it is:** Forcing authenticated users to submit unwanted requests.

**How to detect:**
- State-changing operations on GET requests
- Missing CSRF tokens on forms
- No SameSite cookie attribute
- CORS misconfiguration allowing any origin

**Vulnerable code examples:**

```javascript
// State change on GET - One malicious link and boom!
app.get('/api/delete-account', (req, res) => {
  await db.deleteUser(req.user.id);
  res.json({ success: true });
});

// No CSRF protection - Any site can submit this form!
app.post('/api/transfer', (req, res) => {
  await transferMoney(req.user.id, req.body.to, req.body.amount);
});

// Permissive CORS - Everyone's invited!
app.use(cors({ origin: '*', credentials: true }));
```

**Fix:**
```javascript
// Use POST/PUT/DELETE for state changes
app.delete('/api/account', csrfProtection, (req, res) => { /* ... */ });

// Add CSRF tokens
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// Restrictive CORS
app.use(cors({
  origin: 'https://myapp.com',
  credentials: true
}));

// SameSite cookies
res.cookie('session', token, { sameSite: 'strict' });
```

---

### 9. Using Components with Known Vulnerabilities (A06:2021)

**What it is:** Using libraries, frameworks, or components with known security issues.

**How to detect:**
- Outdated dependencies in package.json/requirements.txt
- Known vulnerable versions of libraries
- Unmaintained dependencies

**Detection commands:**
```bash
npm audit
pip-audit
snyk test
```

**Fix:**
- Regularly update dependencies
- Use automated vulnerability scanning in CI/CD
- Remove unused dependencies
- Subscribe to security advisories

---

### 10. Insufficient Logging & Monitoring (A09:2021)

**What it is:** Lack of detection, escalation, and response to active attacks.

**How to detect:**
- No logging of authentication failures
- No logging of access control failures
- No alerting on suspicious activity
- Logs not protected from tampering

**Vulnerable patterns:**
```javascript
// Silent failures - Attackers love the silence!
try {
  await authenticate(user, password);
} catch (e) {
  res.status(401).json({ error: 'Invalid credentials' });
  // No logging!
}
```

**Fix:**
```javascript
// Log security-relevant events
try {
  await authenticate(user, password);
  logger.info('Successful login', { userId: user.id, ip: req.ip });
} catch (e) {
  logger.warn('Failed login attempt', {
    email: user.email,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  res.status(401).json({ error: 'Invalid credentials' });
}
```

---

## Additional Security Patterns

### Cryptographic Failures

**Weak patterns to detect:**
```javascript
// Weak hashing
crypto.createHash('md5')
crypto.createHash('sha1')

// ECB mode (patterns visible)
crypto.createCipheriv('aes-256-ecb', key, '')

// Hardcoded IVs
const iv = Buffer.from('1234567890123456');

// Math.random for security
const token = Math.random().toString(36);
```

**Secure alternatives:**
```javascript
// Strong hashing for passwords
await bcrypt.hash(password, 12);
await argon2.hash(password);

// GCM mode with random IV
const iv = crypto.randomBytes(16);
crypto.createCipheriv('aes-256-gcm', key, iv);

// Cryptographically secure random
const token = crypto.randomBytes(32).toString('hex');
```

### Path Traversal

**Vulnerable:**
```javascript
const filePath = `/uploads/${req.params.filename}`;
res.sendFile(filePath); // ../../../etc/passwd works!
```

**Secure:**
```javascript
const path = require('path');
const safePath = path.join('/uploads', path.basename(req.params.filename));
if (!safePath.startsWith('/uploads/')) {
  return res.status(400).json({ error: 'Invalid path' });
}
```

### Mass Assignment

**Vulnerable:**
```javascript
// User can set isAdmin: true!
const user = new User(req.body);
await user.save();
```

**Secure:**
```javascript
// Whitelist allowed fields
const user = new User({
  email: req.body.email,
  name: req.body.name
});
```

### Server-Side Request Forgery (SSRF)

**Vulnerable:**
```javascript
// I can make your server request internal resources!
app.get('/fetch', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});
```

**Secure:**
```javascript
// Validate and restrict URLs
const allowedHosts = ['api.trusted.com'];
const url = new URL(req.query.url);
if (!allowedHosts.includes(url.hostname)) {
  return res.status(400).json({ error: 'URL not allowed' });
}
```

### Race Conditions (TOCTOU)

**Vulnerable:**
```javascript
// Time-of-check to time-of-use - Race me!
if (await getBalance(userId) >= amount) {
  await deductBalance(userId, amount);  // Another request could have deducted!
  await processPayment(amount);
}
```

**Secure:**
```javascript
// Atomic operations with transactions
await db.transaction(async (trx) => {
  const balance = await trx.forUpdate().getBalance(userId); // Lock the row
  if (balance >= amount) {
    await trx.deductBalance(userId, amount);
    await processPayment(amount);
  }
});
```

---

## Detection Checklist

When reviewing code, check for:

- [ ] SQL queries with string concatenation
- [ ] Shell commands with user input
- [ ] HTML output without escaping
- [ ] Missing authentication middleware
- [ ] Missing authorization checks
- [ ] Hardcoded secrets/credentials
- [ ] Weak cryptographic functions
- [ ] Missing input validation
- [ ] Verbose error messages
- [ ] Missing security headers
- [ ] State changes on GET requests
- [ ] Missing CSRF protection
- [ ] Path traversal possibilities
- [ ] Mass assignment vulnerabilities
- [ ] Race conditions in critical operations
- [ ] SSRF vulnerabilities
- [ ] Insecure deserialization
- [ ] Missing rate limiting
- [ ] Insufficient logging

**Ha-ha! Now go find those vulnerabilities!**

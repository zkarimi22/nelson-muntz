# Code Quality Skill

This skill identifies code quality issues that could become security vulnerabilities, reliability problems, or maintenance nightmares.

## Error Handling Issues

### Silent Failures

**Problem:** Errors swallowed without handling.

```javascript
// Ha-ha! Errors go into the void!
try {
  await processPayment(order);
} catch (e) {
  // Nothing here... payment might have failed, who knows?
}

// Even worse - empty catch with wrong logging
try {
  await saveUser(user);
} catch (e) {
  console.log('An error occurred'); // Which error? Who knows!
}
```

**Why it matters:** Attackers love silent failures. Failed security checks that don't throw = bypass.

**Fix:**
```javascript
try {
  await processPayment(order);
} catch (error) {
  logger.error('Payment processing failed', { orderId: order.id, error: error.message });
  throw new PaymentError('Payment could not be processed');
}
```

### Generic Error Handling

**Problem:** Catching too broadly, masking real issues.

```javascript
// Ha-ha! Catch-all hides everything!
try {
  const user = await authenticate(credentials);
  const data = await fetchUserData(user);
  await processData(data);
} catch (e) {
  return res.status(500).json({ error: 'Something went wrong' });
}
```

**Why it matters:** Authentication failures look the same as data errors. Can't debug, can't monitor.

**Fix:**
```javascript
try {
  const user = await authenticate(credentials);
  // ...
} catch (error) {
  if (error instanceof AuthenticationError) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (error instanceof NotFoundError) {
    return res.status(404).json({ error: 'Resource not found' });
  }
  logger.error('Unexpected error', { error });
  return res.status(500).json({ error: 'Internal error' });
}
```

### Missing Error Handling

**Problem:** No try-catch where operations can fail.

```javascript
// Ha-ha! What could go wrong with network calls?
const response = await fetch(externalApi);
const data = await response.json();
return processData(data);
```

**Fix:**
```javascript
try {
  const response = await fetch(externalApi);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}`);
  }
  const data = await response.json();
  return processData(data);
} catch (error) {
  logger.error('External API call failed', { error });
  throw new ExternalServiceError('Could not fetch data');
}
```

---

## Null/Undefined Issues

### Missing Null Checks

**Problem:** Assuming values exist when they might not.

```javascript
// Ha-ha! What if user doesn't exist?
const user = await db.findUser(id);
return user.email; // TypeError: Cannot read property 'email' of null

// Or in nested objects
const city = user.address.city; // What if address is undefined?
```

**Fix:**
```javascript
const user = await db.findUser(id);
if (!user) {
  throw new NotFoundError('User not found');
}
return user.email;

// Optional chaining for nested access
const city = user?.address?.city ?? 'Unknown';
```

### Dangerous Defaults

**Problem:** Using falsy defaults incorrectly.

```javascript
// Ha-ha! Zero is falsy, dummy!
function getLimit(limit) {
  return limit || 100; // If limit is 0, returns 100!
}

// Empty string is also falsy
function getName(name) {
  return name || 'Anonymous'; // Empty string becomes Anonymous
}
```

**Fix:**
```javascript
function getLimit(limit) {
  return limit ?? 100; // Nullish coalescing - only null/undefined
}

function getName(name) {
  return name !== undefined ? name : 'Anonymous';
}
```

---

## Race Conditions

### Time-of-Check to Time-of-Use (TOCTOU)

**Problem:** State changes between check and action.

```javascript
// Ha-ha! I'll race you!
async function purchaseItem(userId, itemId) {
  const balance = await getBalance(userId);
  const price = await getPrice(itemId);

  if (balance >= price) {
    // Another request could deduct balance here!
    await deductBalance(userId, price);
    await grantItem(userId, itemId);
  }
}
```

**Fix:**
```javascript
async function purchaseItem(userId, itemId) {
  await db.transaction(async (trx) => {
    const balance = await trx.forUpdate().getBalance(userId);
    const price = await getPrice(itemId);

    if (balance < price) {
      throw new InsufficientFundsError();
    }

    await trx.deductBalance(userId, price);
    await grantItem(userId, itemId);
  });
}
```

### Double Submission

**Problem:** Same operation processed multiple times.

```javascript
// Ha-ha! No idempotency check!
app.post('/api/transfer', async (req, res) => {
  await transferMoney(req.body.from, req.body.to, req.body.amount);
  res.json({ success: true });
});
```

**Fix:**
```javascript
app.post('/api/transfer', async (req, res) => {
  const idempotencyKey = req.headers['idempotency-key'];

  if (await isProcessed(idempotencyKey)) {
    return res.json({ success: true, cached: true });
  }

  await transferMoney(req.body.from, req.body.to, req.body.amount);
  await markProcessed(idempotencyKey);

  res.json({ success: true });
});
```

---

## Resource Leaks

### Unclosed Connections

**Problem:** Database/file/socket connections not closed.

```javascript
// Ha-ha! Connection leak!
async function getData() {
  const connection = await db.connect();
  const data = await connection.query('SELECT * FROM users');
  return data; // Connection never closed!
}

// File handle leak
function readConfig() {
  const file = fs.openSync('config.json', 'r');
  const content = fs.readSync(file, buffer, 0, 1000, 0);
  return JSON.parse(content); // File never closed!
}
```

**Fix:**
```javascript
async function getData() {
  const connection = await db.connect();
  try {
    return await connection.query('SELECT * FROM users');
  } finally {
    await connection.close();
  }
}

// Or use pools/context managers
async function getData() {
  return await db.pool.query('SELECT * FROM users');
}
```

### Memory Leaks

**Problem:** Growing data structures never cleaned up.

```javascript
// Ha-ha! Memory grows forever!
const cache = {};

function cacheResult(key, value) {
  cache[key] = value; // Never evicted!
}

// Event listener leak
function setupHandler() {
  window.addEventListener('resize', handleResize);
  // Never removed!
}
```

**Fix:**
```javascript
// Use LRU cache with size limit
const cache = new LRUCache({ max: 1000 });

// Clean up listeners
function setupHandler() {
  window.addEventListener('resize', handleResize);
  return () => window.removeEventListener('resize', handleResize);
}
```

---

## Logic Bugs

### Off-by-One Errors

**Problem:** Loop or index boundaries wrong by one.

```javascript
// Ha-ha! Classic off-by-one!
for (let i = 0; i <= array.length; i++) { // Should be <
  process(array[i]); // Will access undefined
}

// Substring wrong
const extension = filename.substring(filename.lastIndexOf('.') + 1); // What if no dot?
```

**Fix:**
```javascript
for (let i = 0; i < array.length; i++) {
  process(array[i]);
}

// Handle edge case
const dotIndex = filename.lastIndexOf('.');
const extension = dotIndex !== -1 ? filename.substring(dotIndex + 1) : '';
```

### Incorrect Boolean Logic

**Problem:** Complex conditions with wrong operators.

```javascript
// Ha-ha! Logic fail!
if (!user.isAdmin || !user.isActive) {
  return denyAccess(); // This denies active admins too!
}

// Should be:
if (!user.isAdmin || !user.isActive) // Denies if NOT admin OR NOT active
// vs
if (!(user.isAdmin && user.isActive)) // Same thing
// vs
if (!user.isAdmin && !user.isActive) // Denies only if neither
```

### Async/Await Mistakes

**Problem:** Not awaiting promises properly.

```javascript
// Ha-ha! Race condition city!
async function processAll(items) {
  items.forEach(async (item) => {
    await processItem(item); // forEach doesn't wait!
  });
  console.log('Done!'); // Prints before processing completes
}

// Ignoring promise
function save() {
  db.save(data); // Returns promise, not awaited
  return { success: true }; // Returns before save completes
}
```

**Fix:**
```javascript
async function processAll(items) {
  await Promise.all(items.map(item => processItem(item)));
  console.log('Done!');
}

// Or sequential
for (const item of items) {
  await processItem(item);
}
```

---

## Code Smells

### Magic Numbers/Strings

**Problem:** Unexplained literals in code.

```javascript
// Ha-ha! What does 86400 mean?
if (timestamp < Date.now() - 86400000) {
  expireSession();
}

if (user.role === 'r2') { // What's r2?
  grantAccess();
}
```

**Fix:**
```javascript
const ONE_DAY_MS = 24 * 60 * 60 * 1000;
if (timestamp < Date.now() - ONE_DAY_MS) {
  expireSession();
}

const ROLES = { ADMIN: 'r1', MODERATOR: 'r2', USER: 'r3' };
if (user.role === ROLES.MODERATOR) {
  grantAccess();
}
```

### Deep Nesting

**Problem:** Too many levels of indentation.

```javascript
// Ha-ha! Arrow code!
function process(data) {
  if (data) {
    if (data.users) {
      for (const user of data.users) {
        if (user.active) {
          if (user.email) {
            if (isValidEmail(user.email)) {
              sendEmail(user.email);
            }
          }
        }
      }
    }
  }
}
```

**Fix:**
```javascript
function process(data) {
  if (!data?.users) return;

  const activeUsersWithEmail = data.users.filter(
    user => user.active && user.email && isValidEmail(user.email)
  );

  activeUsersWithEmail.forEach(user => sendEmail(user.email));
}
```

### Long Functions

**Problem:** Functions doing too much.

```javascript
// Ha-ha! 500-line function!
function handleRequest(req, res) {
  // 100 lines of validation
  // 100 lines of business logic
  // 100 lines of database operations
  // 100 lines of response formatting
  // 100 lines of error handling
}
```

**Fix:** Extract into smaller, focused functions.

### Duplicated Code

**Problem:** Same logic repeated in multiple places.

```javascript
// Ha-ha! Copy-paste programming!
// In file1.js
const user = await db.users.findOne({ email });
if (!user) throw new Error('User not found');
if (!user.active) throw new Error('User inactive');

// In file2.js (same code)
const user = await db.users.findOne({ email });
if (!user) throw new Error('User not found');
if (!user.active) throw new Error('User inactive');
```

**Fix:**
```javascript
// userService.js
async function getActiveUser(email) {
  const user = await db.users.findOne({ email });
  if (!user) throw new NotFoundError('User not found');
  if (!user.active) throw new InactiveError('User inactive');
  return user;
}
```

---

## Dangerous Patterns

### Eval and Dynamic Code

**Problem:** Executing strings as code.

```javascript
// Ha-ha! Free code execution!
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 1000);
setInterval(userInput, 1000);

// Template injection
const template = `Hello ${userInput}`;
eval('`' + template + '`');
```

**Why it matters:** Direct path to code execution vulnerabilities.

### Prototype Pollution

**Problem:** Modifying object prototypes.

```javascript
// Ha-ha! I'll pollute your prototype!
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key]; // __proto__ and constructor too!
  }
}

merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
({}).isAdmin // true - every object is now admin!
```

**Fix:**
```javascript
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor') continue;
    target[key] = source[key];
  }
}
```

### Insecure Deserialization

**Problem:** Deserializing untrusted data.

```javascript
// Ha-ha! Deserialize my payload!
const obj = JSON.parse(untrustedInput); // Relatively safe
const obj = yaml.load(untrustedInput); // Can execute code!
const obj = pickle.loads(untrustedInput); // Python - arbitrary code execution
```

---

## Incomplete Implementations

### TODO/FIXME Comments

**Problem:** Unfinished work left in production.

```javascript
// Ha-ha! TODO means never!
function validateInput(input) {
  // TODO: Add actual validation
  return true;
}

// FIXME: This is vulnerable to SQL injection
db.query(`SELECT * FROM users WHERE id = ${id}`);

// HACK: Temporary workaround, remove before release
if (user.email === 'admin@test.com') {
  user.isAdmin = true;
}
```

### Commented-Out Code

**Problem:** Dead code cluttering the codebase.

```javascript
// Ha-ha! What was this for?
function authenticate(user) {
  // const isValid = checkOldAuth(user);
  // if (isValid) {
  //   return grantAccess();
  // }

  // Old validation - keeping just in case
  // if (user.legacyToken) {
  //   return validateLegacy(user.legacyToken);
  // }

  return newAuth(user);
}
```

### Missing Validation

**Problem:** Input not validated before use.

```javascript
// Ha-ha! No validation whatsoever!
app.post('/api/users', (req, res) => {
  const { email, age, role } = req.body;
  db.users.insert({ email, age, role }); // No checks!
});
```

**Fix:**
```javascript
app.post('/api/users', (req, res) => {
  const { email, age, role } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  if (typeof age !== 'number' || age < 0 || age > 150) {
    return res.status(400).json({ error: 'Invalid age' });
  }
  if (!ALLOWED_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  db.users.insert({ email, age, role });
});
```

---

## Performance Anti-Patterns

### N+1 Queries

**Problem:** Querying in a loop instead of batching.

```javascript
// Ha-ha! Database says ow!
const users = await db.users.find({});
for (const user of users) {
  const posts = await db.posts.find({ userId: user.id }); // N+1!
  user.posts = posts;
}
```

**Fix:**
```javascript
const users = await db.users.find({});
const userIds = users.map(u => u.id);
const posts = await db.posts.find({ userId: { $in: userIds } });
const postsByUser = groupBy(posts, 'userId');
users.forEach(user => user.posts = postsByUser[user.id] || []);
```

### Unbounded Operations

**Problem:** Operations without limits.

```javascript
// Ha-ha! Select * from production!
const allUsers = await db.users.find({}); // All 10 million?

const results = await search(query); // Returns everything matching
```

**Fix:**
```javascript
const users = await db.users.find({}).limit(100);
const results = await search(query, { limit: 50, offset: 0 });
```

---

## Detection Checklist

When reviewing code, check for:

- [ ] Empty catch blocks
- [ ] Catch-all error handling
- [ ] Missing null/undefined checks
- [ ] Race conditions in state changes
- [ ] Unclosed resources (connections, files)
- [ ] Magic numbers and strings
- [ ] Deeply nested code (> 3 levels)
- [ ] Functions over 50 lines
- [ ] Duplicated code blocks
- [ ] TODO/FIXME comments
- [ ] Commented-out code
- [ ] Missing input validation
- [ ] N+1 query patterns
- [ ] Unbounded database queries
- [ ] eval() or dynamic code execution
- [ ] Prototype pollution vectors
- [ ] Async/await mistakes

**Ha-ha! Code quality matters too!**

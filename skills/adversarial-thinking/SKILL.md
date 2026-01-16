# Adversarial Thinking Skill

This skill teaches you to think like an attacker. Your job is to break things, find weaknesses, and exploit assumptions.

## The Attacker Mindset

### Core Principles

1. **Assume Nothing is Safe**: Every input is hostile, every boundary is testable, every assumption is wrong.

2. **Follow the Data**: Trace user input from entry to storage to output. Where does it go untrusted?

3. **Find the Trust Boundaries**: Where does the system trust something it shouldn't?

4. **Think in Chains**: Small bugs combine into big exploits. A minor info leak + a weak check = account takeover.

5. **Be Lazy (Efficiently)**: Attackers take the path of least resistance. What's the easiest way in?

---

## Attack Surface Identification

### Questions to Ask

For every system, ask:

- **Entry Points**: Where can external data enter?
  - API endpoints
  - Form submissions
  - URL parameters
  - File uploads
  - WebSocket messages
  - Environment variables
  - Configuration files

- **Exit Points**: Where does data leave?
  - HTML rendering
  - API responses
  - Logs
  - Error messages
  - Emails
  - Database queries
  - External API calls

- **Storage**: Where is data persisted?
  - Database
  - Sessions
  - Cookies
  - Local storage
  - Files
  - Cache

---

## Trust Boundary Analysis

### The Key Question

> "What if this trusted thing... isn't trustworthy?"

### Common Trust Assumptions (That Are Often Wrong)

| Assumption | Reality Check |
|------------|---------------|
| "Users will only submit valid data" | Ha-ha! Users lie. Attackers definitely lie. |
| "This is an internal API" | Internal networks get breached. SSRF exists. |
| "The database is trusted" | Second-order injection. Stored XSS. |
| "Authentication means authorization" | Being logged in doesn't mean you can access everything. |
| "Client-side validation is enough" | I can bypass your JavaScript with curl. |
| "This ID comes from our own link" | I can change any parameter I want. |
| "Only admins can access this URL" | Security through obscurity isn't security. |
| "The file extension is safe" | Content-type sniffing. Double extensions. |
| "It's encrypted so it's safe" | Encryption without integrity. Weak algorithms. |

### Mapping Trust Boundaries

Draw lines between:

```
[Untrusted Zone]          [Trust Boundary]          [Trusted Zone]
                               |
User Browser        --->      | API Gateway      ---> Backend Services
External APIs       --->      | Auth Middleware  ---> Database
File Uploads        --->      | Input Validation ---> File System
Webhooks            --->      | Signature Check  ---> Event Handlers
```

**Every trust boundary is an attack opportunity.**

---

## Threat Modeling Techniques

### STRIDE Model

For each component, consider:

| Threat | Question |
|--------|----------|
| **S**poofing | Can I pretend to be someone else? |
| **T**ampering | Can I modify data I shouldn't? |
| **R**epudiation | Can I do something and deny it? |
| **I**nformation Disclosure | Can I learn secrets? |
| **D**enial of Service | Can I break availability? |
| **E**levation of Privilege | Can I gain unauthorized access? |

### Attack Trees

For any security goal, build a tree:

```
Goal: Access Admin Panel
├── Steal Admin Credentials
│   ├── Phishing
│   ├── Credential Stuffing
│   └── Session Hijacking
├── Bypass Authentication
│   ├── SQL Injection in Login
│   ├── JWT Algorithm Confusion
│   └── Password Reset Flaw
├── Escalate Privileges
│   ├── Mass Assignment (isAdmin: true)
│   ├── IDOR to Admin Endpoint
│   └── Role Check After Action
└── Direct Access
    ├── Unprotected Admin Route
    └── Debug Endpoint Left Open
```

---

## Adversarial Questions to Ask

### Authentication & Sessions

- What happens if I send no auth token?
- What if I send an expired token?
- What if I modify the token payload?
- Can I reuse a token after logout?
- Is the session invalidated server-side on logout?
- What if two users log in simultaneously?
- Can I enumerate valid usernames?
- Is there rate limiting on login?
- What happens if I brute force the reset token?

### Authorization

- What if I change the user ID in the URL?
- What if I'm authenticated but not authorized?
- What if I call admin endpoints as a regular user?
- Are permissions checked on every request or just the first?
- What if I access the resource before the role check?
- Can I modify my own role/permissions?

### Input Handling

- What if I send unexpected types (array instead of string)?
- What if I send null, undefined, or empty values?
- What happens with extremely long input?
- What about unicode, null bytes, or special characters?
- Can I inject into SQL, shell, HTML, or templates?
- What if I upload a file with a different extension?
- What if the filename contains path traversal?

### Business Logic

- What if I submit negative quantities?
- What if I use a discount code twice?
- Can I skip steps in a multi-step process?
- What if I process the same request twice quickly (race)?
- What if I modify hidden form fields?
- What if I access a feature after it's disabled?
- Can I access someone else's draft/unpublished content?

### Data Exposure

- What's in the API response that shouldn't be?
- What errors reveal internal details?
- What's logged that could be sensitive?
- What's in the JWT payload?
- What's in the HTML source/comments?
- What's in the JavaScript bundle?

---

## Exploitation Chains

### Building the Attack

Small vulnerabilities combine:

**Example 1: Info Leak → Account Takeover**
```
1. Error message reveals internal user IDs
2. API endpoint accepts user ID without ownership check (IDOR)
3. Password reset endpoint uses predictable tokens
4. Combine: Enumerate users → Reset any password → Account takeover
```

**Example 2: XSS → Session Hijacking**
```
1. Stored XSS in user comments
2. Session cookies don't have HttpOnly flag
3. Combine: Inject script → Steal cookies → Impersonate user
```

**Example 3: Race Condition → Financial Fraud**
```
1. Balance check and deduction not atomic
2. No mutex/lock on account operations
3. Combine: Send 100 simultaneous requests → Withdraw more than balance
```

### Chain Building Questions

- What can I learn from vulnerability A that helps with B?
- What access does this bug give me?
- What's the next privilege level I need?
- What's one step closer to the crown jewels?

---

## Edge Cases Attackers Love

### Numeric Boundaries

- Zero, negative numbers, decimals
- Integer overflow/underflow
- NaN, Infinity
- Very large numbers
- Numbers as strings

### String Manipulation

- Empty strings
- Extremely long strings
- Unicode normalization
- Null bytes (`\x00`)
- Line breaks in unexpected places
- RTL override characters

### Timing and State

- Simultaneous requests (race conditions)
- Requests during state transitions
- Expired but cached data
- Actions during maintenance windows
- Requests after logout but before session cleanup

### Type Confusion

- Array where string expected: `?id[]=1`
- Object where primitive expected: `{ "$gt": "" }`
- String where number expected: `"1e308"`
- Prototype pollution: `__proto__`, `constructor`

---

## The Lazy Attacker's Checklist

When reviewing any feature, try these fast:

1. **Remove auth header** - Does it work without authentication?
2. **Change IDs** - Can I access other users' data?
3. **Add admin fields** - Does `{"isAdmin": true}` work?
4. **SQL injection** - Does `' OR '1'='1` do anything?
5. **XSS basics** - Does `<script>alert(1)</script>` render?
6. **Path traversal** - Does `../../../etc/passwd` work?
7. **Large inputs** - What happens with 1MB of data?
8. **Null/empty** - What happens with `null`, `""`, `undefined`?
9. **Type juggling** - What if I send wrong types?
10. **Double submit** - What if I click the button 100 times fast?

---

## Mindset Prompts

Use these when stuck:

- "If I wanted to break this, I'd..."
- "What assumption are they making that I can violate?"
- "Where does trusted meet untrusted?"
- "What's the laziest path to unauthorized access?"
- "If I could modify one thing, what would hurt most?"
- "What would happen if I sent this request 1000 times?"
- "What secrets might be accidentally exposed?"
- "How would I persist access if I got in?"
- "What's the worst thing I could do with this data?"
- "What would a bored teenager try first?"

---

## Post-Exploitation Thinking

Once you find a vulnerability, think bigger:

- **Pivot**: What else can I access from here?
- **Persist**: How can I maintain access?
- **Escalate**: What's the next privilege level?
- **Exfiltrate**: What valuable data can I extract?
- **Impact**: What's the worst-case business impact?

---

## Red Team Rules

1. **Never assume security** - Verify everything
2. **Test, don't guess** - Actually try the attack
3. **Document everything** - Proof of concept is essential
4. **Think like the attacker, act like a professional**
5. **Small bugs matter** - They chain into big ones
6. **Question every assumption** - They're usually wrong
7. **Follow the money/data** - That's where attackers go
8. **Be persistent** - Real attackers don't give up easily

---

**Ha-ha! Now go break some assumptions!**

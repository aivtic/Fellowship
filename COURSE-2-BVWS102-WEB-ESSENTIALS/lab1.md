# Web Application Security Lab: Understanding Web Architecture and XSS Vulnerabilities

## Lab Overview
**Course:** BVWS102 – Web Application Security Essentials  
**Lab Title:** Web Architecture Analysis and XSS Vulnerability Identification  
**Duration:** 2-3 hours  
**Difficulty:** Beginner  
**Objectives:** Understand web application components, identify security vulnerabilities, and implement secure coding practices.

---

## Lab Introduction

Welcome to your first hands-on web security lab! In this practical exercise, you'll explore how web applications work behind the scenes and learn to identify common security vulnerabilities.

### Learning Objectives
By completing this lab, you will be able to:
- Explain the client-server-database architecture
- Identify XSS vulnerabilities in web applications
- Implement secure coding practices
- Use proper input sanitization techniques
- Analyze the flow of web requests and responses

---

## Lab Setup

### Prerequisites
- Basic web browser (Chrome, Firefox, Safari)
- Text editor (VS Code, Notepad++, or similar)
- No additional software required

### Files You'll Create
1. `vulnerable-login.html` - Insecure login form
2. `secure-login.html` - Protected login form  
3. `vulnerable-search.html` - Search page with XSS vulnerability
4. `secure-search.html` - Safe search implementation

---

## Lab Exercises

### Exercise 1: Understanding Web Architecture (30 minutes)

#### Step 1: Analyze the Three-Tier Architecture
Create a diagram showing the relationship between:
- **Client** (Your browser)
- **Server** (Application logic)
- **Database** (Data storage)

**Task:** Draw this flow for a Facebook login scenario:
1. User enters credentials in browser
2. Browser sends request to Facebook servers
3. Server validates credentials with database
4. Database returns user data
5. Server sends response back to client

#### Step 2: Restaurant Analogy Mapping
Map web components to restaurant equivalents:
- Client = Customer
- Server = Waiter/Kitchen
- Database = Recipe book/Storage

**Discussion Question:** Why is it dangerous if the "customer" can directly access the "recipe book"?

### Exercise 2: Creating Vulnerable Web Applications (45 minutes)

#### Step 1: Build a Vulnerable Login Form
Create `vulnerable-login.html` with the following code:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login - ICDFA Lab</title>
    <style>
        .vulnerable { background: #ffe6e6; padding: 20px; max-width: 500px; margin: 50px auto; border: 3px solid red; }
    </style>
</head>
<body>
    <div class="vulnerable">
        <h1>VULNERABLE LOGIN FORM</h1>
        <p style="color: red;"><strong>WARNING: This form has XSS vulnerabilities!</strong></p>
        
        <form>
            <input type="text" id="username" placeholder="Username" style="width: 100%; padding: 10px; margin: 10px 0;">
            <input type="password" id="password" placeholder="Password" style="width: 100%; padding: 10px; margin: 10px 0;">
            <button type="button" onclick="vulnerableLogin()" style="width: 100%; padding: 10px; background: red; color: white;">
                Login (Insecure)
            </button>
        </form>
        
        <div id="message" style="margin-top: 20px; min-height: 50px; padding: 15px; background: white;">
            Messages will appear here...
        </div>
    </div>

    <script>
        function vulnerableLogin() {
            const username = document.getElementById('username').value;
            const messageDiv = document.getElementById('message');
            
            // VULNERABLE: Direct user input in innerHTML
            messageDiv.innerHTML = `
                <div style="background: lightyellow; padding: 15px;">
                    <h4>Welcome back, ${username}!</h4>
                    <p>Your login was successful.</p>
                    <p>Last login: ${new Date().toLocaleString()}</p>
                </div>
            `;
        }
        
        // Pre-fill with XSS example for testing
        window.onload = function() {
            document.getElementById('username').value = 'admin<script>alert("HACKED")</script>';
        };
    </script>
</body>
</html>
```

#### Step 2: Test XSS Vulnerabilities
1. Open the file in your web browser
2. Click the "Login (Insecure)" button without changing the username
3. **Observe:** The script tag executes and shows an alert
4. Try these additional XSS payloads in the username field:
   - `<img src="x" onerror="alert('XSS')">`
   - `<svg onload="alert('ICDFA')">`
   - `<div onclick="alert(1)">Click me</div>`

**Document Your Findings:** What happens with each payload?

### Exercise 3: Building Secure Counterparts (45 minutes)

#### Step 1: Create Secure Login Form
Build `secure-login.html` with proper input sanitization:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - ICDFA Lab</title>
    <style>
        .secure { background: #e6ffe6; padding: 20px; max-width: 500px; margin: 50px auto; border: 3px solid green; }
    </style>
</head>
<body>
    <div class="secure">
        <h1>SECURE LOGIN FORM</h1>
        <p style="color: green;"><strong>SAFE: This form is protected against XSS!</strong></p>
        
        <form>
            <input type="text" id="username" placeholder="Username" style="width: 100%; padding: 10px; margin: 10px 0;">
            <input type="password" id="password" placeholder="Password" style="width: 100%; padding: 10px; margin: 10px 0;">
            <button type="button" onclick="secureLogin()" style="width: 100%; padding: 10px; background: green; color: white;">
                Login (Secure)
            </button>
        </form>
        
        <div id="message" style="margin-top: 20px; min-height: 50px; padding: 15px; background: white;">
            Messages will appear here...
        </div>
    </div>

    <script>
        // SECURE: HTML escaping function
        function escapeHTML(unsafe) {
            if (!unsafe) return '';
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        function secureLogin() {
            const username = document.getElementById('username').value;
            const messageDiv = document.getElementById('message');
            
            // SAFE: Escape user input before display
            const safeUsername = escapeHTML(username);
            
            messageDiv.innerHTML = `
                <div style="background: lightyellow; padding: 15px;">
                    <h4>Welcome back, ${safeUsername}!</h4>
                    <p>Your login was successful.</p>
                    <p>Last login: ${new Date().toLocaleString()}</p>
                </div>
            `;
        }
        
        // Pre-fill with XSS example to show it's neutralized
        window.onload = function() {
            document.getElementById('username').value = 'admin<script>alert("HACKED")</script>';
        };
    </script>
</body>
</html>
```

#### Step 2: Compare and Contrast
1. Open both login forms side by side
2. Test the same XSS payloads in both forms
3. **Observation:** The secure form displays the payload as harmless text

**Analysis Questions:**
- What specific characters does the `escapeHTML` function neutralize?
- Why is displaying `<script>alert('XSS')</script>` as text safe?

### Exercise 4: Search Page Vulnerability Analysis (30 minutes)

#### Step 1: Create Vulnerable Search Page
Build `vulnerable-search.html` following the vulnerable pattern from the course materials.

#### Step 2: Create Secure Search Page  
Build `secure-search.html` implementing proper sanitization.

#### Step 3: Testing and Documentation
Test both pages with these payloads and document the results:

| Payload | Vulnerable Result | Secure Result |
|---------|------------------|---------------|
| `<script>alert('XSS')</script>` | | |
| `<img src="x" onerror="alert(1)">` | | |
| `<svg onload="alert('ICDFA')">` | | |

---

## Lab Analysis Questions

### Part A: Web Architecture
1. Explain why the database should never directly communicate with the client.
2. What security risks exist if client-side code contains hidden admin panels?
3. How does the three-tier architecture help with security?

### Part B: XSS Vulnerabilities
1. What is the fundamental difference between how vulnerable and secure code handles user input?
2. Why is `innerHTML` dangerous while `textContent` is safe?
3. List three real-world consequences of XSS vulnerabilities.

### Part C: Secure Development
1. Besides input sanitization, what other measures can prevent XSS attacks?
2. Why should validation happen on both client and server sides?
3. What's the risk of relying only on client-side security measures?

---

## Advanced Challenge (Optional)

### Multi-Step Attack Scenario
Create a simulated attack scenario where:
1. An attacker steals session cookies using XSS
2. The attacker impersonates a legitimate user
3. The attack accesses unauthorized admin functions

**Task:** Document how each layer (client, server, database) could prevent this attack.

---

## Lab Submission Requirements

Submit the following:
1. All four HTML files created during the lab
2. Answers to all analysis questions
3. Screenshots showing:
   - XSS payload executing in vulnerable version
   - XSS payload neutralized in secure version
4. A brief report (500 words) summarizing:
   - Key differences between vulnerable and secure code
   - Most surprising finding from the lab
   - One security practice you'll implement in future projects

---

## Grading Rubric

| Criteria | Excellent (4) | Good (3) | Satisfactory (2) | Needs Improvement (1) |
|----------|---------------|----------|------------------|---------------------|
| **Code Implementation** | All files work correctly, secure code properly neutralizes all XSS attempts | Most files work, minor issues with sanitization | Basic functionality works but security flaws remain | Major issues with implementation |
| **Analysis Questions** | Comprehensive, accurate answers with real-world examples | Correct answers with good understanding | Basic understanding shown with some inaccuracies | Significant misunderstandings |
| **Documentation** | Clear screenshots, well-organized report, thorough testing documentation | Good documentation with minor gaps | Basic documentation provided | Poor or missing documentation |
| **Security Understanding** | Demonstrates deep understanding of vulnerabilities and prevention | Good understanding of concepts | Basic comprehension | Limited understanding |

---

## Lab Conclusion

**Key Takeaways:**
- Never trust user input - always validate and sanitize
- Understand the data flow through your application
- Security must be implemented at multiple layers
- Client-side security alone is insufficient

**Remember:** "Master the flow, master the security. Know the path, know the vulnerabilities."

# Week 5 Lab: Complete Security Mastery - Encryption & SSL/TLS

## Lab Overview
**Course:** BVWS102 – Web Application Security Essentials  
**Week:** 5  
**Lab Title:** Complete Security Mastery - Data Encryption & SSL/TLS Analysis  
**Duration:** 4-5 hours  
**Difficulty:** Beginner/Intermediate  
**Objectives:** Master data encryption at rest, SSL/TLS configuration, security analysis, and practical implementation.

---

## Lab Introduction

Welcome to your final comprehensive security lab! You'll master both data protection at rest (stored data) and in transit (SSL/TLS). This complete security approach will give you real-world skills for protecting information everywhere.

### Learning Objectives
By completing this lab, you will be able to:
- Encrypt and decrypt files on Linux systems
- Understand encryption algorithms and methods
- Configure and analyze SSL/TLS configurations
- Perform comprehensive security assessments
- Implement end-to-end data protection

---

## Part A: Data Encryption at Rest Mastery (120 minutes)

### Exercise 1: Encryption Fundamentals Research

#### Understanding Encryption Types

**Research Mission:** Complete the encryption comparison table below using online resources.

| Encryption Type | How It Works | Best For | Real-World Example | Key Length |
|----------------|-------------|----------|-------------------|------------|
| **AES** | | | | |
| **RSA** | | | | |
| **ChaCha20** | | | | |
| **Blowfish** | | | | |

**Research Questions:**
1. Which encryption type is fastest for large files? Why?
2. Which is best for secure messaging? Why?
3. What's the difference between block and stream ciphers?
4. Why do we need different key lengths?

#### Encryption Algorithm Timeline

Create a timeline showing when major encryption algorithms were developed:

**1970s:** 
- _______________ (1976) - First public key cryptography
- _______________ (1977) - Early block cipher

**1980s:**
- _______________ (1985) - Popular public key algorithm
- _______________ (1987) - Fast alternative to DES

**1990s-2000s:**
- _______________ (1998) - Selected as AES winner
- _______________ (2008) - Modern stream cipher

### Exercise 2: File Encryption Hands-On Practice

#### Step 1: Basic File Encryption with GPG

```bash
# Create a test file to encrypt
echo "This is my super secret data for ICDFA lab!" > secret-data.txt
cat secret-data.txt

# Encrypt the file using GPG
gpg --symmetric --cipher-algo AES256 secret-data.txt

# What files do you see now?
ls -la secret-data.txt*

# Decrypt the file
gpg --decrypt secret-data.txt.gpg > decrypted-data.txt
cat decrypted-data.txt
```

**Observation Questions:**
1. What happened to the original file during encryption?
2. What's the file extension of the encrypted file?
3. Were you prompted for a passphrase? Why is this important?

#### Step 2: Advanced Encryption Options

```bash
# Create different encrypted versions
gpg --symmetric --cipher-algo CAMELLIA256 secret-data.txt -o secret-camellia.gpg
gpg --symmetric --cipher-algo TWOFISH secret-data.txt -o secret-twofish.gpg

# Compare file sizes
ls -la secret-*.gpg

# Try decrypting with wrong passphrase
gpg --decrypt secret-data.txt.gpg
# Enter wrong password and observe what happens
```

**Analysis Table:**

| Encryption Algorithm | File Size | Encryption Speed | Security Notes |
|---------------------|-----------|------------------|----------------|
| AES256 | | | |
| CAMELLIA256 | | | |
| TWOFISH | | | |

### Exercise 3: Directory Encryption with tar & GPG

#### Step 1: Create Sample Project Structure

```bash
# Create a project directory with sensitive files
mkdir my-secret-project
cd my-secret-project

echo "API_KEY=1234567890abcdef" > .env
echo "DB_PASSWORD=SuperSecret123!" >> .env
echo "Important business plans" > business-plan.docx
echo "Financial projections" > financials.xlsx

# View the sensitive data
cat .env
```

#### Step 2: Encrypt Entire Directory

```bash
# Create encrypted archive
tar czf - . | gpg --symmetric --cipher-algo AES256 -o project-backup.tar.gz.gpg

# Verify encryption worked
file project-backup.tar.gz.gpg

# Clean up original files (simulate secure deletion)
cd ..
rm -rf my-secret-project

# Restore from encrypted backup
gpg --decrypt project-backup.tar.gz.gpg | tar xzf -
ls -la my-secret-project/
```

**Security Scenario Questions:**
1. Why encrypt entire directories instead of individual files?
2. What's the advantage of combining tar and gpg?
3. How would this protect against stolen backup drives?
4. What additional security measures could you add?

### Exercise 4: Password Manager Simulation

#### Step 1: Create Encrypted Password File

```bash
# Create a structured password file
cat > passwords.txt << EOF
Website: bank.example.com
Username: john_doe
Password: Tr0ub4d0r!23
Notes: Main banking account

Website: email.provider.com
Username: john.doe@email.com
Password: S3cur3P@ssw0rd!
Notes: Primary email

Website: socialmedia.com
Username: johndoe
Password: MyS0c1alM3d1a!
Notes: Personal account
EOF

# Encrypt the password file
gpg --symmetric --cipher-algo AES256 passwords.txt

# Remove original
rm passwords.txt

# Practice accessing passwords
gpg --decrypt passwords.txt.gpg | grep -A2 "bank.example.com"
```

#### Step 2: Create Management Script

```bash
cat > password-manager.sh << 'EOF'
#!/bin/bash
PASSWORD_FILE="passwords.txt.gpg"

case $1 in
    "add")
        echo "Adding new password entry..."
        gpg --decrypt $PASSWORD_FILE 2>/dev/null
        echo -e "\nWebsite: $2\nUsername: $3\nPassword: $4\nNotes: $5\n" | gpg --symmetric --cipher-algo AES256 -o $PASSWORD_FILE
        ;;
    "view")
        echo "Viewing passwords..."
        gpg --decrypt $PASSWORD_FILE 2>/dev/null
        ;;
    "search")
        echo "Searching for: $2"
        gpg --decrypt $PASSWORD_FILE 2>/dev/null | grep -A3 -i "$2"
        ;;
    *)
        echo "Usage: $0 {add|view|search}"
        ;;
esac
EOF

chmod +x password-manager.sh

# Test your password manager
./password-manager.sh add "netflix.com" "john_doe" "MyStr0ngPass!" "Entertainment"
./password-manager.sh search "netflix"
```

**Password Security Analysis:**

| Security Practice | Why Important | Implementation in Script |
|-------------------|---------------|--------------------------|
| Encryption at rest | | |
| Master passphrase | | |
| Secure deletion | | |
| Access control | | |

---

## Part B: SSL/TLS Deep Dive & Analysis (120 minutes)

### Exercise 5: SSL/TLS Certificate Research

#### Certificate Authority Market Research

**Research Mission:** Investigate the top Certificate Authorities and complete the table:

| CA Name | Market Share | Certificate Types | Price Range | Validity Period | Special Features |
|---------|--------------|------------------|-------------|----------------|------------------|
| **Let's Encrypt** | | | | | |
| **DigiCert** | | | | | |
| **Sectigo** | | | | | |
| **GoDaddy** | | | | | |
| **GlobalSign** | | | | | |

**Research Questions:**
1. Why is Let's Encrypt able to offer free certificates?
2. What's the difference between DV, OV, and EV certificates?
3. Why do paid certificates cost more than free ones?
4. What factors should a business consider when choosing a CA?

#### Certificate Chain of Trust Mapping

Draw and label the complete trust chain for a website certificate:

```
[   ] Root Certificate Authority
     ↓
[   ] Intermediate CA 1
     ↓  
[   ] Intermediate CA 2
     ↓
[   ] Website Certificate
     ↓
[   ] Your Browser
```

**Trust Chain Questions:**
1. Why are intermediate CAs used?
2. What happens if a Root CA is compromised?
3. How does certificate revocation work?
4. What's the purpose of OCSP stapling?

### Exercise 6: Comprehensive SSL Analysis

#### Step 1: Website Security Assessment

Analyze 5 different websites and complete the security report:

| Website | SSL Grade | Certificate Issuer | Expiration Date | Protocols Supported | Vulnerabilities Found |
|---------|-----------|-------------------|----------------|---------------------|----------------------|
| https://www.google.com | | | | | |
| https://www.github.com | | | | | |
| https://www.wikipedia.org | | | | | |
| https://www.example.com | | | | | |
| https://www.ssllabs.com | | | | | |

**Tools to Use:**
- SSL Labs SSL Test (https://www.ssllabs.com/ssltest/)
- Browser Developer Tools
- OpenSSL command line

#### Step 2: Manual SSL Testing with OpenSSL

```bash
# Test specific SSL/TLS versions
echo "Testing TLS 1.2:"
openssl s_client -connect google.com:443 -tls1_2 < /dev/null 2>/dev/null | grep "Protocol"

echo "Testing TLS 1.3:"
openssl s_client -connect google.com:443 -tls1_3 < /dev/null 2>/dev/null | grep "Protocol"

# Check certificate details
openssl s_client -connect github.com:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -text -noout | grep -A1 "Subject:"
```

**Protocol Support Table:**

| Website | SSL 3.0 | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|---------|---------|---------|
| google.com | | | | | |
| github.com | | | | | |
| bankofamerica.com | | | | | |

### Exercise 7: Advanced SSL Configuration

#### Step 1: Create SSL Security Headers

Research and implement security headers in your Apache configuration:

```apache
# Add to your SSL virtual host configuration
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self' https:;"
```

**Security Header Research Table:**

| Header | Purpose | Recommended Value | Protection Against |
|--------|---------|-------------------|-------------------|
| HSTS | | | |
| X-Content-Type-Options | | | |
| X-Frame-Options | | | |
| CSP | | | |
| Referrer-Policy | | | |

#### Step 2: Cipher Suite Optimization

Research and configure secure cipher suites:

```apache
# Modern cipher suite configuration
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLProtocol All -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
```

**Cipher Suite Analysis:**

| Cipher Suite | Forward Secrecy | Strength | Compatibility |
|--------------|----------------|----------|---------------|
| ECDHE-RSA-AES128-GCM-SHA256 | | | |
| ECDHE-RSA-AES256-GCM-SHA384 | | | |
| AES128-SHA | | | |
| RC4-MD5 | | | |

### Exercise 8: Real-World SSL Migration Plan

#### Website Security Upgrade Scenario

**Scenario:** You're the security administrator for "ExampleCorp". Your website examplecorp.com currently has:
- TLS 1.0 only
- Self-signed certificate
- No security headers
- Mixed content issues

**Create a 6-month migration plan:**

**Month 1-2: Assessment & Planning**
- [ ] Current security assessment
- [ ] _______________
- [ ] _______________

**Month 3-4: Implementation**
- [ ] Purchase trusted certificate from _______________
- [ ] Configure _______________ protocol support
- [ ] Implement _______________ headers

**Month 5: Testing**
- [ ] _______________ testing with employees
- [ ] _______________ scan with SSL Labs
- [ ] Fix _______________ content issues

**Month 6: Go-Live & Monitoring**
- [ ] Enable _______________ enforcement
- [ ] Set up _______________ monitoring
- [ ] Document _______________ procedures

**Risk Assessment Table:**

| Migration Step | Potential Risks | Mitigation Strategies | Backup Plan |
|---------------|----------------|---------------------|-------------|
| Certificate Upgrade | | | |
| Protocol Disablement | | | |
| HSTS Implementation | | | |
| CSP Header | | | |

---

## Part C: Integrated Security Project (60 minutes)

### Exercise 9: Complete Security Implementation

#### Project: Secure Document Management System

**Requirements:**
1. Encrypt sensitive documents at rest
2. Secure transmission via HTTPS
3. Access control and auditing
4. Backup and recovery

#### Step 1: Document Encryption Setup

```bash
# Create document management structure
mkdir -p secure-docs/{incoming,processed,backup}
cd secure-docs

# Create sample sensitive documents
echo "Confidential: Q4 Financial Report" > incoming/report.txt
echo "Employee: John Doe - Salary: $75,000" > incoming/salaries.txt
echo "Project Alpha - Secret Plans" > incoming/project-alpha.docx

# Create encryption script
cat > encrypt-docs.sh << 'EOF'
#!/bin/bash
for file in incoming/*; do
    if [ -f "$file" ]; then
        echo "Encrypting: $file"
        gpg --symmetric --cipher-algo AES256 --batch --passphrase "MySecurePass123!" "$file"
        mv "$file.gpg" processed/
        # Securely delete original
        shred -u "$file"
    fi
done
echo "Documents encrypted and secured"
EOF

chmod +x encrypt-docs.sh
```

#### Step 2: Create Access Log System

```bash
# Create access logging
cat > access-doc.sh << 'EOF'
#!/bin/bash
DOCUMENT=$1
USER=$(whoami)
DATE=$(date +"%Y-%m-%d %H:%M:%S")

echo "[$DATE] ACCESS: User $USER accessed $DOCUMENT" >> access.log

gpg --decrypt --batch --passphrase "MySecurePass123!" "processed/$DOCUMENT.gpg"
EOF

chmod +x access-doc.sh
```

#### Step 3: Security Monitoring

```bash
# Create security monitor
cat > security-monitor.sh << 'EOF'
#!/bin/bash
echo "=== SECURITY STATUS REPORT ==="
echo "Generated: $(date)"

echo -e "\n🔐 ENCRYPTED DOCUMENTS:"
ls -la processed/*.gpg | wc -l

echo -e "\n📊 ACCESS LOG SUMMARY:"
tail -10 access.log

echo -e "\n🔍 SSL/TLS STATUS:"
openssl s_client -connect localhost:443 -tlsextdebug 2>/dev/null | grep "TLS" | head -5

echo -e "\n✅ SECURITY CHECKS COMPLETE"
EOF

chmod +x security-monitor.sh
```

### Exercise 10: Comprehensive Security Audit

#### Complete Security Assessment Checklist

**Data Encryption Audit:**
- [ ] All sensitive files encrypted with _______________
- [ ] Encryption keys stored _______________
- [ ] Backup encryption implemented _______________
- [ ] Key rotation policy: Every _______________ days

**SSL/TLS Configuration Audit:**
- [ ] TLS 1.2 enabled: ☐ Yes ☐ No
- [ ] TLS 1.3 enabled: ☐ Yes ☐ No
- [ ] Weak ciphers disabled: ☐ Yes ☐ No  
- [ ] HSTS implemented: ☐ Yes ☐ No
- [ ] Certificate expires: _______________

**Access Control Audit:**
- [ ] Document access logged: ☐ Yes ☐ No
- [ ] Failed access attempts monitored: ☐ Yes ☐ No
- [ ] Encryption passphrase strength: _______________
- [ ] Backup access restricted: ☐ Yes ☐ No

**Security Compliance Scorecard:**

| Category | Current Score | Target Score | Gap Analysis |
|----------|---------------|--------------|--------------|
| Data Encryption | /10 | /10 | |
| SSL/TLS Security | /10 | /10 | |
| Access Control | /10 | /10 | |
| Monitoring | /10 | /10 | |
| **Overall** | **/40** | **/40** | |

---

## Final Lab Assignment: Security Architect Report

### Create Comprehensive Security Documentation

**Section 1: Executive Summary**
- Current security posture assessment
- Key risks identified
- Priority recommendations

**Section 2: Data Encryption Strategy**
- Encryption methods implemented
- Key management procedures
- Backup and recovery processes

**Section 3: SSL/TLS Configuration**
- Current protocol support
- Certificate management
- Security headers implementation

**Section 4: Access Control & Monitoring**
- User access logging
- Security monitoring procedures
- Incident response plan

**Section 5: Compliance & Best Practices**
- Industry standards alignment
- Regular audit procedures
- Continuous improvement plan

### Report Requirements

- **Length:** 5-7 pages including diagrams
- **Format:** Professional business report
- **Diagrams:** Include encryption flowcharts and SSL trust chains
- **Appendices:** Include configuration files and scripts
- **Recommendations:** Actionable security improvements

---

## Bonus Challenges

### Challenge 1: Automated Security Scanner
Create a script that automatically:
- Checks SSL/TLS configuration of multiple websites
- Tests file encryption integrity
- Generates security reports
- Sends alerts for issues found

### Challenge 2: Disaster Recovery Plan
Design a complete disaster recovery plan including:
- Encrypted backup procedures
- Certificate recovery process
- Data restoration testing
- Emergency access protocols

### Challenge 3: Security Training Program
Create a 30-minute security training covering:
- Data encryption basics
- SSL/TLS recognition
- Secure file handling
- Incident reporting procedures

---

## Lab Completion Checklist

### Part A: Data Encryption Mastery
- [ ] Completed encryption research tables
- [ ] Successfully encrypted/decrypted files
- [ ] Created directory encryption system
- [ ] Built password manager simulation
- [ ] Understand encryption algorithms

### Part B: SSL/TLS Deep Dive
- [ ] Researched Certificate Authorities
- [ ] Analyzed multiple website SSL configurations
- [ ] Implemented security headers
- [ ] Optimized cipher suites
- [ ] Created migration plan

### Part C: Integrated Security
- [ ] Built document management system
- [ ] Implemented access logging
- [ ] Created security monitoring
- [ ] Completed security audit
- [ ] Written comprehensive report

### Final Deliverables
- [ ] All completed exercise tables
- [ ] Working encryption scripts
- [ ] SSL configuration files
- [ ] Security audit checklist
- [ ] Comprehensive final report

---

## Key Takeaways & Course Completion

**🎓 Congratulations! You've mastered:**

### Data Protection
- File and directory encryption techniques
- Encryption algorithm selection
- Key management best practices
- Secure backup procedures

### Web Security
- SSL/TLS protocol configuration
- Certificate authority management
- Security headers implementation
- Comprehensive security testing

### Real-World Skills
- Security assessment and auditing
- Risk analysis and mitigation
- Security documentation
- Implementation planning

### Career Applications
- Security Administration
- DevOps Security
- Compliance Auditing
- Security Consulting

**Your Security Journey Continues...**
"Security is not a destination, but a continuous journey. The skills you've learned here form the foundation for protecting digital assets everywhere. Stay curious, keep learning, and remember: every system you secure makes the internet safer for everyone."

---


**Final Thought:** "The best time to implement security was yesterday. The second best time is now. Go forth and secure!"
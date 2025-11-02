# Week 4 Lab: CVE Mapping & Vulnerability Fundamentals for Beginners

## Lab Overview
**Course:** BVWS102 – Web Application Security Essentials  
**Week:** 4  
**Lab Title:** CVE Discovery & Vulnerability Mapping  
**Duration:** 3-4 hours  
**Difficulty:** Beginner  
**Objectives:** Understand CVEs, map vulnerabilities to real-world examples, practice basic security concepts.

---

## Lab Introduction

Welcome to your introduction to Common Vulnerabilities and Exposures (CVEs)! This lab will help you understand how security vulnerabilities are documented and categorized in the real world. You'll learn to read CVE descriptions, understand risk ratings, and map them to practical examples.

### Learning Objectives
By completing this lab, you will be able to:
- Understand what CVEs are and how they're structured
- Read and interpret CVE descriptions
- Map CVEs to real-world vulnerability types
- Practice basic vulnerability identification
- Create simple security assessments

---

## Pre-Lab Setup

### What You'll Need
- Web browser with internet access
- Text editor
- Basic understanding of web concepts from previous weeks

### Important Note
This is a **theory and mapping exercise** - no complex coding required! We'll use simple, safe examples to learn.

---

## Exercise 1: CVE Fundamentals & Structure (45 minutes)

### Understanding CVE Basics

**What is a CVE?**
CVE stands for **Common Vulnerabilities and Exposures**. It's like a universal dictionary that security professionals use to discuss vulnerabilities.

**CVE Format: CVE-YEAR-IDNUMBER**
Example: **CVE-2021-44228**
- **CVE**: Common Vulnerabilities and Exposures
- **2021**: The year the CVE was assigned
- **44228**: A unique identifier number

### CVSS Scores - Measuring Severity

CVSS (Common Vulnerability Scoring System) rates how dangerous a vulnerability is:

| Score Range | Severity | Description |
|-------------|----------|-------------|
| 0.1-3.9 | Low | Minor issues, hard to exploit |
| 4.0-6.9 | Medium | Concerning, but limited impact |
| 7.0-8.9 | High | Serious, can cause significant damage |
| 9.0-10.0 | Critical | Emergency! Can compromise entire systems |

### Hands-On Activity: CVE Identification

**Exercise 1.1:** Break down these CVEs:

| CVE ID | Year | ID Number |
|--------|------|-----------|
| CVE-2019-11510 | | |
| CVE-2018-15133 | | |
| CVE-2021-41773 | | |

**Exercise 1.2:** Match the severity levels:

1. CVE-2021-44228 - Score: 10.0 → [ ] Low [ ] Medium [ ] High [ ] Critical
2. CVE-2021-41773 - Score: 9.8 → [ ] Low [ ] Medium [ ] High [ ] Critical
3. CVE-2017-5638 - Score: 10.0 → [ ] Low [ ] Medium [ ] High [ ] Critical

---

## Exercise 2: Famous CVEs Research & Mapping (60 minutes)

### Research Mission

Your task is to research these famous CVEs and complete the information cards.

**Research Sources:**
- https://cve.mitre.org
- https://nvd.nist.gov/vuln/search
- https://www.cvedetails.com

### CVE Research Cards

**CVE-2021-44228 - Log4Shell**
- CVSS Score: _________
- Severity Level: [ ] Low [ ] Medium [ ] High [ ] Critical
- Vulnerability Type: _________________
- Affected Software: _________________
- Simple Description: 
  ___________________________________
  ___________________________________

**CVE-2021-41773 - Apache Path Traversal**
- CVSS Score: _________
- Severity Level: [ ] Low [ ] Medium [ ] High [ ] Critical
- Vulnerability Type: _________________
- Affected Software: _________________
- Simple Description: 
  ___________________________________
  ___________________________________

**CVE-2019-11510 - Pulse VPN**
- CVSS Score: _________
- Severity Level: [ ] Low [ ] Medium [ ] High [ ] Critical
- Vulnerability Type: _________________
- Affected Software: _________________
- Simple Description: 
  ___________________________________
  ___________________________________

### Research Tips:
- Start with the official CVE description
- Look for "CVSS Score" in vulnerability databases
- Read multiple sources for better understanding
- Focus on understanding what the vulnerability allows attackers to do
- Note which versions of software are affected

---

## Exercise 3: Vulnerability Type Matching Game (45 minutes)

### Matching Game Instructions

Match each CVE with its correct vulnerability type by drawing lines or writing the corresponding letters:

**Column A - CVEs**
1. CVE-2021-44228 (Log4Shell)
2. CVE-2021-41773 (Apache Path Traversal)  
3. CVE-2019-11510 (Pulse VPN)
4. CVE-2018-15133 (Laravel)

**Column B - Vulnerability Types**
A. Remote Code Execution (RCE) - Allows attackers to run commands on the server
B. Path Traversal - Access files outside intended directory
C. Arbitrary File Read - Read any file on the system
D. Insecure Deserialization - Untrusted data execution during deserialization

**Your Matches:**
1. → _____
2. → _____
3. → _____
4. → _____

### Answer Key Discussion

After completing the matching, discuss:
- Why each CVE matches its vulnerability type
- What makes each vulnerability dangerous
- How attackers might exploit these vulnerabilities
- What steps organizations should take to protect themselves

---

## Exercise 4: Vulnerability Impact Analysis (45 minutes)

### Real-World Impact Assessment

For each CVE below, analyze and document the potential impacts:

**CVE-2021-44228 (Log4Shell)**
- What could attackers do? 
  ___________________________________
  ___________________________________
- Which systems were affected?
  ___________________________________
166- Business impact:
  ___________________________________

**CVE-2021-41773 (Apache Path Traversal)**
- What could attackers do?
  ___________________________________
  ___________________________________
- Which systems were affected?
  ___________________________________
- Business impact:
  ___________________________________

**CVE-2019-11510 (Pulse VPN)**
- What could attackers do?
  ___________________________________
  ___________________________________
- Which systems were affected?
  ___________________________________
- Business impact:
  ___________________________________

### Severity Comparison Chart

Create a chart comparing the three CVEs:

| CVE | CVSS Score | Severity | Exploitation Complexity | Potential Damage |
|-----|------------|----------|------------------------|------------------|
| CVE-2021-44228 | | | | |
| CVE-2021-41773 | | | | |
| CVE-2019-11510 | | | | |

**Discussion Questions:**
1. Which CVE do you think was most dangerous and why?
2. What factors make a vulnerability "critical" vs "high" severity?
3. How could organizations have prevented these vulnerabilities?

---

## Exercise 5: CVE Timeline Creation (30 minutes)

### Vulnerability History Timeline

Create a timeline showing when these major CVEs were discovered:

**2017**
- CVE-2017-5638: Apache Struts vulnerability
  Impact: ___________________________________

**2018** 
- CVE-2018-15133: Laravel vulnerability
  Impact: ___________________________________

**2019**
- CVE-2019-11510: Pulse VPN vulnerability
  Impact: ___________________________________

**2021**
- CVE-2021-41773: Apache Path Traversal
  Impact: ___________________________________
- CVE-2021-44228: Log4Shell
  Impact: ___________________________________

### Pattern Recognition

What patterns do you notice in the timeline?
- Are certain years particularly bad for vulnerabilities?
- Do you see trends in vulnerability types?
- How has vulnerability discovery evolved over time?

---

## Exercise 6: Defense Strategies Mapping (30 minutes)

### Vulnerability Prevention Chart

For each vulnerability type, identify prevention measures:

| Vulnerability Type | Prevention Method 1 | Prevention Method 2 | Prevention Method 3 |
|-------------------|---------------------|---------------------|---------------------|
| Remote Code Execution | | | |
| Path Traversal | | | |
| Arbitrary File Read | | | |
| Insecure Deserialization | | | |

### Security Control Identification

Match security controls to vulnerabilities:

**Security Controls:**
- Input validation
- Output encoding
- Access controls
- Secure configuration
- Regular patching
- Web Application Firewall (WAF)

**Which controls help prevent which vulnerabilities?**
- CVE-2021-44228: __________, __________, __________
- CVE-2021-41773: __________, __________, __________  
- CVE-2019-11510: __________, __________, __________

---

## Lab Assignment: CVE Analyst Report

### Create Your First Vulnerability Report

Using the information gathered in previous exercises, create a comprehensive CVE analysis report:

**Section 1: Executive Summary**
- Brief overview of the 3 CVEs analyzed
- Overall risk assessment
- Key recommendations

**Section 2: CVE Details**
For each CVE (choose 3 from the lab):
- CVE identifier and name
- CVSS score and severity
- Vulnerability type
- Affected software/versions
- Brief description

**Section 3: Impact Analysis**
- What attackers could achieve
- Business consequences
- Systems affected

**Section 4: Prevention Strategies**
- Immediate actions needed
- Long-term security improvements
- Monitoring recommendations

**Section 5: Learning Outcomes**
- What you learned about vulnerability management
- How this knowledge applies to real-world security
- Key takeaways for future security practices

### Report Grading Rubric

| Criteria | Excellent (4) | Good (3) | Satisfactory (2) | Needs Improvement (1) |
|----------|---------------|----------|------------------|---------------------|
| **CVE Understanding** | Deep understanding of all CVEs | Good understanding | Basic comprehension | Limited understanding |
| **Impact Analysis** | Comprehensive impact assessment | Good impact analysis | Basic impact description | Poor analysis |
| **Prevention Strategies** | Practical, detailed prevention methods | Good prevention ideas | Basic suggestions | Inadequate suggestions |
| **Report Quality** | Professional, well-organized | Good organization | Basic structure | Poor organization |
| **Learning Reflection** | Insightful, applicable reflections | Good reflections | Basic reflections | Poor reflections |

---

## Bonus Challenges

### Challenge 1: Recent CVE Research
Research a CVE from the current year and:
- Document its details
- Analyze its potential impact
- Suggest prevention measures
- Compare it to historical CVEs

### Challenge 2: Vulnerability Family Tree
Create a diagram showing how different vulnerability types relate to each other and which CVEs belong to each family.

### Challenge 3: Security News Analysis
Find a recent news article about a security breach and:
- Identify which CVE might be involved
- Analyze how the vulnerability was exploited
- Suggest how it could have been prevented

---

## Lab Completion Checklist

- [ ] Completed CVE identification exercises
- [ ] Researched and documented 3 major CVEs
- [ ] Successfully matched CVEs to vulnerability types
- [ ] Analyzed real-world impacts of vulnerabilities
- [ ] Created vulnerability timeline
- [ ] Mapped prevention strategies
- [ ] Written comprehensive CVE analyst report
- [ ] Participated in discussion and reflection

---

## Key Takeaways

**By completing this lab, you now understand:**
- How CVEs are structured and categorized
- How to research and analyze vulnerabilities
- The real-world impact of major security vulnerabilities
- Basic vulnerability prevention strategies
- How to create professional vulnerability reports

**Remember:** "Knowing about vulnerabilities is the first step toward preventing them. Every CVE represents a lesson learned in cybersecurity."

This foundation in CVE understanding will serve you well as you continue your cybersecurity journey. You're now equipped with the basic knowledge to understand security advisories, participate in security discussions, and begin thinking like a security professional.

**Next Steps:** Continue following security news, practice researching new CVEs as they're published, and consider setting up alerts for vulnerabilities in software you commonly use.
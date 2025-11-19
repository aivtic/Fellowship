# LAB-1.2.4: Hands-on Linux Permission Setting and Management

## Lab Overview

**Course:** BVWS101 – Foundations of Linux, Networking & Bash Scripting  
**Lab Code:** LAB-1.2.4  
**Lab Title:** Hands-on Linux Permission Setting and Management  
**Duration:** 2-3 hours  
**Difficulty:** Beginner to Intermediate  
**Objectives:** Master advanced user management, group administration, sudo configuration, and Access Control Lists (ACLs) for secure system administration.

---

## Lab Introduction

As a web application security professional, you'll frequently need to manage users, configure permissions, and implement the principle of least privilege. This lab builds on basic Linux permissions and introduces advanced user management concepts critical for securing production systems.

### Learning Objectives

By completing this lab, you will be able to:
- Create and manage user accounts and groups
- Configure sudo access with appropriate restrictions
- Implement Access Control Lists (ACLs) for fine-grained permissions
- Apply the principle of least privilege in real scenarios
- Audit user activity and permissions
- Troubleshoot common permission issues
- Secure multi-user environments

---

## Lab Setup

### Prerequisites
- Kali Linux VM or Ubuntu/Debian system
- Root or sudo access
- Completion of LAB-1.1.3 (Linux CLI basics)
- Basic understanding of Linux file permissions

### Lab Environment
```bash
# Create lab directory
mkdir -p ~/fellowship-labs/week2
cd ~/fellowship-labs/week2

# Verify sudo access
sudo -v
```

---

## Part 1: User Account Management (40 minutes)

### Exercise 1.1: Creating and Managing Users

**Task 1:** Create user accounts for a development team

```bash
# Create users
sudo useradd -m -s /bin/bash developer1
sudo useradd -m -s /bin/bash developer2
sudo useradd -m -s /bin/bash tester1

# Set passwords
sudo passwd developer1
# Enter password: Dev@2024!

sudo passwd developer2
# Enter password: Dev@2024!

sudo passwd tester1
# Enter password: Test@2024!

# Verify users were created
cat /etc/passwd | grep -E "developer|tester"

# Check home directories
ls -la /home/

# View user details
id developer1
finger developer1  # Install if needed: sudo apt install finger
```

**Understanding useradd flags:**
- `-m` : Create home directory
- `-s` : Specify shell
- `-c` : Add comment/full name
- `-e` : Set expiration date
- `-G` : Add to supplementary groups

**Task 2:** Create users with additional options

```bash
# Create user with full details
sudo useradd -m -s /bin/bash -c "John Doe, Security Analyst" -e 2025-12-31 analyst1

# Create user with specific UID
sudo useradd -m -u 2001 -s /bin/bash customuser

# Create system user (for services)
sudo useradd -r -s /usr/sbin/nologin webapp_service

# Verify
cat /etc/passwd | tail -5
```

---

### Exercise 1.2: Modifying User Accounts

**Task 3:** Modify existing user properties

```bash
# Change user's shell
sudo usermod -s /bin/zsh developer1

# Change user's home directory
sudo usermod -d /home/newdev1 -m developer1

# Lock user account (disable login)
sudo usermod -L developer2
# Or
sudo passwd -l developer2

# Unlock user account
sudo usermod -U developer2
# Or
sudo passwd -u developer2

# Set account expiration
sudo usermod -e 2025-06-30 tester1

# Change username
sudo usermod -l newname developer2

# Verify changes
sudo chage -l tester1  # View password aging info
```

---

### Exercise 1.3: Deleting Users

**Task 4:** Remove user accounts safely

```bash
# Delete user but keep home directory
sudo userdel developer1

# Delete user and home directory
sudo userdel -r tester1

# Force delete (even if logged in)
sudo userdel -f customuser

# Find and remove user files
sudo find / -user oldusername -exec rm -rf {} \; 2>/dev/null

# Verify deletion
cat /etc/passwd | grep developer1
ls /home/
```

**Security Best Practice:** Always backup user data before deletion!

---

## Part 2: Group Management (40 minutes)

### Exercise 2.1: Creating and Managing Groups

**Task 5:** Set up groups for project teams

```bash
# Create groups
sudo groupadd developers
sudo groupadd testers
sudo groupadd security
sudo groupadd webadmins

# Create group with specific GID
sudo groupadd -g 3001 database_admins

# View all groups
cat /etc/group

# View specific group
getent group developers

# Add users to groups
sudo usermod -aG developers developer1
sudo usermod -aG developers developer2
sudo usermod -aG testers tester1
sudo usermod -aG security analyst1

# Add user to multiple groups
sudo usermod -aG developers,security,webadmins developer1

# Verify group membership
groups developer1
id developer1
```

**Important:** Use `-aG` (append to groups) not `-G` alone, which replaces all groups!

---

### Exercise 2.2: Group Permissions in Practice

**Task 6:** Create shared project directories

```bash
# Create project structure
sudo mkdir -p /projects/{webapp,api,database}

# Set group ownership
sudo chgrp developers /projects/webapp
sudo chgrp developers /projects/api
sudo chgrp database_admins /projects/database

# Set permissions for group collaboration
sudo chmod 770 /projects/webapp
sudo chmod 770 /projects/api
sudo chmod 750 /projects/database

# Set SGID bit (files inherit group)
sudo chmod g+s /projects/webapp
sudo chmod g+s /projects/api

# Verify
ls -la /projects/

# Test as developer1
sudo -u developer1 bash -c "
    cd /projects/webapp
    touch test_file.txt
    ls -l test_file.txt
"
# File should have 'developers' group
```

---

### Exercise 2.3: Managing Group Membership

**Task 7:** Advanced group operations

```bash
# Remove user from group
sudo gpasswd -d developer1 security

# Add multiple users to group
for user in developer1 developer2; do
    sudo usermod -aG webadmins $user
done

# Set group administrator
sudo gpasswd -A developer1 developers

# Change user's primary group
sudo usermod -g developers developer1

# View group members
getent group developers

# List all groups a user belongs to
groups developer1
id -Gn developer1
```

---

## Part 3: Sudo Configuration (45 minutes)

### Exercise 3.1: Understanding Sudo

**Task 8:** Configure sudo access

```bash
# View sudo configuration
sudo cat /etc/sudoers

# NEVER edit directly! Use visudo
sudo visudo

# Check sudo privileges
sudo -l

# View sudo log
sudo cat /var/log/auth.log | grep sudo
```

**Sudo Syntax:**
```
user    host=(run_as_user) commands
```

---

### Exercise 3.2: Granting Sudo Access

**Task 9:** Configure different levels of sudo access

```bash
# Edit sudoers file
sudo visudo

# Add these lines:

# Full sudo access (like root)
developer1 ALL=(ALL:ALL) ALL

# Sudo without password (DANGEROUS!)
developer2 ALL=(ALL) NOPASSWD: ALL

# Limited commands only
tester1 ALL=(ALL) /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx

# Run as specific user
analyst1 ALL=(www-data) /usr/bin/php

# Group-based sudo
%developers ALL=(ALL) /usr/bin/apt update, /usr/bin/apt upgrade

# Alias for command groups
Cmnd_Alias WEBADMIN = /usr/bin/systemctl restart apache2, /usr/bin/systemctl restart nginx
%webadmins ALL=(ALL) WEBADMIN
```

**Test sudo access:**

```bash
# As developer1 (full access)
sudo -u developer1 sudo apt update

# As tester1 (limited)
sudo -u tester1 sudo systemctl status nginx  # Should work
sudo -u tester1 sudo apt update  # Should fail

# As analyst1 (run as www-data)
sudo -u analyst1 sudo -u www-data php -v
```

---

### Exercise 3.3: Sudo Security Best Practices

**Task 10:** Implement secure sudo configuration

```bash
# Create sudo configuration file for developers
sudo visudo -f /etc/sudoers.d/developers

# Add secure configuration:
# Require password re-entry every time
Defaults    timestamp_timeout=0

# Log all sudo commands
Defaults    logfile=/var/log/sudo.log
Defaults    log_input, log_output

# Require TTY (prevent some attacks)
Defaults    requiretty

# Restrict environment variables
Defaults    env_reset
Defaults    env_keep="LANG LC_* HOME"

# Specific user configuration
developer1 ALL=(ALL) /usr/bin/systemctl, /usr/bin/journalctl

# Verify syntax
sudo visudo -c -f /etc/sudoers.d/developers

# View sudo logs
sudo cat /var/log/sudo.log
```

---

## Part 4: Access Control Lists (ACLs) (45 minutes)

### Exercise 4.1: Understanding ACLs

**What are ACLs?**

ACLs provide more fine-grained permissions than traditional Unix permissions. They allow you to:
- Grant permissions to multiple users/groups on the same file
- Set default permissions for new files
- Implement complex permission schemes

**Task 11:** Check ACL support and install tools

```bash
# Check if filesystem supports ACLs
mount | grep acl

# Install ACL tools
sudo apt install acl -y

# Verify installation
getfacl --version
setfacl --version
```

---

### Exercise 4.2: Setting ACLs

**Task 12:** Implement ACLs for shared resources

```bash
# Create test environment
mkdir -p ~/fellowship-labs/week2/acl_test
cd ~/fellowship-labs/week2/acl_test

# Create test file
echo "Confidential project data" > project_data.txt

# View current permissions
ls -l project_data.txt
getfacl project_data.txt

# Grant read access to specific user
setfacl -m u:developer1:r project_data.txt

# Grant write access to specific user
setfacl -m u:developer2:rw project_data.txt

# Grant access to group
setfacl -m g:developers:rw project_data.txt

# View ACL
getfacl project_data.txt

# Notice the '+' in ls -l output
ls -l project_data.txt
```

---

### Exercise 4.3: Advanced ACL Operations

**Task 13:** Complex ACL scenarios

```bash
# Remove specific ACL entry
setfacl -x u:developer1 project_data.txt

# Remove all ACLs
setfacl -b project_data.txt

# Set default ACLs for directory
mkdir shared_project
setfacl -d -m g:developers:rwx shared_project/

# New files inherit these permissions
touch shared_project/newfile.txt
getfacl shared_project/newfile.txt

# Copy ACLs from one file to another
getfacl project_data.txt | setfacl --set-file=- another_file.txt

# Recursive ACL setting
setfacl -R -m u:analyst1:rx /projects/webapp/

# Mask (maximum permissions)
setfacl -m m::rx project_data.txt
getfacl project_data.txt
```

---

### Exercise 4.4: ACL Backup and Restore

**Task 14:** Backup and restore ACLs

```bash
# Backup ACLs
getfacl -R /projects > ~/acl_backup.txt

# View backup
cat ~/acl_backup.txt

# Restore ACLs
setfacl --restore=~/acl_backup.txt

# Backup with tar (preserves ACLs)
tar --acls -czf project_backup.tar.gz /projects/

# Restore with ACLs
tar --acls -xzf project_backup.tar.gz
```

---

## Part 5: Practical Security Scenarios (40 minutes)

### Exercise 5.1: Web Application Deployment

**Scenario:** Deploy a web application with proper user/group setup

**Task 15:** Configure secure web application environment

```bash
# Create web application user
sudo useradd -r -s /usr/sbin/nologin -d /var/www/myapp webapp

# Create web application group
sudo groupadd webdev

# Add developers to webdev group
sudo usermod -aG webdev developer1
sudo usermod -aG webdev developer2

# Create application directory
sudo mkdir -p /var/www/myapp/{public,logs,config,uploads}

# Set ownership
sudo chown -R webapp:webdev /var/www/myapp

# Set base permissions
sudo chmod 750 /var/www/myapp
sudo chmod 755 /var/www/myapp/public
sudo chmod 770 /var/www/myapp/uploads
sudo chmod 750 /var/www/myapp/config
sudo chmod 770 /var/www/myapp/logs

# Set SGID on directories
sudo chmod g+s /var/www/myapp/uploads
sudo chmod g+s /var/www/myapp/logs

# Restrict config files
sudo chmod 640 /var/www/myapp/config/*

# Set ACLs for developers
sudo setfacl -R -m g:webdev:rwx /var/www/myapp
sudo setfacl -R -d -m g:webdev:rwx /var/www/myapp

# Verify
ls -la /var/www/myapp/
getfacl /var/www/myapp/
```

---

### Exercise 5.2: Database Server Security

**Task 16:** Secure database environment

```bash
# Create database user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/mysql mysql_app

# Create database admin group
sudo groupadd dbadmins

# Add administrators
sudo usermod -aG dbadmins analyst1

# Create database directories
sudo mkdir -p /var/lib/mysql_app/{data,logs,backups}

# Set ownership
sudo chown -R mysql_app:mysql_app /var/lib/mysql_app

# Set permissions (very restrictive)
sudo chmod 700 /var/lib/mysql_app/data
sudo chmod 750 /var/lib/mysql_app/logs
sudo chmod 750 /var/lib/mysql_app/backups

# Give dbadmins read access to logs
sudo setfacl -m g:dbadmins:rx /var/lib/mysql_app/logs

# Configure sudo for database operations
sudo visudo -f /etc/sudoers.d/database

# Add:
# %dbadmins ALL=(mysql_app) NOPASSWD: /usr/bin/mysql, /usr/bin/mysqldump
```

---

### Exercise 5.3: Security Audit

**Task 17:** Audit user permissions and identify issues

```bash
# Find files with SUID bit
sudo find / -type f -perm -4000 -ls 2>/dev/null

# Find world-writable files
sudo find / -type f -perm -002 -ls 2>/dev/null

# Find files with no owner
sudo find / -nouser -ls 2>/dev/null

# Find files with no group
sudo find / -nogroup -ls 2>/dev/null

# List users with sudo access
sudo grep -E '^[^#]' /etc/sudoers /etc/sudoers.d/*

# List users with empty passwords
sudo awk -F: '($2 == "") {print $1}' /etc/shadow

# List users with UID 0 (root equivalent)
sudo awk -F: '($3 == 0) {print $1}' /etc/passwd

# Check password policies
sudo chage -l developer1

# View recent logins
last -n 20
lastlog

# View failed login attempts
sudo lastb -n 20

# Check for accounts that never expire
sudo awk -F: '{if ($2 == "") print $1}' /etc/shadow
```

---

## Part 6: Lab Challenge (30 minutes)

### Challenge: Secure Multi-Tenant Environment

**Scenario:** You're setting up a shared development server for three teams. Each team needs:
- Isolated workspace
- Shared team directory
- Limited sudo access
- Proper logging

**Requirements:**

1. **Create three teams:**
   - Team Alpha (3 developers)
   - Team Beta (2 developers)
   - Team Gamma (2 developers + 1 admin)

2. **Each team needs:**
   - Private team directory (team members only)
   - Shared project directory (with proper ACLs)
   - Team-specific sudo permissions

3. **Security requirements:**
   - No team can access another team's files
   - Admins can read all team directories
   - All sudo commands must be logged
   - Implement password policies

**Solution Framework:**

```bash
# 1. Create users
for team in alpha beta gamma; do
    for i in {1..3}; do
        sudo useradd -m -s /bin/bash ${team}_dev${i}
        echo "${team}_dev${i}:Password@2024" | sudo chpasswd
    done
done

# 2. Create groups
sudo groupadd team_alpha
sudo groupadd team_beta
sudo groupadd team_gamma
sudo groupadd admins

# 3. Assign users to groups
sudo usermod -aG team_alpha alpha_dev1 alpha_dev2 alpha_dev3
sudo usermod -aG team_beta beta_dev1 beta_dev2
sudo usermod -aG team_gamma gamma_dev1 gamma_dev2
sudo usermod -aG team_gamma,admins gamma_dev3

# 4. Create directory structure
for team in alpha beta gamma; do
    sudo mkdir -p /projects/team_${team}/{private,shared}
    sudo chgrp team_${team} /projects/team_${team}
    sudo chmod 2770 /projects/team_${team}/private
    sudo chmod 2775 /projects/team_${team}/shared
done

# 5. Set ACLs for admins
for team in alpha beta gamma; do
    sudo setfacl -R -m g:admins:rx /projects/team_${team}
    sudo setfacl -R -d -m g:admins:rx /projects/team_${team}
done

# 6. Configure sudo
sudo visudo -f /etc/sudoers.d/teams

# Add team-specific permissions
# %team_alpha ALL=(ALL) /usr/bin/systemctl restart webapp_alpha
# %team_beta ALL=(ALL) /usr/bin/systemctl restart webapp_beta
# %team_gamma ALL=(ALL) /usr/bin/systemctl restart webapp_gamma
# %admins ALL=(ALL) ALL

# 7. Verify setup
ls -la /projects/
getfacl /projects/team_alpha/
sudo -l -U alpha_dev1
```

---

## Verification and Testing

### Checklist

- [ ] Can create, modify, and delete user accounts
- [ ] Can create and manage groups
- [ ] Can add/remove users from groups
- [ ] Understand and can configure sudo access
- [ ] Can implement ACLs for fine-grained permissions
- [ ] Can audit user permissions and identify issues
- [ ] Can apply principle of least privilege
- [ ] Can troubleshoot permission problems

### Self-Test

1. What's the difference between `usermod -G` and `usermod -aG`?
2. How do you grant sudo access without requiring a password?
3. What does the SGID bit do on a directory?
4. How do ACLs differ from traditional Unix permissions?
5. How do you find all files owned by a specific user?

---

## Cleanup

```bash
# Remove test users
for user in developer1 developer2 tester1 analyst1; do
    sudo userdel -r $user 2>/dev/null
done

# Remove test groups
for group in developers testers security webadmins; do
    sudo groupdel $group 2>/dev/null
done

# Remove test directories
sudo rm -rf /projects
sudo rm -rf ~/fellowship-labs/week2/acl_test

# Or keep for reference
echo "Lab completed on $(date)" > ~/fellowship-labs/week2/completion.txt
```

---

## Submission Requirements

Submit the following:

1. **Lab Report** including:
   - Screenshots of user/group creation
   - Sudo configuration examples
   - ACL implementation screenshots
   - Security audit results

2. **Challenge Solution:**
   - Complete script for multi-tenant setup
   - Verification screenshots
   - Security analysis

3. **Reflection** (300-400 words) on:
   - Most challenging aspect
   - Real-world applications
   - Security implications of improper permissions

---

## Additional Resources

### Documentation
- [Linux User Management](https://www.linux.com/training-tutorials/how-manage-users-groups-linux/)
- [Sudo Manual](https://www.sudo.ws/docs/man/sudo.man/)
- [ACL Guide](https://www.redhat.com/sysadmin/linux-access-control-lists)
- [Security Best Practices](https://www.cyberciti.biz/tips/linux-security.html)

### Tools
- `useradd`, `usermod`, `userdel` - User management
- `groupadd`, `groupmod`, `groupdel` - Group management
- `sudo`, `visudo` - Privilege escalation
- `setfacl`, `getfacl` - ACL management
- `chage` - Password aging

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**

---
layout: post
title: "Detecting and Removing Webshells in Wordpress - Part 1"
date: 2025-05-08
categories: [blueteam]
tags: [hardening, bash, malware analysis]
---

This guide is an attempt to identify and remove the most common artifacts and persistence mechanisms seen in the wild in compromised wordpress/php servers.

## Looking for suspicious files

A good starting point would be to scan the server’s file system for files that could be used as backdoors/webshells:

### Find recently modified files
Checking the recently modified files is a good way to start tracking the activities from attackers. 
For example, to find all the files modified in the last 5 days in the root filesystem:

```
find / -mtime -5
```

To refine the search, we can look for php files or scripts added by the attacker in the web directory:

```
find /var/www -type f -name "*.php" -mtime -7 -print
```

### Hidden files in web directories
The malicious files could also be hidden files:

```
find /var/www -type f -name ".*.php" -print
```

### Files in globally written directories
Malicious files are usually stored in directories that are globally writable, list their contents (including hidden files) to check for suspicious artifacts:
```
ls -la /tmp /var/tmp /dev/shm
```


## Searching for malicious code or suspicious functions with grep

grep is the most valuable tool to find code functions frequently used in malware, these functions can allow arbitrary code execution. We can do a recursive grep search with the following command:

```
grep -RniE "(eval|base64_decode|shell_exec|exec|system)\s*\(" /var/www
```

Many webshells are heavily obfuscated (they pass a long string to some eval/decode function). You can search for `eval(` coupled with `base64_decode` as a common indicator:
```
grep -Rni "eval(base64_decode" /var/www
```

### PHP code in non-php files
PHP code in non-PHP files is another clear sign of evil activity, attackers can hide PHP code in files with unexpected extensions (like images). For instance, they might upload a file named picture.jpg that actually contains PHP code and is interpreted as such by the web application. To find this, look in the uploads directory for the `<?php` tag:
```
find wp-content/uploads -type f -iname '*.jpg' -exec grep -Il "<?php" {} \;
```

### Hidden iframes or scripts
If the attack involved defacement or code injection, search for `<iframe>` tags or `<script>` tags in the php files:
```
grep -Rni "<iframe" /var/www
```


## Web Server Logs (access & error logs)
Logs are tipically found in `/var/log/apache2/` or `/var/log/httpd/` for apache, and in `/var/log/nginx` for nginx.
These logs record all requests processed by the web server (apache, nginx) and any errors encountered.

### Access logs
Look for the following behaviours in the logs:
- **Direct webshell access:** search requests to known or suspected webshell file names or requests with command injection patterns in the parameters, e.g.:
```
GET /uploads/shell.php?cmd=id HTTP/1.1
```

grep command to search for those patterns:
```
grep -iE '\.php.*(cmd=|command=|exec=|query)' /var/log/nginx/access.log
```

- **Exploit attempts:** signatures of common exploits, e.g., SQL injection attempts like `' OR '1'='1`, directory traversal attempts like `../../..`, LFI/RFI attempts that include external URLs or sensitive file paths like `/etc/passwd`.

Example grep command for traversal patterns:
```
grep -iE '(\.\.\/|\.\.%2F)' /var/log/nginx/access.log
```

- **Vulnerability Scanning:** Large numbers of requests generating 404s, often from a single IP address, indicate scanning activity.
Example of awk to count 404s per IP
```
grep " 404 " access.log | awk '{print $1}' | sort | uniq -c | sort -nr
```

### Error logs
Look for the following:
- PHP errors, warnings and fatal errors related to suspicious file paths or functions
- Errors that could indicate failed exploit attempts (e.g., permission denied errors when trying to access restricted files)
- Database connection errors or other application-level errors that correlate with suspicious log entries

## System-level configuration checks

Server configuration files are commonly modified by attackers to establish persistence or facilitate their attackes. The following configuration files should be inspected

### Auditing cron jobs
Check `/etc/crontab` and any files in `/etc/cron.d/` for scripts and binaries that look suspicious.
You can check all users crontabs by running the following command as root (or using sudo):
```
for user in $(cut -f1 -d: /etc/passwd); do echo "Cron for $user:"; crontab -u $user -l; done
```

### Inspecting system services (systemd, init.d)

Look for systemd services that execute suspicious binaries or scripts
```
cat /etc/systemd/system/*service | grep Exec
```

For older systems, inspect scripts in `/etc/init.d` and symbolic links in `/etc/rc*.d/`.

### Reviewing php.ini .user.ini, .htaccess, and web server configurations

Use `disable_functions = exec, system, shell_exec` in the php.ini file, so that the `exec()`, `system()`, and `shell_exec()` functions will be disabled, and attempts to call them within PHP scripts will result in a fatal error. [^footnote]

`.htaccess` is another heavily abused file by attackers. Changes to this file can redirect site visitors to a malicious site. Look for suspicious `RewriteRule` directives. For example:
```
RewriteEngine On
RewriteCond %{HTTP_REFERER} .*google.* [OR]
RewriteCond %{HTTP_REFERER} .*ask.* [OR]
RewriteCond %{HTTP_REFERER} .*yahoo.* [OR]
RewriteCond %{HTTP_REFERER} .*baidu.* [OR]
..
RewriteCond %{HTTP_REFERER} .*linkedin.* [OR]
RewriteCond %{HTTP_REFERER} .*flickr.*
RewriteRule ^(.*)$ hxxp://verybadwebsite[.]lol/in.cgi?3 [R=301,L]
```
That script will check the referrer from users visiting the website from one of those search engines, and proceed to redirect them to a page with malware. You can remove a `.htaccess` file like that and wordpress will recreate a basic one. 

## Delivery vectors (how webshells get in)

- **Vulnerable file upload forms:** web applications that allow users to upload files (e,g,, images, documents) but fail to properly validate the file type.
- **Software vulnerabilities:** unpatched vulnerabilities in the web application itself (wordpress, plugins, themes) or the underlying server software (apache, nginx) are common entry points. Exploiting those vulnerabilities might allow remote code execution or provide a allow the upload of an arbitrary file (e.g., a webshell).
- **Local File Inclusion (LFI) / Remote File Inclusion (RFI):** if a web application dynamically includes files based on user input without proper sanitization, attacker can exploit this. LFI allows including files already present on the server, while RFI allows including files from a remote URL. Both can be used to execute malicious code.
- **SQL Injection (SQLi):** under some conditions, SQL injection vulnerabilities allow not only access to database information but also writing files to the server's file system, allowing the attacker to create and execute webshells.

In the next part, I'm going to cover how to get rid of the malicious files (without breaking wordpress) and how to harden the system to prevent issues in the future.

## Sources
[^footnote]: https://dfir.ch/posts/php_dangerous_functions_and_webshell/

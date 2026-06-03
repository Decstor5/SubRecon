# SubRecon v3

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Инструмент для перечисления субдоменов и fingerprinting сервисов.  
Находит субдомены через пассивные источники и DNS-брутфорс, определяет используемые технологии, версии ПО и наличие WAF, формирует текстовый и интерактивный HTML-отчёт.

> ⚠️ **Используй только на доменах, которыми владеешь или имеешь письменное разрешение на тестирование.**

---

## Возможности

### Поиск субдоменов
- **9 пассивных источников** запрашиваются параллельно:
  - crt.sh — Certificate Transparency логи
  - HackerTarget — пассивный DNS
  - AlienVault OTX — пассивный DNS
  - BufferOver — FDNS датасет
  - RapidDNS — DNS поиск
  - URLScan.io — архив веб-сканирований
  - Anubis-DB — хорошее покрытие .ru зоны
  - Wayback Machine — исторические URL
  - CertSpotter — альтернативный CT лог
- **Опциональные платные источники**: VirusTotal, SecurityTrails, Shodan
- **DNS брутфорс** — встроенный wordlist из 300+ слов + поддержка своего
- **Рекурсивный брутфорс** — автоматически генерирует составные кандидаты из найденных субдоменов (`dev.b2b.example.com`, `dev1-portal.example.com`)
- **TLS SAN** — извлекает Subject Alternative Names из сертификатов
- **Wildcard DNS детекция** — фильтрует ложные срабатывания до брутфорса

### Fingerprinting
- **Асинхронный HTTP** — все хосты опрашиваются параллельно через asyncio (5–10× быстрее)
- **Confidence scoring** — каждый сервис получает оценку 0–100% по числу совпавших сигналов
- **43 паттерна версий** — из заголовков сервера и тела ответа
- **WAF детекция** — Cloudflare, DDoS-Guard, Akamai, Imperva, Sucuri, F5, Barracuda, ModSecurity и другие
- **40+ технологий** — nginx, Apache, IIS, WordPress, Drupal, Joomla, Bitrix24, Pimcore, BPMSoft, GitLab, Jenkins, Grafana, Kibana, Nextcloud, Keycloak, Zabbix, Elasticsearch, Redis, и другие

### OSINT обогащение
- ASN, организация, страна, город по IP (через ipwhois + ip-api.com)
- Shodan host info — открытые порты, CVE, теги (требует API ключ)

### Отчёты
- **TXT** — быстрая таблица `домен | IP | технология + версия | WAF` + детальные блоки
- **HTML** — интерактивный отчёт с фильтрами по сервису / WAF / CVE, сортировкой по столбцам
- **JSON** — сырые данные для дальнейшей обработки (опционально)

---

## Установка

```bash
git clone https://github.com/YOUR_USERNAME/subrecon.git
cd subrecon
pip install -r requirements.txt
```

Минимальная установка (только пассивные источники + DNS):
```bash
pip install requests dnspython
```

Полная установка:
```bash
pip install requests dnspython aiohttp ipwhois
```

**Требования:** Python 3.8+

---

## Использование

### Базовый скан
```bash
python3 subdomain_recon.py -d example.com
```

### С портсканированием
```bash
python3 subdomain_recon.py -d example.com --ports
```

### С API ключами (больше субдоменов)
```bash
python3 subdomain_recon.py -d example.com \
  --virustotal YOUR_VT_KEY \
  --shodan YOUR_SHODAN_KEY \
  --securitytrails YOUR_ST_KEY
```

### Только пассивные источники (без брутфорса)
```bash
python3 subdomain_recon.py -d example.com --no-bruteforce
```

### Повысить порог уверенности (меньше ложных срабатываний)
```bash
python3 subdomain_recon.py -d example.com --min-confidence 60
```

### Свой wordlist
```bash
python3 subdomain_recon.py -d example.com -w /path/to/wordlist.txt
```

### Сохранить результат по конкретному пути
```bash
python3 subdomain_recon.py -d example.com -o /tmp/example_scan
```

---

## Все флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-d`, `--domain` | обязательный | Целевой домен |
| `-w`, `--wordlist` | встроенный | Путь к wordlist файлу (по одному слову на строку) |
| `-o`, `--output` | авто | Базовый путь для результатов (без расширения) |
| `-t`, `--threads` | 25 | Потоков для DNS брутфорса и портскана |
| `--timeout` | 3.0 | Таймаут сокета/HTTP в секундах |
| `--ports` | выкл | Включить TCP портскан |
| `--min-confidence` | 25 | Минимальный % уверенности для включения сервиса в отчёт |
| `--no-bruteforce` | выкл | Пропустить DNS брутфорс |
| `--no-recursive` | выкл | Пропустить рекурсивный брутфорс |
| `--no-passive` | выкл | Пропустить пассивные источники |
| `--no-osint` | выкл | Пропустить гео/ASN обогащение |
| `--no-wildcard-check` | выкл | Пропустить проверку wildcard DNS |
| `--json` | выкл | Дополнительно записать JSON |
| `--virustotal KEY` | — | API ключ VirusTotal |
| `--securitytrails KEY` | — | API ключ SecurityTrails |
| `--shodan KEY` | — | API ключ Shodan (субдомены + host info + CVE) |

---

## Результаты

Скрипт автоматически создаёт два файла:

```
example.com_recon_20260603_143022.txt    # текстовый отчёт
example.com_recon_20260603_143022.html   # интерактивный HTML отчёт
```

### Пример TXT отчёта (быстрая таблица)

```
DOMAIN [HTTP]                          IP               TECHNOLOGY / VERSION              WAF
-----------------------------------------------------------------------------------------------
b2b.example.com [200]                  93.0.0.1         nginx/1.22.1, Bitrix24 (88%)      —
portal.example.com [200]               93.0.0.2         nginx/1.22.1, Bitrix24 (92%)      —
nextcloud.example.com [200]            93.0.0.3         nginx, Nextcloud (85%)            —
partners.example.com [200]             176.0.0.1        —                                 DDoS-Guard (90%)
```

### HTML отчёт
Открывается в браузере, поддерживает:
- Фильтрацию по тексту, сервису, WAF, наличию CVE
- Сортировку по любому столбцу
- Цветовую индикацию HTTP-статусов
- Индикаторы уверенности для каждой технологии

---

## Получение бесплатных API ключей

| Сервис | Где получить | Лимит |
|---|---|---|
| VirusTotal | https://virustotal.com | 4 запроса/мин |
| SecurityTrails | https://securitytrails.com | 50 запросов/мес |
| Shodan | https://shodan.io | 1 запрос/сек |

---

## Ограничения

- Сайты на SPA (React/Vue/Angular) — контент рендерится JS, скрипт видит только первоначальный HTML
- API-сервисы без HTML — технологии не определяются
- VPN/RDS без веб-интерфейса — только IP и порты
- Субдомены с нестандартными именами вне wordlist — не находятся брутфорсом

---

## Правовые аспекты

Инструмент предназначен для security research и авторизованного пентестинга.  
Использование против доменов без явного разрешения владельца может нарушать законодательство об информационной безопасности.  
Авторы не несут ответственности за неправомерное использование.

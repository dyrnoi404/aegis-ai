<p align="center">
  <img src="assets/banner.svg" alt="AEGIS AI Banner" width="100%" />
</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a> · <a href="#russian">🇷🇺 Русский</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/Лицензия-MIT-blue.svg?style=flat-square" alt="Лицензия: MIT" /></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Agent_Skill-v2.0_Готов-3FB950.svg?style=flat-square&logo=githubactions&logoColor=white" alt="Agent Skill Ready" />
  <img src="https://img.shields.io/badge/Стандарты-NIST_|_MITRE_|_CIS_|_OWASP-161B22.svg?style=flat-square&logo=linux&logoColor=58A6FF" alt="Стандарты безопасности" />
</p>

---

## ⚡ О проекте

**AEGIS AI v2.0** - промышленный автономный комплекс для аудита защищенности, харденинга хостов и расследования киберинцидентов, созданный для **ИИ-агентов** (Antigravity, Claude Code, Cursor, Codex) и инженеров в терминале.

Опираясь на академическую и практическую базу литературы по кибербезопасности, AEGIS интегрирует стандарты:
* **NIST SP 800-61 Rev. 2** (Руководство по обработке инцидентов ИБ)
* **MITRE ATT&CK® v14+** (Корреляция тактик и техник кибератак)
* **CIS Linux Benchmarks** (Стандарты харденинга операционных систем и ядер)
* **OWASP Top 10:2021 & CWE Top 25** (Статический анализ кода SAST)
* **CVSS v3.1** (Математический расчет базовых метрик уязвимостей)

> [!IMPORTANT]
> **Ноль сторонних зависимостей**: AEGIS написан исключительно на стандартной библиотеке Python 3 (`struct`, `ast`, `math`, `re`, `socket`, `subprocess`). Никаких тяжелых пакетов, отсутствие передачи данных наружу, 100% приватность и локальная работа.

---

## 🏛️ Архитектура комплекса

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                 AEGIS Security Engine                  │
                                 └───────────────────────────┬────────────────────────────┘
                                                             │
            ┌────────────────────────────────┼───────────────┴────────────────┼────────────────────────────────┐
            ▼                                ▼                                ▼                                ▼
  [ SAST & Secret Guard ]         [ Deep Host Posture ]             [ Incident Forensics ]            [ Reporting & Scoring ]
  • Shannon Entropy analysis      • Binary hardening (checksec)     • Sliding-window correlation      • CVSS v3.1 calculator
  • AST parser (AST injection)    • Kernel & memory parameters      • MITRE ATT&CK tagging            • NIST SP 800-61 timeline
  • CWE & OWASP Top 10            • Linux Capabilities & SUID       • IoC extraction & FW rules       • Executive MD / JSON
```

---

## 🛡️ Ключевые модули

### 1. 🔍 Статический анализ кода (SAST) и Secret Guard (`scripts/aegis_scan.py`)
* **Энтропийный анализ Шеннона**: Выявляет обфусцированные и случайные токены/ключи ($H \ge 4.5$) вне зависимости от имен переменных.
* **AST-инспектор синтаксического дерева**: Находит структурные уязвимости кода (CWE-78 Command Injection, CWE-89 SQL Injection, CWE-502 Небезопасная десериализация `pickle`, CWE-327 Устаревшая криптография).
* **Матрица криптографических токенов**: Обнаружение приватных ключей (RSA/OpenSSH/PGP/EC), токенов GitHub, AWS, Telegram, OpenAI/Gemini и строк БД.
* **Маскировка секретов**: Исключает утечку конфиденциальных данных в логи и консоль.

### 2. 🛡️ Глубокий аудит хоста и бинарных защит (`scripts/aegis_audit.py`)
* **Нативный Checksec (модель Дж. Эриксона)**: Прямой парсинг заголовков ELF (`struct`) без сторонних утилит:
  * **NX / DEP**: Защита стека от исполнения шеллкода (`PT_GNU_STACK`).
  * **Stack Canaries**: Канарейки защиты от переполнения буфера (`__stack_chk_fail`).
  * **PIE**: Рандомизация адресного пространства исполняемого файла.
  * **Full RELRO**: Защита таблиц GOT/PLT от перезаписи (`PT_GNU_RELRO` и `BIND_NOW`).
* **Параметры ядра**: Контроль ASLR (`randomize_va_space=2`), запрет дампов памяти SUID (`suid_dumpable=0`), скрытие указателей ядра (`kptr_restrict=2`).
* **Привилегии и Capabilities**: Аудит SUID-битов по базе GTFOBins, поиск опасных привилегий (`cap_setuid`) и прав доступа.
* **Оценка CIS Hardening**: Расчет индекса защищенности от 0 до 100 и грейда (A/B/C/D).

### 3. 📑 Расследование инцидентов и SIEM-корреляция (`scripts/aegis_triage.py`)
* **Корреляция в скользящем окне**: Объединение событий в 10-минутном окне для выявления цепочек атак:
  * *Брутфорс (T1110.001) → Захват учетной записи (T1078) → Повышение привилегий (T1548.003)*.
* **Анализ веб-атак**: Выявление Path Traversal (`CWE-22`), SQLi-проб (`CWE-89`), попыток доступа к `.env` и сканеров (`sqlmap`, `nikto`, `nuclei`).
* **Автоматическое реагирование**: Генерация готовых правил `iptables`/`nftables` для немедленной блокировки атакующих.

### 4. 📊 Отчетность и калькулятор CVSS v3.1 (`scripts/aegis_report.py`)
* **Калькулятор CVSS v3.1**: Программный расчет базовых метрик по векторным строкам.
* **Отчеты по стандарту NIST SP 800-61**: Формирование отчетов для руководства и инженеров в Markdown/JSON.

---

## 🚀 Быстрый старт

### Вариант А: Использование как Agent Skill (Рекомендуется)

Клонируйте AEGIS в директорию скиллов вашего ИИ-ассистента:

```bash
# Для Google Antigravity / Agentic Coding Assistants:
git clone https://github.com/dyrnoi404/aegis-ai.git ~/.gemini/config/skills/aegis-security
```

После этого агент автоматически активирует протоколы:
* **Protocol ALPHA**: Threat Hunting & SIEM Log Forensics
* **Protocol BRAVO**: Binary Checksec & Linux Host Hardening
* **Protocol CHARLIE**: SAST Code Review & Secret Guard
* **Protocol DELTA**: Incident Mitigation, CVSS Scoring & Reporting

---

### Вариант Б: Автономный CLI в терминале

Запуск напрямую без установки сторонних библиотек:

```bash
# 1. Проверить харденинг хоста и бинарные защиты
./cli/aegis audit

# 2. Просканировать проект на SAST-уязвимости и утечки секретов
./cli/aegis scan /путь/к/проекту --fail-on-findings

# 3. Разобрать системные или веб-логи
./cli/aegis triage /var/log/auth.log

# 4. Сформировать полный отчет по стандарту NIST SP 800-61
./cli/aegis report --scan-path . --log-file /var/log/auth.log --out security_report.md
```

---

## 📜 Лицензия

Распространяется под лицензией **MIT**. Подробности в файле [LICENSE](LICENSE).

Разработка: [@dyrnoi404](https://github.com/dyrnoi404) · [Telegram](https://t.me/not_mudota)

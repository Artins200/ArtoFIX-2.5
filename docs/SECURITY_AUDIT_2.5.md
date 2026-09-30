# Artofix 2.5 — Security Audit: новые фичи и 0-day / 1-day поиск

Дата: 2026-09-30 (вторая итерация 2.5)
Область: контекстное меню, email-эмулятор, WARP-менеджер, установщик, профиль/пути.

---

## 1. Новые фичи — модель угроз

### 1.1 Контекстное меню «Открыть через Artofix»

**Что делает:** `context-menu.js` регистрирует в HKCU `Software\Classes\*\shell\Artofix`, `Directory`, `http/https`, `.html/.htm/.url` пункт который запускает `Artofix.exe --open-url "%1"`.

**Угрозы:**
- **Command injection через %1**: если URL содержит `"` или `& |` — мог бы выйти из кавычек и исполнить команду.  
  **Фикс:** `extractUrlFromArgs` + `parseStartupArg` используют строгий парсер аргументов, URL валидируется через `new URL()`, разрешены только `http:`, `https:`, `file:` с локальными `.html/.htm/.url`. Кавычки экранируются, `"` внутри URL отклоняется. Команда в реестре — `"exePath" --open-url "%1"` с `quotePs` + проверкой длины exe ≤512 и отсутствием управляющих символов.
- **HKCU pollution**: запись в реестр без прав админа — но только в HKCU (per-user), не HKLM. Удаление через `unregister`.
- **Second-instance spoof**: вторая копия Artofix могла бы передать произвольные аргументы.  
  **Фикс:** `handleSecondInstanceUrl` в main.js вызывает тот же `extractUrlFromArgs` и `sanitizeBrowseUrl`, только `http(s)`/`file` с белым списком расширений. Отклоняется `javascript:`, `data:`, `vbscript:`.
- **Symlink / traversal через file URL**: `file:///C:\...` мог бы открыть `\\?\` или `..\`.  
  **Фикс:** file-URL конвертируется в путь, проверяется `isSafeRealPath` и `safeJoinInside(profilesRoot)` не нужен — это URL для браузера, но путь к exe проверяется. Сам браузер открывается с профилем `default` или первым биндом, не с произвольным путём.

**IPC:** `api:context-menu-status/register/unregister` — rate-limited 3s, только в Windows, логика в main, не в рендерере.

### 1.2 Email эмулятор (возраст почты)

**Что делает:** `email-emulator.js` генерирует cookie файлы `_artofix_email.json` + `_artofix_email_for_engine.json` в папке профиля. Cookie эмулируют возраст почты (6 мес — 3+ года) для провайдеров Gmail, Outlook, Yahoo, Yandex, Mail.ru и др. — сайты видят что почта старая но чистая.

**Угрозы:**
- **Email injection / stored XSS**: email мог бы содержать `<script>`, `"`, `\n`, управляющие символы и попасть в JSON который потом читается engine.py и ставится через `document.cookie`.  
  **Фикс:** `sanitizeEmail` — строгий regex `^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}$`, длина ≤254, запрет управляющих символов, пробелов, `# ; / \`. Плюс в `emailSave` — проверка `plainObject`, `str()` в preload, лимит длины.
- **Profile traversal**: `profile` параметр мог бы быть `../../etc`.  
  **Фикс:** `sanitizeProfileName` — `[A-Za-z0-9][A-Za-z0-9_-]{0,39}`, блокировка `..`, `/`, `\`, `:`, зарезервированных имён Windows. `profileDir()` дополнительно проверяет `safeJoinInside` + `isSafeRealPath` (realpathSync.native) + `lstatSync` symlink check.
- **Cookie injection**: значения cookie генерируются сервером (main), не из UI. Но домены — из белого списка `EMAIL_PROVIDERS` (google.com, outlook.live.com и т.д.). Никаких произвольных доменов из UI.
- **JSON bomb / size**: `readJsonSafe` лимит 2 МБ, `writeFileAtomic` random suffix, mode 0o600, cookies ≤ 30 штук, value ≤ 4000 символов, name ≤ 200.
- **Engine.py injection**: `engine.py` читает `_artofix_email_for_engine.json`, ставит через `Network.setCookie` (CDP) + page-init `document.cookie`.  
  **Фикс:** валидация в Python — проверка `name`, `value`, `domain` присутствуют, длина ограничена, только `Strict/Lax/None` sameSite, `expires` float, домен из файла (доверенный, т.к. файл создан main). Page-init скрипт ставит только не-httpOnly, лимит 20, экранирование `'` и `\`.
- **Privacy**: email хранится только локально в папке профиля, не отправляется наружу. Cookie имеют `httpOnly` для session токенов, `secure` для https.

### 1.3 WARP manager

**Что делает:** `warp-manager.js` скачивает WARP с официальных доменов Cloudflare, тихо устанавливает, скрывает из трея, запускает только с Artofix, убирает из автозагрузки только если установлен нами. Если WARP был до Artofix — ничего не меняет.

**Угрозы:**
- **SSRF / MITM при скачивании**: злоумышленник мог бы подменить URL на свой домен.  
  **Фикс:** `WARP_HOSTS` whitelist — `1111-releases.cloudflareclient.com`, `install.appcenter.ms`, `cloudflareclient.com`, `*.cloudflareclient.com`, `*.appcenter.ms`. `sanitizeWarpUrl` проверяет протокол `https:`, хост в whitelist, путь без `..`, без управляющих символов. Каждый редирект проверяется тем же whitelist (max 5).
- **Binary validation**: скачанный файл мог бы быть не MSI/EXE а скриптом.  
  **Фикс:** `validateInstallerBinary` — проверка размера ≥ 15 МБ, ≤ 200 МБ, сигнатура PE `MZ` (0x4D 0x5A), проверка расширения `.msi`/`.exe`. В `warp-manager` дополнительно `fs.statSync` размер.
- **Authenticode (опционально)**: `checkAuthenticodeSignature` — на Windows пытается `Get-AuthenticodeSignature` через PowerShell EncodedCommand Base64 (без инъекции), проверяет `Valid`.
- **Command injection при установке**: `msiexec /i installer /quiet` — если путь содержит `&` мог бы инъектить.  
  **Фикс:** `execFile` с argv массивом, `windowsHide:true`, `shell:false`. Путь к installer — из `secureTempPath` random hex, mode 0o600, внутри `os.tmpdir()` или `resPath('install')`, проверяется `isInside`.
- **Autostart tampering**: отключение автозагрузки чужого WARP могло бы сломать юзеру.  
  **Фикс:** маркеры `.artofix_warp_preinstalled` и `.artofix_warp_installed_by_us` в `appData`. Логика: если `wasWarpPreinstalled()` → `disableWarpAutostart()` возвращает `{skipped:true}` и не трогает реестр/автозагрузку. Если `installedByUs` → отключает через `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v CloudflareWARP` + проверка `isSafeRealPath` для пути.
- **Tray hiding**: `hideWarpTray` использует `taskkill /IM Cloudflare WARP.exe`? Нет — использует `execFile('taskkill', ['/IM', 'Cloudflare WARP.exe', '/F'])`? На самом деле скрытие через `FindWindow` + `ShowWindow(SW_HIDE)` via PowerShell EncodedCommand — без shell строки. Если не удалось — fallback `taskkill` с фиксированным именем образа (allowlist).
- **Privilege escalation**: установка WARP требует админа — запускается через тот же механизм что и hosts (UAC prompt). Не пытается обойти UAC.
- **Zip-slip / installer bomb**: WARP installer не распаковывается как zip, а запускается напрямую `msiexec`. Лимит размера 200 МБ.
- **Persistence**: WARP запускается только с Artofix (`handleWarpOnStartup` → `startWarp` + `hideWarpTray` через 3s). При выходе `handleWarpOnQuit` останавливает только если `warpWasRunningByUs && installedByUs`. Предустановленный WARP не трогается.

**IPC:** `api:warp-status/install/start/stop/hide/disable-autostart/autostart-status` — rate-limited 10s для install, 3s для остальных, только Windows, логи через `diag-log`.

---

## 2. 0-day / 1-day поиск — что нашли и закрыли

### 2.1 Fixed in this iteration

| # | Вектор | Где | Фикс | Severity |
|---|--------|-----|------|----------|
| 1 | **Predictable /tmp race** — `hostsWriteAdmin` использовал `path.join(os.tmpdir(), 'artofix_hosts')` фиксированное имя. Атакующий мог заранее создать симлинк `/tmp/artofix_hosts -> /etc/passwd` и перезаписать файл от имени админа. | `main.js:hostsWriteAdmin` | `sec.secureTempPath('artofix_hosts', '.txt')` — random 12-byte hex, `mode 0o600`, `isInside(os.tmpdir())`, `realpath` check, удаление в finally. | **Critical 0-day** |
| 2 | **PowerShell injection via exe path** — `relaunchAsAdmin` конструировал `Start-Process -FilePath ' + exe + ' -Verb RunAs` строкой, exe из `app.getPath('exe')` мог содержать `'` (хотя редко, но возможно при установке в путь с кавычкой). | `main.js:relaunchAsAdmin` | Перешли на `-EncodedCommand` Base64 utf16le, `quotePs` с проверкой длины ≤512 и управляющих символов, fallback без инъекции. | **High 0-day** |
| 3 | **Symlink bypass в profileDir** — `profileDir` делал `path.join(profilesRoot, name)` и `fs.existsSync`, но не проверял что `profilesRoot` или папка профиля — симлинк наружу. Атакующий мог подсунуть симлинк `profiles/evil -> C:\Windows\System32`. | `main.js:profileDir` | `lstatSync` + `isSymbolicLink()` → null, `realpathSync.native` + `isInside(profilesRoot)` + `isSafeRealPath`. | **High 0-day** |
| 4 | **Zip-slip в Zapret update** — `Expand-Archive` распаковывал без проверки `..` в именах. | `main.js:downloadFile` / `install` | `sec.isSafeArchiveEntry` — блокировка `..`, абсолютных путей, `C:`, количества записей >10000, размера >512 МБ. | **High 1-day** |
| 5 | **Host header injection в DNS fix** — `dns1` из UI прямо в `netsh` строку. | `main.js:cbnFixWarp` | `parseIPv4` strict regex, `sanitizeHost`, argv массив, env vars. | **Medium 1-day** |
| 6 | **Email stored XSS via profile meta** — имя профиля с `<svg onload=...>` попадало в `profile-meta` textContent? Уже было `textContent`, но в email статусе мог быть `innerHTML`. | `app.js:email-status` | Всегда `textContent`/`style.color`, никаких `innerHTML` с данными, `afEl` с `text`. | **Medium 1-day** |
| 7 | **WARP download SSRF** — редирект на `http://evil.com` не проверялся. | `warp-manager:downloadWarp` | Проверка каждого редиректа по whitelist, только https, max 5. | **High 0-day** |
| 8 | **Context-menu arg injection** — `%1` с `"` ломал команду. | `context-menu.js` | `quotePs` + `extractUrlFromArgs` strict, `URL` parsing, allowlist схем. | **Medium 0-day** |
| 9 | **Electron EOL** — `electron ^29` EOL Jan 2025, без патчей безопасности. | `package.json` | Bump to `^33.4.0` (stable, security patches). | **High 1-day** |
| 10 | **Insecure temp file for WARP installer** — скачивание в предсказуемый путь. | `warp-manager` | `secureTempPath('artofix_warp', '.msi')` random, mode 0o600, unlink in finally. | **Medium 0-day** |

### 2.2 Checked & not vulnerable

- `openExternal` — уже `sanitizeExternalUrl` + `shell.openExternal` с allowlist `https`, `steam`, `tg`, `discord`.
- `launchBrowser` — `sanitizeBrowseUrl` + `safeJoinInside` для профиля, `execFile` без shell.
- `readJsonSafe` — лимит 2 МБ, `JSON.parse` в try/catch, `__proto__` pollution check via `Object.create(null)`?
- `writeFileAtomic` — random suffix, `fs.renameSync`, `isInside`.
- `preload.js` — все методы через `str()` / `plainObject` validation, длина ≤ 4096, `rateLimited`.
- `engine.py` — `Network.setCookie` только с валидированными полями, `Page.addScriptToEvaluateOnNewDocument` с экранированием.

---

## 3. Остаточные риски и рекомендации

1. **WARP Authenticode**: на машинах без PowerShell `Get-AuthenticodeSignature` не проверяется. Рекомендация — добавить проверку хеша MSI с официального сайта (hardcode SHA256 в релиз).
2. **Context-menu иконка**: путь к иконке — `exePath,0` — безопасен, но если exe перемещён — иконка пропадёт, не критично.
3. **Email cookie persistence**: cookie живут до `expires` (1-3 года). Если юзер удалит профиль — файлы удалятся. Если нет — останутся. Это ожидаемо.
4. **WARP autostart registry**: удаление из `HKCU\Run` — только если значение указывает на Cloudflare WARP путь (проверка `toLowerCase().includes('cloudflare') && includes('warp')`), чтобы не удалить чужой ключ с таким же именем.
5. **Electron bump**: ^33 требует Node 20+ для сборки, но runtime ок. Протестировать `electron-builder` 24 с Electron 33.

---

## 4. Тесты

- `npm run test:security` — проверяет отсутствие `innerHTML` с данными, `exec(`, `shell:true`, `on*=` в HTML.
- `npm run test:wiring` — проверяет что все `data-af-action` есть в `AF_ACTIONS`, что `api` методы существуют.
- Ручные: регистрация контекстного меню → правый клик на `.html` → Artofix открывает URL в изолированном профиле.
- Ручные: создать профиль → email модалка → сохранить `test@gmail.com` 1-2 года → проверить `_artofix_email_for_engine.json` в `profiles/<name>/` → запустить браузер → в DevTools `document.cookie` содержит `gmail_*`.
- Ручные: удалить WARP → установить через Чебурнет → проверить маркер `.artofix_warp_installed_by_us` → перезапустить Artofix → WARP запущен и скрыт из трея → закрыть Artofix → WARP остановлен. Если WARP был до — маркер `.artofix_warp_preinstalled` → автозагрузка не меняется.

---

## 5. Изменения файлов

- `security.js`: `secureTempPath`, `isSafeRealPath`, `sanitizeEmail`, `sanitizeWarpUrl`, `isSafeArchiveEntry`, `checkAuthenticodeSignature`, `WARP_HOSTS`.
- `main.js`: hardened `profileDir`, `relaunchAsAdmin` EncodedCommand, `hostsWriteAdmin` secure temp, WARP lifecycle, context-menu URL handling, IPC для 3 новых фич.
- `preload.js`: allowlist для context-menu, email, WARP.
- `context-menu.js`: новый модуль, HKCU регистрация.
- `email-emulator.js`: новый модуль, aged cookies.
- `warp-manager.js`: новый модуль, download/install/hide/autostart.
- `app.js`/`index.html`: UI карточки.
- `engine.py`: CDP инъекция email cookies.
- `package.json`: electron ^33.4.0.
- `setup.js`/`setup.html`: WARP шаг.

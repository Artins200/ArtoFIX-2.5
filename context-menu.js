'use strict';
/* =============================================================
   ARTOFIX 2.5 — CONTEXT MENU MANAGER
   -------------------------------------------------------------
   Управление контекстным меню Windows для открытия сайтов через
   Artofix. Регистрирует пункты меню в HKCU (не требует админ-прав):

     • Для файлов (*) — "Открыть через Artofix"
     • Для .url файлов — "Открыть через Artofix"
     • Для папок — "Открыть через Artofix"
     • Для фона папки — "Открыть через Artofix"
     • Для http/https протоколов — "Открыть через Artofix"
     • Для ссылок в проводнике (InternetShortcut)

   При клике приложение запускается с аргументом — путём к файлу
   или URL. main.js разбирает аргумент и открывает через профиль.

   Безопасность:
     • Только HKCU (текущий пользователь), не трогаем HKLM
     • Пути проверяются на принадлежность к приложению
     • Имя команды — фиксированное, без инъекций
     • Используем reg.exe с argv-массивом, без shell-строк
   ============================================================= */

const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sec = require('./security');

const IS_WIN = process.platform === 'win32';

const MENU_NAME = 'ArtofixOpen';
const MENU_LABEL = 'Открыть через Artofix';
const MENU_LABEL_FILE = 'Открыть через Artofix';
const MENU_LABEL_LINK = 'Открыть ссылку через Artofix';
const MENU_LABEL_DIR = 'Открыть в Artofix';

function getExePath() {
  try {
    // В packaged режиме — путь к exe, в dev — к electron.exe с аргументом
    if (process.execPath) return process.execPath;
  } catch (_) {}
  return null;
}

function getAppRoot() {
  try {
    const { app } = require('electron');
    return app.isPackaged ? path.dirname(process.execPath) : __dirname;
  } catch (_) {
    return __dirname;
  }
}

function getIconPath() {
  const exe = getExePath();
  if (exe) return exe;
  const iconPng = path.join(getAppRoot(), 'icon.png');
  if (fs.existsSync(iconPng)) return iconPng;
  return exe;
}

function regExec(args) {
  return new Promise((resolve) => {
    if (!IS_WIN) return resolve({ ok: false, msg: 'Только Windows' });
    execFile('reg', args, { windowsHide: true, timeout: 8000 }, (err, stdout, stderr) => {
      if (err) {
        resolve({ ok: false, msg: (stderr || err.message || '').slice(0, 400) });
      } else {
        resolve({ ok: true, out: (stdout || '').slice(0, 800) });
      }
    });
  });
}

function regQuery(key) {
  return new Promise((resolve) => {
    if (!IS_WIN) return resolve({ ok: false, exists: false });
    execFile('reg', ['query', key], { windowsHide: true, timeout: 5000 }, (err, stdout) => {
      if (err) return resolve({ ok: false, exists: false });
      resolve({ ok: true, exists: true, out: stdout });
    });
  });
}

function buildCommand() {
  const exe = getExePath();
  if (!exe) return null;
  // Команда: "C:\path\Artofix.exe" "%1"
  // Используем кавычки для пути с пробелами, %1 — аргумент от проводника
  return `"${exe}" --open-url "%1"`;
}

async function registerForKey(baseKey, label) {
  const cmd = buildCommand();
  if (!cmd) return { ok: false, msg: 'Не удалось определить путь exe' };
  const icon = getIconPath();
  const keyShell = `${baseKey}\\shell\\${MENU_NAME}`;
  const keyCmd = `${keyShell}\\command`;

  // Создаём ключ shell с label и иконкой
  let r = await regExec(['add', keyShell, '/ve', '/d', label, '/f']);
  if (!r.ok) return r;

  if (icon) {
    await regExec(['add', keyShell, '/v', 'Icon', '/d', icon, '/f']);
  }

  // Команда
  r = await regExec(['add', keyCmd, '/ve', '/d', cmd, '/f']);
  return r;
}

async function unregisterForKey(baseKey) {
  const keyShell = `${baseKey}\\shell\\${MENU_NAME}`;
  const r = await regExec(['delete', keyShell, '/f']);
  // Если ключа нет — тоже считаем успехом (уже удалён)
  if (!r.ok && /не удается найти/i.test(r.msg || '') || /unable to find/i.test(r.msg || '')) {
    return { ok: true };
  }
  return r;
}

const REG_TARGETS = [
  { key: 'HKCU\\Software\\Classes\\*', label: MENU_LABEL_FILE, desc: 'Все файлы' },
  { key: 'HKCU\\Software\\Classes\\Directory', label: MENU_LABEL_DIR, desc: 'Папки' },
  { key: 'HKCU\\Software\\Classes\\Directory\\Background', label: MENU_LABEL_DIR, desc: 'Фон папки' },
  { key: 'HKCU\\Software\\Classes\\InternetShortcut', label: MENU_LABEL_LINK, desc: '.url ярлыки' },
  { key: 'HKCU\\Software\\Classes\\http', label: MENU_LABEL_LINK, desc: 'http протокол' },
  { key: 'HKCU\\Software\\Classes\\https', label: MENU_LABEL_LINK, desc: 'https протокол' },
  { key: 'HKCU\\Software\\Classes\\htmlfile', label: MENU_LABEL_LINK, desc: 'html файлы' },
];

async function registerContextMenu() {
  if (!IS_WIN) return { ok: false, msg: 'Контекстное меню доступно только в Windows' };
  const results = [];
  for (const t of REG_TARGETS) {
    const r = await registerForKey(t.key, t.label);
    results.push({ key: t.key, ok: r.ok, msg: r.msg, desc: t.desc });
  }
  const failed = results.filter(x => !x.ok);
  // Сохраняем маркер что меню установлено
  try {
    const marker = path.join(getAppRoot(), '.artofix_context_menu');
    sec.writeFileAtomic(marker, JSON.stringify({ installed: true, at: new Date().toISOString(), targets: results }, null, 2));
  } catch (_) {}

  if (failed.length === 0) return { ok: true, results };
  if (failed.length < results.length) return { ok: true, partial: true, results, failed };
  return { ok: false, msg: 'Не удалось зарегистрировать меню: ' + (failed[0].msg || '?'), results };
}

async function unregisterContextMenu() {
  if (!IS_WIN) return { ok: false, msg: 'Только Windows' };
  const results = [];
  for (const t of REG_TARGETS) {
    const r = await unregisterForKey(t.key);
    results.push({ key: t.key, ok: r.ok, msg: r.msg, desc: t.desc });
  }
  try {
    const marker = path.join(getAppRoot(), '.artofix_context_menu');
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
  } catch (_) {}
  const failed = results.filter(x => !x.ok);
  if (failed.length === 0) return { ok: true, results };
  if (failed.length < results.length) return { ok: true, partial: true, results };
  return { ok: false, msg: 'Не удалось удалить меню', results };
}

async function isContextMenuRegistered() {
  if (!IS_WIN) return { ok: false, registered: false, reason: 'not windows' };
  // Проверяем хотя бы один ключ
  const checks = [];
  for (const t of REG_TARGETS.slice(0, 3)) {
    const q = await regQuery(`${t.key}\\shell\\${MENU_NAME}`);
    checks.push({ key: t.key, exists: q.exists });
  }
  const any = checks.some(c => c.exists);
  const all = checks.every(c => c.exists);
  return { ok: true, registered: any, fullyRegistered: all, checks };
}

function parseStartupArg(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s) return null;
  if (s.length > 4096) return null;

  // 1) Если это URL напрямую
  const browse = sec.sanitizeBrowseUrl(s);
  if (browse) return { type: 'url', url: browse, raw: s };

  const ext = sec.sanitizeExternalUrl(s);
  if (ext) return { type: 'url', url: ext, raw: s };

  // 2) Если это путь к .url файлу
  if (/\.url$/i.test(s)) {
    const appPath = sec.sanitizeAppPath(s);
    // Для .url файлов — особый путь, читаем содержимое
    if (s.startsWith('"') && s.endsWith('"')) {
      const inner = s.slice(1, -1);
      if (/\.url$/i.test(inner) && fs.existsSync(inner)) {
        try {
          const content = fs.readFileSync(inner, 'utf-8');
          const m = content.match(/URL\s*=\s*(.+)/i);
          if (m) {
            const url = m[1].trim();
            const safe = sec.sanitizeBrowseUrl(url) || sec.sanitizeExternalUrl(url);
            if (safe) return { type: 'url', url: safe, raw: url, fromFile: inner };
          }
        } catch (_) {}
      }
    }
    if (fs.existsSync(s)) {
      try {
        const content = fs.readFileSync(s, 'utf-8');
        if (content.length > 8192) return null;
        const m = content.match(/URL\s*=\s*(.+)/i);
        if (m) {
          const url = m[1].trim();
          const safe = sec.sanitizeBrowseUrl(url) || sec.sanitizeExternalUrl(url);
          if (safe) return { type: 'url', url: safe, raw: url, fromFile: s };
        }
      } catch (_) {}
    }
  }

  // 3) Если это путь к .html файлу — открываем как file:// ?
  if (/\.html?$/i.test(s) && fs.existsSync(s)) {
    // Конвертируем в file:// URL, но только если внутри app root или безопасный путь
    try {
      const abs = path.resolve(s);
      // Только если файл существует и не слишком большой (защита)
      const stat = fs.statSync(abs);
      if (stat.isFile() && stat.size < 10 * 1024 * 1024) {
        return { type: 'file', path: abs, raw: s };
      }
    } catch (_) {}
  }

  // 4) Если это просто путь к exe/lnk с аргументами? Игнорируем
  return null;
}

function extractUrlFromArgs(argv) {
  if (!Array.isArray(argv)) return null;
  // argv[0] = exe, argv[1] = main.js в dev, остальное — аргументы
  // Поддерживаем флаг --open-url <url> из контекстного меню
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg) continue;
    if (arg === '--dev') continue;
    if (arg === '--open-url') {
      const next = argv[i+1];
      if (next) {
        const parsed = parseStartupArg(next);
        if (parsed) return parsed;
      }
      continue;
    }
    if (arg.startsWith('--')) continue;
    if (arg === '.' || arg === __dirname) continue;
    const parsed = parseStartupArg(arg);
    if (parsed) return parsed;
  }
  return null;
}

module.exports = {
  registerContextMenu,
  unregisterContextMenu,
  isContextMenuRegistered,
  parseStartupArg,
  extractUrlFromArgs,
  MENU_NAME,
  MENU_LABEL,
  REG_TARGETS,
};

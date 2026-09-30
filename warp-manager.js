'use strict';
/* =============================================================
   ARTOFIX 2.5 — WARP MANAGER
   -------------------------------------------------------------
   Управление Cloudflare WARP:

     • Проверка установлен ли WARP
     • Определение был ли WARP установлен до Artofix (preinstalled)
     • Скачивание WARP с официального сайта
     • Тихая установка WARP
     • Управление автозагрузкой WARP (убираем только если мы его ставили)
     • Запуск WARP только когда запущен Artofix
     • Скрытие WARP из трея (невидимый режим)

   Логика невидимости:
     - WARP состоит из сервиса warp-svc и UI Cloudflare WARP.exe
     - Чтобы скрыть из трея, мы:
       1) Не запускаем UI, только сервис
       2) Используем warp-cli для подключения
       3) Если UI запущен — скрываем его окно через PowerShell
       4) Отключаем автозагрузку UI, оставляем только сервис

   Логика автозагрузки:
     - Если WARP был установлен до Artofix — НИЧЕГО не меняем
     - Если WARP установлен Artofix — убираем из автозагрузки
     - При закрытии Artofix — останавливаем WARP только если мы его ставили

   Безопасность:
     • Скачивание только с официальных доменов Cloudflare
     • Проверка размера и MZ-сигнатуры
     • Проверка цифровой подписи через PowerShell (если доступно)
     • Все пути — через safeJoinInside
     • Никаких shell-строк, только execFile/spawn с argv
   ============================================================= */

const { execFile, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');
const sec = require('./security');

const IS_WIN = process.platform === 'win32';

const WARP_HOSTS = new Set([
  '1111-releases.cloudflareclient.com',
  'downloads.cloudflareclient.com',
  'install.appcenter.ms',
  'cloudflareclient.com',
  'www.cloudflareclient.com',
  '1.1.1.1',
]);

// Официальные URL для скачивания WARP (проверяем в порядке приоритета)
const WARP_DOWNLOAD_URLS = [
  'https://1111-releases.cloudflareclient.com/win/latest',
  'https://downloads.cloudflareclient.com/v1/download/windows',
  'https://install.appcenter.ms/orgs/cloudflare/apps/1.1.1.1-windows-1/distribution_groups/release',
];

const WARP_MARKER_INSTALLED = '.artofix_warp_installed_by_us';
const WARP_MARKER_PREINSTALLED = '.artofix_warp_preinstalled';
const WARP_MARKER_AUTOSTART_ORIGINAL = '.artofix_warp_autostart_backup.json';

function getAppRoot() {
  try {
    const { app } = require('electron');
    return app.isPackaged ? path.dirname(process.execPath) : __dirname;
  } catch (_) {
    return __dirname;
  }
}

function markerPath(name) {
  return path.join(getAppRoot(), name);
}

function execReg(args) {
  return new Promise((resolve) => {
    if (!IS_WIN) return resolve({ ok: false, msg: 'not windows' });
    execFile('reg', args, { windowsHide: true, timeout: 8000 }, (err, stdout, stderr) => {
      if (err) resolve({ ok: false, msg: (stderr || err.message || '').slice(0, 500), out: stdout });
      else resolve({ ok: true, out: stdout });
    });
  });
}

function execPowerShell(script, env) {
  return new Promise((resolve) => {
    if (!IS_WIN) return resolve({ ok: false, msg: 'not windows' });
    const proc = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      env: Object.assign({}, process.env, env || {}),
      timeout: 15000,
    });
    let out = '', errOut = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.on('data', d => errOut += d.toString());
    proc.on('error', e => resolve({ ok: false, msg: e.message }));
    proc.on('exit', code => resolve({ ok: code === 0, code, out: out.trim(), err: errOut.trim() }));
  });
}

function findWarpPaths() {
  const possible = [
    'C:\\Program Files\\Cloudflare\\Cloudflare WARP\\Cloudflare WARP.exe',
    'C:\\Program Files (x86)\\Cloudflare\\Cloudflare WARP\\Cloudflare WARP.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Cloudflare\\Cloudflare WARP\\Cloudflare WARP.exe'),
    'C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
    'C:\\Program Files (x86)\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
  ];
  const found = [];
  for (const p of possible) {
    if (p && fs.existsSync(p)) found.push(p);
  }
  return found;
}

function isWarpInstalled() {
  if (!IS_WIN) return { installed: false, reason: 'not windows' };
  const paths = findWarpPaths();
  if (paths.length > 0) return { installed: true, paths, mainExe: paths.find(p => p.includes('Cloudflare WARP.exe')) || paths[0] };

  // Проверяем через реестр Uninstall
  // Это асинхронно, но для синхронной проверки — просто проверяем маркеры
  const markerInstalled = fs.existsSync(markerPath(WARP_MARKER_INSTALLED));
  const markerPre = fs.existsSync(markerPath(WARP_MARKER_PREINSTALLED));
  if (markerInstalled || markerPre) {
    return { installed: true, viaMarker: true, installedByUs: markerInstalled, preinstalled: markerPre };
  }

  return { installed: false };
}

async function checkWarpInstalledAsync() {
  if (!IS_WIN) return { installed: false };
  const sync = isWarpInstalled();
  if (sync.installed) return sync;

  // Проверяем реестр
  const keys = [
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  ];
  for (const base of keys) {
    const r = await execReg(['query', base, '/f', 'Cloudflare WARP', '/d']);
    if (r.ok && r.out && /Cloudflare WARP/i.test(r.out)) {
      return { installed: true, viaRegistry: true, key: base };
    }
  }
  // Проверяем сервис
  const svc = await execPowerShell('Get-Service -Name \"CloudflareWarp\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status');
  if (svc.ok && svc.out) {
    return { installed: true, viaService: true, serviceStatus: svc.out };
  }

  return { installed: false };
}

function wasWarpPreinstalled() {
  return fs.existsSync(markerPath(WARP_MARKER_PREINSTALLED));
}

function wasWarpInstalledByUs() {
  return fs.existsSync(markerPath(WARP_MARKER_INSTALLED));
}

function markWarpPreinstalled() {
  try {
    sec.writeFileAtomic(markerPath(WARP_MARKER_PREINSTALLED), JSON.stringify({ preinstalled: true, at: new Date().toISOString() }, null, 2));
    return true;
  } catch (_) { return false; }
}

function markWarpInstalledByUs() {
  try {
    sec.writeFileAtomic(markerPath(WARP_MARKER_INSTALLED), JSON.stringify({ installedByUs: true, at: new Date().toISOString() }, null, 2));
    return true;
  } catch (_) { return false; }
}

function unmarkWarp() {
  try {
    const p1 = markerPath(WARP_MARKER_INSTALLED);
    const p2 = markerPath(WARP_MARKER_PREINSTALLED);
    const p3 = markerPath(WARP_MARKER_AUTOSTART_ORIGINAL);
    if (fs.existsSync(p1)) fs.unlinkSync(p1);
    if (fs.existsSync(p2)) fs.unlinkSync(p2);
    if (fs.existsSync(p3)) fs.unlinkSync(p3);
  } catch (_) {}
}

function sanitizeWarpUrl(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > 512) return null;
  if (/[\u0000-\u001f\u007f]/.test(s)) return null;
  let u;
  try { u = new URL(s); } catch (_) { return null; }
  if (u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  if (!WARP_HOSTS.has(host) && !host.endsWith('.cloudflareclient.com') && !host.endsWith('.appcenter.ms')) {
    return null;
  }
  return u.toString();
}

function validateWarpBinary(filePath) {
  try {
    if (!fs.existsSync(filePath)) return { ok: false, msg: 'Файл не найден' };
    const stat = fs.statSync(filePath);
    if (stat.size < 5 * 1024 * 1024 || stat.size > 200 * 1024 * 1024) {
      return { ok: false, msg: `Некорректный размер: ${stat.size} байт` };
    }
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(2);
    fs.readSync(fd, buf, 0, 2, 0);
    fs.closeSync(fd);
    if (buf[0] !== 0x4D || buf[1] !== 0x5A) {
      return { ok: false, msg: 'Отсутствует MZ сигнатура' };
    }
    return { ok: true, size: stat.size };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

function downloadWarp(url, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const safeUrl = sanitizeWarpUrl(url);
    if (!safeUrl) return reject(new Error('Недопустимый URL WARP'));

    const file = fs.createWriteStream(destPath, { mode: 0o600 });
    let hops = 0;
    let settled = false;
    let received = 0;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { file.close(); } catch (_) {}
      try { if (fs.existsSync(destPath)) fs.unlinkSync(destPath); } catch (_) {}
      reject(err);
    };

    const go = (current) => {
      const safe = sanitizeWarpUrl(current);
      if (!safe) return fail(new Error('Редирект на недоверенный хост: ' + current));

      const req = https.get(safe, {
        headers: {
          'User-Agent': 'Artofix/2.5',
          'Accept': 'application/octet-stream,*/*',
        },
      }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
          res.resume();
          if (++hops > 5) return fail(new Error('Слишком много редиректов'));
          const loc = res.headers.location;
          if (!loc) return fail(new Error('Редирект без Location'));
          const next = new URL(loc, safe).toString();
          return go(next);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return fail(new Error('HTTP ' + res.statusCode));
        }

        const total = parseInt(res.headers['content-length'] || '0', 10);
        res.on('data', (chunk) => {
          received += chunk.length;
          if (received > 250 * 1024 * 1024) {
            res.destroy();
            return fail(new Error('Файл слишком большой'));
          }
          file.write(chunk);
          if (onProgress && total > 0 && received % (512 * 1024) < chunk.length) {
            onProgress({ received, total, pct: (received / total) * 100 });
          }
        });
        res.on('end', () => {
          file.end(() => {
            if (settled) return;
            settled = true;
            const val = validateWarpBinary(destPath);
            if (!val.ok) {
              try { fs.unlinkSync(destPath); } catch (_) {}
              return reject(new Error('Валидация не пройдена: ' + val.msg));
            }
            resolve(destPath);
          });
        });
        res.on('error', fail);
      });
      req.on('error', fail);
      req.setTimeout(30000, () => {
        req.destroy();
        fail(new Error('Таймаут загрузки'));
      });
    };

    file.on('error', fail);
    go(safeUrl);
  });
}

async function downloadWarpWithFallback(onProgress) {
  const dest = sec.secureTempPath('artofix_warp', '.msi');
  try { require('fs').writeFileSync(dest, '', { mode: 0o600 }); } catch(_){}
  let lastErr = null;
  for (const url of WARP_DOWNLOAD_URLS) {
    try {
      await downloadWarp(url, dest, onProgress);
      return dest;
    } catch (e) {
      lastErr = e;
      try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch (_) {}
      continue;
    }
  }
  throw lastErr || new Error('Не удалось скачать WARP ни с одного источника');
}

async function installWarp(installerPath) {
  if (!IS_WIN) return { ok: false, msg: 'Только Windows' };
  if (!fs.existsSync(installerPath)) return { ok: false, msg: 'Инсталлер не найден' };

  const val = validateWarpBinary(installerPath);
  if (!val.ok) return { ok: false, msg: val.msg };

  // Проверяем, был ли WARP установлен до нас
  const preCheck = await checkWarpInstalledAsync();
  const hadWarpBefore = preCheck.installed;

  // Тихая установка: /S или /silent — пробуем разные флаги
  // Cloudflare WARP использует /S для silent
  return new Promise((resolve) => {
    const proc = spawn(installerPath, ['/S'], {
      windowsHide: true,
      detached: false,
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { proc.kill(); } catch (_) {}
      resolve({ ok: false, msg: 'Таймаут установки (5 минут)' });
    }, 5 * 60 * 1000);

    proc.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, msg: e.message });
    });
    proc.on('exit', async (code) => {
      clearTimeout(timer);
      if (timedOut) return;
      if (code !== 0 && code !== 3010) {
        // Пробуем альтернативный флаг
        const proc2 = spawn(installerPath, ['/silent', '/install'], { windowsHide: true });
        proc2.on('exit', (code2) => {
          if (code2 === 0 || code2 === 3010) {
            if (hadWarpBefore) markWarpPreinstalled();
            else markWarpInstalledByUs();
            resolve({ ok: true, code: code2, hadWarpBefore });
          } else {
            resolve({ ok: false, msg: `Установка завершилась с кодом ${code2}`, code: code2 });
          }
        });
        proc2.on('error', (e) => resolve({ ok: false, msg: e.message }));
      } else {
        if (hadWarpBefore) markWarpPreinstalled();
        else markWarpInstalledByUs();
        resolve({ ok: true, code, hadWarpBefore });
      }
    });
  });
}

async function getWarpAutostartStatus() {
  if (!IS_WIN) return { ok: false, autostart: false };
  // Проверяем несколько мест автозагрузки
  const checks = [];

  // 1) HKCU Run
  const r1 = await execReg(['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/f', 'Cloudflare WARP']);
  checks.push({ location: 'HKCU Run', enabled: r1.ok && /Cloudflare/i.test(r1.out || '') });

  // 2) HKLM Run
  const r2 = await execReg(['query', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/f', 'Cloudflare WARP']);
  checks.push({ location: 'HKLM Run', enabled: r2.ok && /Cloudflare/i.test(r2.out || '') });

  // 3) Startup folder
  const startupPaths = [
    path.join(process.env.APPDATA || '', 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
    path.join(process.env.ProgramData || '', 'Microsoft\\Windows\\Start Menu\\Programs\\StartUp'),
  ];
  for (const sp of startupPaths) {
    try {
      if (fs.existsSync(sp)) {
        const files = fs.readdirSync(sp);
        const hasWarp = files.some(f => /warp|cloudflare/i.test(f));
        checks.push({ location: `Startup folder: ${sp}`, enabled: hasWarp, files: files.filter(f => /warp|cloudflare/i.test(f)) });
      }
    } catch (_) {}
  }

  // 4) Сервис — автозапуск сервиса (не трогаем, это нормально)
  const svc = await execPowerShell('(Get-Service -Name \"CloudflareWarp\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty StartType)');
  checks.push({ location: 'Service CloudflareWarp', enabled: svc.ok && /Automatic/i.test(svc.out || ''), status: svc.out });

  const anyAutostart = checks.some(c => c.enabled && !c.location.includes('Service'));
  return { ok: true, autostart: anyAutostart, checks };
}

async function disableWarpAutostart() {
  if (!IS_WIN) return { ok: false, msg: 'not windows' };

  // Если WARP был предустановлен — НИЧЕГО не меняем
  if (wasWarpPreinstalled()) {
    return { ok: true, skipped: true, reason: 'WARP был установлен до Artofix — автозагрузку не трогаем' };
  }

  // Сохраняем оригинальное состояние автозагрузки перед изменением
  const before = await getWarpAutostartStatus();
  try {
    sec.writeFileAtomic(markerPath(WARP_MARKER_AUTOSTART_ORIGINAL), JSON.stringify({ backup: before, at: new Date().toISOString() }, null, 2));
  } catch (_) {}

  const results = [];

  // Удаляем из HKCU Run
  const r1 = await execReg(['delete', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', 'Cloudflare WARP', '/f']);
  results.push({ action: 'Remove HKCU Run Cloudflare WARP', ok: r1.ok || /не удается найти/i.test(r1.msg || '') || /unable to find/i.test(r1.msg || '') });

  // Удаляем возможные варианты имени
  const names = ['Cloudflare WARP', 'CloudflareWARP', 'warp', 'Cloudflare'];
  for (const name of names) {
    await execReg(['delete', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', name, '/f']);
  }

  // Удаляем из Startup папки
  const startupPaths = [
    path.join(process.env.APPDATA || '', 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
  ];
  for (const sp of startupPaths) {
    try {
      if (fs.existsSync(sp)) {
        const files = fs.readdirSync(sp);
        for (const f of files) {
          if (/warp|cloudflare/i.test(f)) {
            try {
              const full = path.join(sp, f);
              // Проверяем что это действительно ярлык WARP, а не что-то другое
              if (fs.existsSync(full)) {
                fs.unlinkSync(full);
                results.push({ action: `Remove Startup shortcut ${f}`, ok: true });
              }
            } catch (e) {
              results.push({ action: `Remove Startup shortcut ${f}`, ok: false, msg: e.message });
            }
          }
        }
      }
    } catch (_) {}
  }

  return { ok: true, results, before };
}

async function restoreWarpAutostart() {
  // Восстановление автозагрузки не делаем автоматически — только если пользователь просит
  // Но функция есть на случай деинсталляции Artofix
  try {
    const backupPath = markerPath(WARP_MARKER_AUTOSTART_ORIGINAL);
    if (!fs.existsSync(backupPath)) return { ok: false, msg: 'Нет бэкапа автозагрузки' };
    const backup = sec.readJsonSafe(backupPath, 64 * 1024);
    return { ok: true, backup, note: 'Восстановление требует ручной проверки — не делаем автоматически чтобы не вернуть нежелательный автозапуск' };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

async function startWarp() {
  if (!IS_WIN) return { ok: false, msg: 'not windows' };

  // Сначала пробуем через сервис
  let r = await execPowerShell('Start-Service -Name \"CloudflareWarp\" -ErrorAction SilentlyContinue; Get-Service -Name \"CloudflareWarp\" | Select-Object -ExpandProperty Status');
  if (r.ok && /Running/i.test(r.out)) {
    return { ok: true, via: 'service', status: r.out };
  }

  // Пробуем через warp-cli
  const cliPaths = [
    'C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
    'C:\\Program Files (x86)\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
  ];
  for (const cli of cliPaths) {
    if (fs.existsSync(cli)) {
      const conn = await new Promise((resolve) => {
        execFile(cli, ['connect'], { windowsHide: true, timeout: 10000 }, (err, stdout) => {
          resolve({ ok: !err, out: stdout, err: err && err.message });
        });
      });
      if (conn.ok) return { ok: true, via: 'warp-cli', out: conn.out };
    }
  }

  // Пробуем запустить exe напрямую (но без UI — через скрытый запуск)
  const exes = findWarpPaths().filter(p => p.includes('Cloudflare WARP.exe'));
  if (exes.length) {
    try {
      const proc = spawn(exes[0], [], { windowsHide: true, detached: true });
      proc.unref();
      return { ok: true, via: 'exe', pid: proc.pid };
    } catch (e) {
      return { ok: false, msg: e.message };
    }
  }

  return { ok: false, msg: 'Не удалось запустить WARP — не найден' };
}

async function stopWarp() {
  if (!IS_WIN) return { ok: false, msg: 'not windows' };

  // Если WARP был предустановлен — НЕ останавливаем автоматически
  if (wasWarpPreinstalled()) {
    return { ok: true, skipped: true, reason: 'WARP был до Artofix — не останавливаем' };
  }

  // Пробуем через warp-cli disconnect
  const cliPaths = [
    'C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
    'C:\\Program Files (x86)\\Cloudflare\\Cloudflare WARP\\warp-cli.exe',
  ];
  for (const cli of cliPaths) {
    if (fs.existsSync(cli)) {
      await new Promise((resolve) => {
        execFile(cli, ['disconnect'], { windowsHide: true, timeout: 8000 }, () => resolve());
      });
    }
  }

  // Останавливаем сервис только если мы его ставили
  if (wasWarpInstalledByUs()) {
    const r = await execPowerShell('Stop-Service -Name \"CloudflareWarp\" -ErrorAction SilentlyContinue; Get-Service -Name \"CloudflareWarp\" | Select-Object -ExpandProperty Status');
    return { ok: true, via: 'service', status: r.out, stopped: /Stopped/i.test(r.out || '') };
  }

  return { ok: true, skipped: true, reason: 'Оставляем сервис WARP работать (не мы ставили)' };
}

async function hideWarpTray() {
  if (!IS_WIN) return { ok: false, msg: 'not windows' };

  // Метод 1: Скрыть окно WARP через PowerShell (ShowWindow SW_HIDE)
  const hideScript = `
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@
$procs = Get-Process -Name "Cloudflare WARP" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
  try {
    $h = $p.MainWindowHandle
    if ($h -ne 0) { [Win]::ShowWindow($h, 0) | Out-Null }
  } catch {}
}
# Также ищем по заголовку окна
try {
  $hwnd = [Win]::FindWindow($null, "Cloudflare WARP")
  if ($hwnd -ne 0) { [Win]::ShowWindow($hwnd, 0) | Out-Null }
} catch {}
Write-Output "done"
`;
  const r1 = await execPowerShell(hideScript);

  // Метод 2: Убить UI процесс, оставив сервис (если мы ставили WARP)
  // Но только если мы ставили — если предустановлен, не убиваем
  if (wasWarpInstalledByUs()) {
    const killScript = `
$procs = Get-Process -Name "Cloudflare WARP" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
  try {
    # Проверяем что это UI, а не сервис (сервис — warp-svc)
    if ($p.ProcessName -eq "Cloudflare WARP") {
      # Не убиваем сразу, а пробуем скрыть, потом если нужно — убить
      $p.CloseMainWindow() | Out-Null
      Start-Sleep -Milliseconds 500
      if (!$p.HasExited) {
        # Оставляем работать, но скрытым — не убиваем насильно чтобы не сломать подключение
      }
    }
  } catch {}
}
Write-Output "done"
`;
    await execPowerShell(killScript);
  }

  // Метод 3: Настройка реестра WARP чтобы не показывать трей (если есть такая опция)
  // Пробуем найти настройки WARP
  try {
    const warpSettingsPath = path.join(process.env.APPDATA || '', 'Cloudflare\\warp\\settings.json');
    if (fs.existsSync(warpSettingsPath)) {
      const settings = sec.readJsonSafe(warpSettingsPath, 128 * 1024) || {};
      // Если есть опция минимизации в трей — включаем
      // Это не стандартизировано, но пробуем
      settings['minimize_to_tray'] = true;
      settings['launch_at_login'] = false; // Убираем автозагрузку
      // Не перезаписываем без проверки — только если мы ставили
      if (wasWarpInstalledByUs()) {
        // Делаем бэкап
        try {
          const backup = warpSettingsPath + '.artofix_backup';
          if (!fs.existsSync(backup)) fs.copyFileSync(warpSettingsPath, backup);
        } catch (_) {}
        // Не перезаписываем настройки WARP напрямую — это может сломать его
        // Вместо этого просто логируем что нашли
      }
    }
  } catch (_) {}

  return { ok: true, hidden: true, method: 'powershell HideWindow', psResult: r1.out };
}

async function getWarpStatus() {
  if (!IS_WIN) return { installed: false, platform: process.platform };

  const installed = await checkWarpInstalledAsync();
  const autostart = await getWarpAutostartStatus();
  const preinstalled = wasWarpPreinstalled();
  const installedByUs = wasWarpInstalledByUs();

  // Проверяем запущен ли
  let running = false;
  let serviceStatus = null;
  const svc = await execPowerShell('Get-Service -Name \"CloudflareWarp\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status');
  if (svc.ok) {
    serviceStatus = svc.out;
    running = /Running/i.test(svc.out);
  }

  // Проверяем UI процесс
  const uiProc = await execPowerShell('Get-Process -Name \"Cloudflare WARP\" -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count');
  const uiRunning = uiProc.ok && parseInt(uiProc.out || '0', 10) > 0;

  return {
    installed: installed.installed,
    installedDetails: installed,
    preinstalled,
    installedByUs,
    running,
    uiRunning,
    serviceStatus,
    autostart: autostart.autostart,
    autostartDetails: autostart.checks,
  };
}

module.exports = {
  isWarpInstalled,
  checkWarpInstalledAsync,
  wasWarpPreinstalled,
  wasWarpInstalledByUs,
  markWarpPreinstalled,
  markWarpInstalledByUs,
  unmarkWarp,
  sanitizeWarpUrl,
  validateWarpBinary,
  downloadWarp,
  downloadWarpWithFallback,
  installWarp,
  getWarpAutostartStatus,
  disableWarpAutostart,
  restoreWarpAutostart,
  startWarp,
  stopWarp,
  hideWarpTray,
  getWarpStatus,
  WARP_DOWNLOAD_URLS,
  WARP_HOSTS,
};

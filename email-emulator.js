'use strict';
/* =============================================================
   ARTOFIX 2.5 — EMAIL AGE EMULATOR
   -------------------------------------------------------------
   Эмулирует "возраст" почты через cookie файлы и локальные данные,
   чтобы при регистрации аккаунтов почта выглядела старше, как будто
   ею давно пользуются, но при этом "чистая" (не спам).

   Идея:
     • При создании профиля пользователь указывает email
     • Модуль генерирует cookie jar для почтового провайдера с
       "старыми" датами создания (от 6 месяцев до 3+ лет)
     • Cookies выглядят как будто почтой пользовались давно,
       но не активно (нет следов спама)
     • Генерируются также localStorage entries, history-like данные
     • Всё сохраняется в profile/_artofix_email.json и
       profile/_artofix_email_cookies.json
     • engine.py при запуске инжектит эти cookies через CDP

   Поддерживаемые провайдеры:
     gmail, outlook/hotmail, yahoo, yandex, mail.ru, proton, custom

   Безопасность:
     • Email валидируется строгим regex
     • Даты — только в допустимом диапазоне (не будущее)
     • Никаких реальных паролей не храним
     • Cookie values — детерминированы от email + installId + salt
     • Не делаем реальных запросов к почтовым сервисам
   ============================================================= */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sec = require('./security');

const EMAIL_RE = /^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}$/;
const MAX_EMAIL_LEN = 254;

function sanitizeEmail(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();
  if (!s || s.length > MAX_EMAIL_LEN) return null;
  if (/[\u0000-\u001f\u007f]/.test(s)) return null;
  if (!EMAIL_RE.test(s)) return null;
  // Дополнительные проверки
  if (s.includes('..')) return null;
  if (s.startsWith('.') || s.startsWith('@') || s.endsWith('.')) return null;
  return s;
}

function detectProvider(email) {
  const domain = (email.split('@')[1] || '').toLowerCase();
  if (!domain) return { provider: 'custom', domain: 'custom' };
  if (domain === 'gmail.com' || domain === 'googlemail.com') return { provider: 'gmail', domain };
  if (domain === 'outlook.com' || domain === 'hotmail.com' || domain === 'live.com' || domain === 'msn.com') return { provider: 'outlook', domain };
  if (domain.includes('yahoo.')) return { provider: 'yahoo', domain };
  if (domain.includes('yandex.')) return { provider: 'yandex', domain };
  if (domain === 'mail.ru' || domain === 'inbox.ru' || domain === 'list.ru' || domain === 'bk.ru') return { provider: 'mailru', domain };
  if (domain.includes('proton')) return { provider: 'proton', domain };
  if (domain.includes('icloud.com') || domain.includes('me.com') || domain.includes('mac.com')) return { provider: 'icloud', domain };
  return { provider: 'custom', domain };
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function seedFrom(str) {
  return parseInt(sha256(str).slice(0, 12), 16) >>> 0;
}

function makeRng(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomString(rng, len, charset) {
  charset = charset || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < len; i++) {
    s += charset[Math.floor(rng() * charset.length)];
  }
  return s;
}

function randomDigits(rng, len) {
  return randomString(rng, len, '0123456789');
}

// Генерирует детерминированный cookie value от seed
function cookieValue(rng, len) {
  return randomString(rng, len);
}

function daysAgo(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() - days);
  return d;
}

function generateAgedDate(rng, ageOption) {
  // ageOption: "6-12 мес", "1-2 года", "3+ года", "новый", или число дней
  const now = new Date();
  let minDays, maxDays;
  switch (ageOption) {
    case '3+ года':
    case '3+':
      minDays = 1095; maxDays = 1825; // 3-5 лет
      break;
    case '1-2 года':
    case '1-2':
      minDays = 365; maxDays = 730;
      break;
    case '6-12 мес':
    case '6-12':
      minDays = 180; maxDays = 365;
      break;
    case 'новый':
    case 'new':
      minDays = 1; maxDays = 30;
      break;
    default:
      if (typeof ageOption === 'number' && ageOption > 0) {
        minDays = Math.floor(ageOption * 0.8);
        maxDays = Math.floor(ageOption * 1.2);
      } else {
        minDays = 365; maxDays = 730;
      }
  }
  const days = minDays + Math.floor(rng() * (maxDays - minDays));
  const created = daysAgo(now, days);
  // Last used — недавно, но не слишком часто (имитация редкого использования)
  const lastUsedDays = Math.floor(rng() * 30); // 0-30 дней назад
  const lastUsed = daysAgo(now, lastUsedDays);
  // Expiry — в будущем
  const expiryDays = 30 + Math.floor(rng() * 335); // 30-365 дней вперёд
  const expiry = new Date(now);
  expiry.setDate(expiry.getDate() + expiryDays);

  return { created, lastUsed, expiry, ageDays: days };
}

function generateProviderCookies(email, providerInfo, ageOption, installId, profileName) {
  const seed = seedFrom(`email|${installId}|${profileName}|${email}|${providerInfo.provider}`);
  const rng = makeRng(seed);
  const aged = generateAgedDate(rng, ageOption);
  const nowSec = Math.floor(Date.now() / 1000);
  const createdSec = Math.floor(aged.created.getTime() / 1000);
  const expirySec = Math.floor(aged.expiry.getTime() / 1000);

  const cookies = [];

  function addCookie(domain, name, value, opts) {
    opts = opts || {};
    cookies.push({
      domain: domain,
      name: name,
      value: value,
      path: opts.path || '/',
      secure: opts.secure !== false,
      httpOnly: !!opts.httpOnly,
      sameSite: opts.sameSite || 'Lax',
      // Для CDP
      expires: expirySec,
      // Для эмуляции возраста
      _artofix_created: createdSec,
      _artofix_ageDays: aged.ageDays,
    });
  }

  // Общие cookies для всех провайдеров — имитация "старого" пользователя
  const commonDomains = {
    gmail: ['.google.com', '.gmail.com', 'accounts.google.com'],
    outlook: ['.live.com', '.outlook.com', '.microsoft.com'],
    yahoo: ['.yahoo.com', '.yahooapis.com'],
    yandex: ['.yandex.ru', '.yandex.com', '.ya.ru'],
    mailru: ['.mail.ru', '.vk.com'],
    proton: ['.proton.me', '.protonmail.com'],
    icloud: ['.icloud.com', '.apple.com'],
    custom: ['.' + providerInfo.domain],
  };

  const domains = commonDomains[providerInfo.provider] || commonDomains.custom;

  // Уникальные ID, детерминированные от email
  const gaId = `GA1.2.${randomDigits(rng, 9)}.${createdSec}`;
  const gid = `${randomDigits(rng, 9)}.${createdSec}`;

  switch (providerInfo.provider) {
    case 'gmail':
      // Google cookies — выглядят как у старого аккаунта
      addCookie('.google.com', 'NID', `${randomDigits(rng, 3)}=${cookieValue(rng, 180)}`, { httpOnly: true });
      addCookie('.google.com', '1P_JAR', `${new Date(aged.lastUsed).toISOString().slice(0, 7)}-${randomDigits(rng, 2)}`, {});
      addCookie('.google.com', 'AEC', cookieValue(rng, 200), { httpOnly: true, sameSite: 'Lax' });
      addCookie('.google.com', 'OGPC', cookieValue(rng, 20) + ':' + cookieValue(rng, 15), {});
      addCookie('.google.com', '_ga', gaId, {});
      addCookie('.google.com', '_gid', gid, {});
      addCookie('.google.com', 'OTZ', `${randomDigits(rng, 7)}_${randomDigits(rng, 2)}_${randomDigits(rng, 6)}`, {});
      // Accounts cookies
      addCookie('accounts.google.com', 'OSID', cookieValue(rng, 100), { httpOnly: true, secure: true });
      addCookie('accounts.google.com', 'LSID', cookieValue(rng, 80), { httpOnly: true, secure: true });
      addCookie('accounts.google.com', 'ACCOUNT_CHOOSER', `AFx${cookieValue(rng, 20)}`, {});
      // Gmail specific
      addCookie('.gmail.com', 'GMAIL_AT', `AF6${cookieValue(rng, 30)}`, { httpOnly: true });
      break;

    case 'outlook':
      addCookie('.live.com', 'MUID', cookieValue(rng, 32).toUpperCase(), {});
      addCookie('.live.com', 'ANON', `A=${cookieValue(rng, 32)}&E=${randomDigits(rng, 3)}&W=${randomDigits(rng, 1)}`, { httpOnly: true });
      addCookie('.outlook.com', 'OlcUserId', randomDigits(rng, 16), {});
      addCookie('.outlook.com', 'OutlookSession', cookieValue(rng, 24), {});
      addCookie('.microsoft.com', 'MSFPC', `ID=${cookieValue(rng, 32)}&LW=1`, {});
      break;

    case 'yandex':
      addCookie('.yandex.ru', 'yuidss', randomDigits(rng, 9), {});
      addCookie('.yandex.ru', 'yandexuid', randomDigits(rng, 19), { httpOnly: true });
      addCookie('.yandex.ru', 'is_gdpr', '0', {});
      addCookie('.yandex.ru', 'gdpr', '0', {});
      addCookie('.yandex.ru', '_yasc', cookieValue(rng, 100), {});
      break;

    case 'mailru':
      addCookie('.mail.ru', 'Mpop', `${createdSec}:${randomDigits(rng, 1)}:${randomDigits(rng, 10)}`, {});
      addCookie('.mail.ru', 'b', cookieValue(rng, 20), {});
      addCookie('.mail.ru', 'p', randomDigits(rng, 10), {});
      break;

    case 'yahoo':
      addCookie('.yahoo.com', 'B', cookieValue(rng, 12), {});
      addCookie('.yahoo.com', 'A3', `d=${cookieValue(rng, 20)}&s=${randomDigits(rng, 1)}`, {});
      addCookie('.yahoo.com', 'A1', `d=${cookieValue(rng, 20)}`, {});
      break;

    default:
      // Custom — базовые cookies
      addCookie(domains[0], 'session_id', cookieValue(rng, 32), { httpOnly: true });
      addCookie(domains[0], 'user_pref', `lang=${providerInfo.domain.includes('ru') ? 'ru' : 'en'}`, {});
      addCookie(domains[0], '_ga', gaId, {});
      break;
  }

  // Добавляем общие для всех — имитация истории браузера
  addCookie(domains[0], '_artofix_email_age', `${aged.ageDays}`, { httpOnly: false });
  addCookie(domains[0], '_artofix_profile', sha256(profileName).slice(0, 16), {});

  return { cookies, aged, provider: providerInfo.provider, domain: providerInfo.domain };
}

function generateLocalStorageData(email, providerInfo, ageOption, installId, profileName) {
  const seed = seedFrom(`ls|${installId}|${profileName}|${email}`);
  const rng = makeRng(seed);
  const aged = generateAgedDate(rng, ageOption);

  const data = {};

  switch (providerInfo.provider) {
    case 'gmail':
      data['https://mail.google.com'] = {
        'GMAIL_UI_STATE': JSON.stringify({ lastVisit: aged.lastUsed.toISOString(), theme: 'default' }),
        'ACCOUNT_AGE_HINT': JSON.stringify({ created: aged.created.toISOString(), verified: true }),
      };
      data['https://accounts.google.com'] = {
        'ACCOUNT_CHOOSER_STATE': JSON.stringify({ accounts: [email], lastUsed: aged.lastUsed.toISOString() }),
      };
      break;
    case 'outlook':
      data['https://outlook.live.com'] = {
        'OutlookSessionData': JSON.stringify({ user: email, firstSeen: aged.created.toISOString() }),
      };
      break;
    case 'yandex':
      data['https://mail.yandex.ru'] = {
        'yandex_mail_state': JSON.stringify({ login: email, firstLogin: aged.created.toISOString() }),
      };
      break;
    default:
      data[`https://${providerInfo.domain}`] = {
        'user_email': email,
        'first_seen': aged.created.toISOString(),
      };
  }

  return { localStorage: data, aged };
}

function saveEmailEmulation(profileDir, email, ageOption, installId, profileName) {
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return { ok: false, msg: 'Некорректный email' };

  const providerInfo = detectProvider(cleanEmail);
  const cookiesData = generateProviderCookies(cleanEmail, providerInfo, ageOption, installId, profileName);
  const lsData = generateLocalStorageData(cleanEmail, providerInfo, ageOption, installId, profileName);

  try {
    fs.mkdirSync(profileDir, { recursive: true });

    const emailMeta = {
      email: cleanEmail,
      provider: providerInfo.provider,
      domain: providerInfo.domain,
      ageOption: ageOption,
      created: cookiesData.aged.created.toISOString(),
      lastUsed: cookiesData.aged.lastUsed.toISOString(),
      expiry: cookiesData.aged.expiry.toISOString(),
      ageDays: cookiesData.aged.ageDays,
      ageHuman: `${Math.floor(cookiesData.aged.ageDays / 365)} лет ${Math.floor((cookiesData.aged.ageDays % 365) / 30)} мес`,
      emulated: true,
      generatedAt: new Date().toISOString(),
      profile: profileName,
      // Не храним пароли
    };

    const cookiesFile = path.join(profileDir, '_artofix_email.json');
    sec.writeFileAtomic(cookiesFile, JSON.stringify(emailMeta, null, 2));

    const cookiesJar = path.join(profileDir, '_artofix_email_cookies.json');
    sec.writeFileAtomic(cookiesJar, JSON.stringify({
      email: cleanEmail,
      provider: providerInfo.provider,
      cookies: cookiesData.cookies,
      localStorage: lsData.localStorage,
      aged: {
        created: cookiesData.aged.created.toISOString(),
        lastUsed: cookiesData.aged.lastUsed.toISOString(),
        expiry: cookiesData.aged.expiry.toISOString(),
        ageDays: cookiesData.aged.ageDays,
      },
      generatedAt: new Date().toISOString(),
    }, null, 2));

    // Также создаём файл для engine.py чтобы инжектить cookies
    const forEngine = path.join(profileDir, '_artofix_email_for_engine.json');
    sec.writeFileAtomic(forEngine, JSON.stringify({
      cookies: cookiesData.cookies.map(c => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        expiry: c.expires,
      })),
      localStorage: lsData.localStorage,
    }, null, 2));

    return { ok: true, meta: emailMeta, cookiesCount: cookiesData.cookies.length };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

function readEmailEmulation(profileDir) {
  try {
    const metaPath = path.join(profileDir, '_artofix_email.json');
    const cookiesPath = path.join(profileDir, '_artofix_email_cookies.json');
    const meta = sec.readJsonSafe(metaPath, 128 * 1024);
    const cookies = sec.readJsonSafe(cookiesPath, 512 * 1024);
    if (!meta) return { ok: false, exists: false };
    return { ok: true, exists: true, meta, cookies };
  } catch (e) {
    return { ok: false, msg: e.message, exists: false };
  }
}

function removeEmailEmulation(profileDir) {
  try {
    const files = ['_artofix_email.json', '_artofix_email_cookies.json', '_artofix_email_for_engine.json'];
    for (const f of files) {
      const p = path.join(profileDir, f);
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
}

function listAges() {
  return [
    { id: 'новый', label: 'Новый (до 1 мес)', days: '1-30' },
    { id: '6-12 мес', label: '6-12 месяцев', days: '180-365' },
    { id: '1-2 года', label: '1-2 года', days: '365-730' },
    { id: '3+ года', label: '3+ года (старый)', days: '1095-1825' },
  ];
}

module.exports = {
  sanitizeEmail,
  detectProvider,
  generateProviderCookies,
  generateLocalStorageData,
  saveEmailEmulation,
  readEmailEmulation,
  removeEmailEmulation,
  listAges,
  EMAIL_RE,
};

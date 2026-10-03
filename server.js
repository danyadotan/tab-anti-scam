/**
 * TAB@Anti-Scam — Call Guardian backend (v3, staged consent)
 * ------------------------------------------------------------------
 * Inbound scam-call guardian using Twilio Conferences + Media Streams + streaming STT.
 *
 * The person stays in control. TAB never takes over a call on its own:
 *
 *   Call opens   → the caller hears "this call is recorded for security".
 *   3 signs      → WARN: the caller is put on hold for a few seconds and only the
 *                  person hears TAB: this call looks suspicious, I'm right here with you.
 *                  The family gets a WhatsApp message with the transcript so far.
 *   4 signs      → OFFER: the person hears how to hand the call to TAB
 *                  (say the consent phrase, or press 9 where keypresses are supported).
 *   Consent      → TAKEOVER: the person hears that TAB has taken over and can hang up.
 *                  The caller hears the persona the person chose (default: the neighbour).
 *                  The family gets a second message.
 * The person can say the consent phrase at any stage, even before any sign.
 *
 * Pipeline:
 *   Caller → Twilio number → /voice: recording notice, caller stream, join conference
 *   TAB dials the person into the same conference, with their own stream
 *   Each stream → Deepgram STT (caller → sign detector, person → consent phrase)
 *   Whisper  = hold the caller + announce to the person's participant only
 *   Takeover = redirect the caller's leg to the persona line, which ends the conference
 *   Every event is broadcast to operator dashboards on /operator (token required).
 *
 * Run:
 *   npm install
 *   node server.js                 (Node 18+)
 *   ngrok http 8080                → set the https host as PUBLIC_HOST
 *   Twilio number Voice webhook →  https://<host>/voice
 *   Operator view (inline):      https://<host>/?token=<OPERATOR_TOKEN>
 *   Operator view (v2 external): wss://<host>/operator?token=<OPERATOR_TOKEN>
 */

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');
const twilio = require('twilio');

// ---------- Config (env) ----------
const PORT = process.env.PORT || 8080;
const PUBLIC_HOST = process.env.PUBLIC_HOST || 'your-ngrok-host.ngrok.app'; // no scheme
const BASE = `https://${PUBLIC_HOST}`;
const ELDER_PHONE = process.env.ELDER_PHONE || '+9725XXXXXXXX';             // the person we protect
const ELDER_NAME = process.env.ELDER_NAME || 'האדם המוגן';                  // used in family messages
const TWILIO_NUMBER = process.env.TWILIO_NUMBER || '';                      // caller ID when dialing the person
const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const STT_LANGUAGE = process.env.STT_LANGUAGE || 'ru';   // 'ru' primary; 'he' for Hebrew (verify Deepgram model)

// The phrase the person says to hand the call to TAB. Works at any stage.
const CONSENT_PHRASE = (process.env.CONSENT_PHRASE || process.env.CUE_PHRASE || 'мой сын рядом').toLowerCase();
const CONSENT_DIGIT = process.env.CONSENT_DIGIT || '9';

// Stage thresholds, in distinct signs (a courier marker counts as one more).
const WARN_AT = Number(process.env.WARN_AT || 3);
const OFFER_AT = Number(process.env.OFFER_AT || 4);

// Family / guardians notified on WhatsApp (comma-separated E.164 numbers).
const FAMILY_WHATSAPP = (process.env.FAMILY_WHATSAPP || '').split(',').map(s => s.trim()).filter(Boolean);
const WHATSAPP_FROM = process.env.WHATSAPP_FROM || '';  // e.g. whatsapp:+14155238886 (Twilio sandbox)

// Emergency numbers we NEVER monitor or touch — wired first, on purpose.
const EMERGENCY = (process.env.EMERGENCY || '100,101,102,112').split(',').map(s => s.trim()).filter(Boolean);
// Optional: numbers we never monitor (known family, etc.)
const WHITELIST = (process.env.WHITELIST || '').split(',').map(s => s.trim()).filter(Boolean);

// Operator access. Live transcripts are private: every operator connection must
// present this token. If unset, a random one is generated and printed at startup.
const OPERATOR_TOKEN = process.env.OPERATOR_TOKEN || crypto.randomBytes(16).toString('hex');
// Demo endpoints (simulated calls and speech) are off unless DEMO_MODE=1.
const DEMO_MODE = process.env.DEMO_MODE === '1';

// ---------- What each side hears ----------
// Polly: Tatyana = ru female, Maxim = ru male. Hebrew uses a Google voice (verify on your account).
const V_RU = process.env.TAB_VOICE || 'Polly.Tatyana';
const V_HE = process.env.HE_VOICE || 'Google.he-IL-Standard-A';

// Heard by the caller before the call connects. Covers the person legally and
// tells a scammer up front that someone is listening.
const NOTICE = [
  { voice: V_RU, language: 'ru-RU', text: process.env.NOTICE_RU || 'Этот разговор записывается в целях безопасности.' },
  { voice: V_HE, language: 'he-IL', text: process.env.NOTICE_HE || 'שיחה זו מוקלטת לצורכי אבטחה.' },
];

// Heard by the person only (the caller is on hold meanwhile). Short on purpose.
const WHISPER = {
  warn: process.env.WARN_LINE ||
    'Это TAB. Этот звонок похож на мошенничество. Не называйте коды и не переводите деньги. Я рядом с вами, не волнуйтесь.',
  warn_courier: process.env.WARN_LINE_COURIER ||
    'Это TAB. Похоже, к вам хотят прислать курьера за деньгами. Никому не открывайте и ничего не передавайте. Я рядом с вами, не волнуйтесь.',
  offer: process.env.OFFER_LINE ||
    `Это TAB. Опасность растёт. Если хотите, чтобы я продолжил разговор вместо вас, скажите: «${process.env.CONSENT_PHRASE || process.env.CUE_PHRASE || 'мой сын рядом'}», или нажмите ${CONSENT_DIGIT}.`,
  handoff: process.env.HANDOFF_LINE ||
    'Это TAB. Я взял разговор на себя. Можете спокойно положить трубку. Семья уже знает.',
};

// Heard by the caller after the person consents. The person chose this voice,
// so it is the person inviting a helper, not the system impersonating anyone.
const PERSONA_NAME = process.env.PERSONA_NAME || 'השכנה נאדיה';
const PERSONA_VOICE = process.env.PERSONA_VOICE || 'Polly.Tatyana';
const PERSONA_LINE = process.env.PERSONA_LINE ||
  'Здравствуйте, это соседка, Надя. Я помогаю с этим звонком. Назовите ваш отдел и табельный номер — мы перезвоним в банк по официальному номеру.';
const PERSONA_LINE_COURIER = process.env.PERSONA_LINE_COURIER ||
  'Здравствуйте, это соседка, Надя. Никто не передаст курьеру ни деньги, ни карту. Семья уже знает об этом звонке.';

const twClient = (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN)
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

// ---------- 5-sign detector ----------
// Rolling keyword match on the caller's transcript. Deterministic and fast (good
// for a live demo); swap in an LLM pass later for nuance. Index order matches the
// operator UI: 0 urgency, 1 money, 2 codes/cards, 3 secrecy, 4 authority.
//
// Matching rules (to avoid false positives like "картошка" matching "карт"):
//  - A term must start at a word boundary.
//  - A term written as "=word" must match the whole word (e.g. "=код" matches
//    "код" but not "кодекс").
//  - Other terms are stems: "перевед" matches "переведите", "переведёте".
//  - Hebrew terms may carry up to two attached prefix letters (ו, ה, ב, ל, מ, ש, כ),
//    so "=קוד" matches "הקוד" and "בקוד" but not "קודם".
const SIGNS = {
  ru: [
    { id: 0, label: 'Срочность и давление', terms: ['срочно', 'немедленно', 'сейчас же', 'прямо сейчас', 'поторопитесь', 'две минуты', 'нет времени'] },
    { id: 1, label: 'Просьба перевести деньги', terms: ['перевед', 'перевод', 'на счёт', 'на счет', 'безопасный счёт', 'безопасный счет', 'реквизит', 'наличны'] },
    { id: 2, label: 'Просьба назвать код или номер карты', terms: ['=код', '=кода', '=коды', 'код из', 'пароль', 'из смс', 'из сообщения', '=пин', 'пин-код', 'cvv', 'секретное слово', 'номер карты', '=карту', '=карты', 'данные карты'] },
    { id: 3, label: 'Просьба никому не говорить', terms: ['никому не говорите', 'не рассказывайте', 'конфиденциально', 'это секрет', 'между нами', 'даже семье', 'даже детям'] },
    { id: 4, label: 'Выдаёт себя за банк или власти', terms: ['служба безопасности', 'службы безопасности', 'полиц', 'налогов', 'госуслуг', 'следовател', 'центральный банк', 'центробанк', 'соцобеспечен'] },
  ],
  he: [
    { id: 0, label: 'דחיפות ולחץ', terms: ['=דחוף', '=מיד', '=תזדרז', '=תזדרזי', 'שתי דקות', 'אין זמן'] },
    { id: 1, label: 'בקשה להעביר כסף', terms: ['=להעביר', '=העברה', 'חשבון בטוח', '=מזומן', 'פרטי חשבון'] },
    { id: 2, label: 'בקשה לקוד או מספר כרטיס', terms: ['=קוד', '=סיסמה', 'קוד מההודעה', 'מספר סודי', 'cvv', 'מספר כרטיס', 'פרטי כרטיס', 'פרטי האשראי'] },
    { id: 3, label: 'בקשה לא לספר לאף אחד', terms: ['אל תספר', 'אל תספרי', 'זה סודי', '=בינינו', 'לא לספר', 'גם לא למשפחה', 'גם לא לילדים'] },
    { id: 4, label: 'מתחזה לבנק או לרשויות', terms: ['מחלקת ביטחון', 'אבטחת מידע', '=משטרה', '=שוטר', 'מס הכנסה', 'ביטוח לאומי', 'בנק ישראל'] },
  ],
};

// Physical-courier markers — the "שלחתי נציג שיאסוף את הצ׳ק" vector.
const COURIER_TERMS = {
  ru: ['курьер', 'приедет за', 'подойдёт за', 'подойдет за', 'заберёт', 'заберет', 'забрать деньги', 'забрать карту', 'передать курьер', '=чек'],
  he: ['=שליח', '=נציג', '=יאסוף', '=לאסוף', '=צ׳ק', "=צ'ק", 'יבוא לקחת', 'יגיע לקחת'],
};

const HE_PREFIX = '[ובהלמשכ]{0,2}';
const _reCache = new Map();
function termRegex(term, lang) {
  const key = lang + '|' + term;
  if (_reCache.has(key)) return _reCache.get(key);
  const whole = term.startsWith('=');
  const body = (whole ? term.slice(1) : term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const prefix = lang === 'he' ? HE_PREFIX : '';
  const tail = whole ? '(?![\\p{L}\\p{N}])' : '';
  const re = new RegExp('(?<![\\p{L}\\p{N}])' + prefix + body + tail, 'iu');
  _reCache.set(key, re);
  return re;
}
function hasTerm(text, terms, lang) {
  const hay = (text || '').toLowerCase();
  return terms.some(t => termRegex(t, lang).test(hay));
}

function detectSigns(text, lang) {
  const set = SIGNS[lang] || SIGNS.ru;
  const fired = [];
  for (const s of set) if (hasTerm(text, s.terms, lang)) fired.push(s.id);
  return fired;
}

function detectCourier(text, lang) {
  return hasTerm(text, COURIER_TERMS[lang] || COURIER_TERMS.ru, lang);
}

// Pressure 0–100 for the v2 meter: escalates with distinct signs, courier adds weight.
function pressureLevel(st) {
  let p = st.firedSet.size * 18;
  if (st.ttype === 'courier') p += 12;
  if (st.firedSet.has(2)) p = Math.max(p, 60);
  return Math.max(0, Math.min(100, p));
}

// Distinct signs, with a courier marker counting as one more.
function signCount(st) {
  return st.firedSet.size + (st.ttype === 'courier' ? 1 : 0);
}

// ---------- App + servers ----------
const app = express();
app.use(express.urlencoded({ extended: false }));
const server = http.createServer(app);

// Per-call state, keyed by the caller's Twilio CallSid
const calls = new Map();
// The person's call leg → caller CallSid
const personLegs = new Map();
// Connected operator dashboards
const operators = new Set();

function broadcast(evt) {
  const msg = JSON.stringify({ ...evt, ts: Date.now() });
  for (const ws of operators) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
}

function tokenOk(token) {
  if (typeof token !== 'string') return false;
  const a = Buffer.from(token), b = Buffer.from(OPERATOR_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function newCall(callSid, from) {
  const st = {
    callSid, from, firedSet: new Set(), ttype: null, transcript: [],
    stage: 'monitor', personSid: null, confSid: null, notified: false,
  };
  calls.set(callSid, st);
  return st;
}

const confName = (callSid) => `tab-${callSid}`;
const esc = (s) => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));

// ---------- /voice : inbound TwiML ----------
app.post('/voice', (req, res) => {
  const from = req.body.From || 'unknown';
  const callSid = req.body.CallSid;

  // Emergency or whitelisted callers: connect straight through, no monitoring, no notice.
  if (EMERGENCY.includes(from) || WHITELIST.includes(from)) {
    const vr = new twilio.twiml.VoiceResponse();
    vr.dial({}, ELDER_PHONE);
    return res.type('text/xml').send(vr.toString());
  }

  newCall(callSid, from);
  broadcast({ type: 'call_start', callSid, from });

  const vr = new twilio.twiml.VoiceResponse();
  // 1. Recording notice, heard by the caller before anything else.
  for (const n of NOTICE) vr.say({ voice: n.voice, language: n.language }, n.text);
  // 2. Stream the caller's voice only.
  vr.start().stream({ url: `wss://${PUBLIC_HOST}/media`, track: 'inbound_track' })
    .parameter({ name: 'callSid', value: callSid })
    .parameter({ name: 'role', value: 'caller' });
  // 3. The caller waits in a conference room; when the caller leaves, the room ends.
  vr.dial().conference({
    startConferenceOnEnter: true, endConferenceOnExit: true, beep: false,
    waitUrl: `${BASE}/silence`,
  }, confName(callSid));
  res.type('text/xml').send(vr.toString());

  // 4. Dial the person into the same room, with their own stream.
  dialPerson(callSid, req.body.To);
});

function dialPerson(callSid, calledNumber) {
  if (!twClient) return;
  const twiml =
    `<Response><Start><Stream url="wss://${esc(PUBLIC_HOST)}/media" track="inbound_track">` +
    `<Parameter name="callSid" value="${esc(callSid)}"/><Parameter name="role" value="person"/>` +
    `</Stream></Start><Dial><Conference beep="false" startConferenceOnEnter="true" endConferenceOnExit="false">` +
    `${esc(confName(callSid))}</Conference></Dial></Response>`;
  twClient.calls.create({
    to: ELDER_PHONE,
    from: TWILIO_NUMBER || calledNumber,
    twiml,
    timeout: 30,
    statusCallback: `${BASE}/person-status?callSid=${encodeURIComponent(callSid)}`,
    statusCallbackEvent: ['completed'],
  }).then(c => {
    const st = calls.get(callSid);
    if (st) st.personSid = c.sid;
    personLegs.set(c.sid, callSid);
  }).catch(err => broadcast({ type: 'error', callSid, msg: 'dialing the person failed: ' + err.message }));
}

// If the person never picked up, release the caller.
app.post('/person-status', (req, res) => {
  res.sendStatus(204);
  const callSid = req.query.callSid;
  const status = req.body.CallStatus;
  if (!twClient || !['no-answer', 'busy', 'failed', 'canceled'].includes(status)) return;
  const vr = new twilio.twiml.VoiceResponse();
  vr.say({ voice: V_RU, language: 'ru-RU' }, 'Абонент не может ответить.');
  vr.hangup();
  twClient.calls(callSid).update({ twiml: vr.toString() }).catch(() => {});
});

app.all('/silence', (_req, res) => res.type('text/xml').send('<Response><Pause length="60"/></Response>'));

// Lines played to one participant are served from here by id, so call text never sits in a URL.
const sayLines = new Map();
app.all('/say/:id', (req, res) => {
  const l = sayLines.get(req.params.id);
  const vr = new twilio.twiml.VoiceResponse();
  if (l) vr.say({ voice: l.voice, language: l.language }, l.text);
  res.type('text/xml').send(vr.toString());
});

async function conferenceSid(st) {
  if (st.confSid) return st.confSid;
  const list = await twClient.conferences.list({ friendlyName: confName(st.callSid), status: 'in-progress', limit: 1 });
  st.confSid = list[0] && list[0].sid;
  return st.confSid;
}

// Rough speaking time, so the caller is released from hold after the line ends.
const speakMs = (text) => Math.min(20000, 1500 + text.length * 70);

// Whisper to the person only: hold the caller, announce to the person's participant, release.
async function whisper(st, text, kind) {
  broadcast({ type: 'whisper', callSid: st.callSid, kind, line: text, simulated: !twClient });
  if (!twClient || !st.personSid) return;
  try {
    const conf = await conferenceSid(st);
    if (!conf) throw new Error('conference not found');
    const id = crypto.randomBytes(8).toString('hex');
    sayLines.set(id, { voice: V_RU, language: 'ru-RU', text });
    setTimeout(() => sayLines.delete(id), 120000);
    await twClient.conferences(conf).participants(st.callSid).update({ hold: true, holdUrl: `${BASE}/silence` });
    await twClient.conferences(conf).participants(st.personSid).update({ announceUrl: `${BASE}/say/${id}` });
    if (kind !== 'handoff') {
      setTimeout(() => {
        twClient.conferences(conf).participants(st.callSid).update({ hold: false }).catch(() => {});
      }, speakMs(text));
    }
  } catch (err) {
    broadcast({ type: 'error', callSid: st.callSid, msg: 'whisper failed: ' + err.message });
  }
}

// ---------- Family notification (WhatsApp) ----------
const SIGN_LABELS_HE = ['דחיפות ולחץ', 'בקשה להעביר כסף', 'בקשה לקוד או מספר כרטיס', 'בקשה לא לספר לאף אחד', 'התחזות לבנק או לרשויות'];

function familyMessage(st, headline) {
  const signs = [...st.firedSet].map(i => SIGN_LABELS_HE[i]).join(', ') || '—';
  const courier = st.ttype === 'courier' ? '\nחשד לשליח שיגיע לאסוף כסף או צ׳ק.' : '';
  const lines = st.transcript.slice(-12)
    .map(t => `${t.who === 'caller' ? 'מתקשר' : ELDER_NAME}: ${t.text}`).join('\n');
  const body = `TAB · ${headline}\nאצל: ${ELDER_NAME}\nמספר מתקשר: ${st.from}\nסימנים (${st.firedSet.size}/5): ${signs}${courier}\n\nתמליל עד עכשיו:\n${lines}`;
  return body.length > 1500 ? body.slice(0, 1497) + '…' : body;
}

function notifyFamily(st, headline) {
  const body = familyMessage(st, headline);
  if (!twClient || !WHATSAPP_FROM || !FAMILY_WHATSAPP.length) {
    broadcast({ type: 'notify', callSid: st.callSid, simulated: true, to: FAMILY_WHATSAPP, body });
    return;
  }
  for (const n of FAMILY_WHATSAPP) {
    twClient.messages.create({ from: WHATSAPP_FROM, to: `whatsapp:${n}`, body })
      .then(() => broadcast({ type: 'notify', callSid: st.callSid, to: [n], body }))
      .catch(err => broadcast({ type: 'error', callSid: st.callSid, msg: `WhatsApp to ${n} failed: ${err.message}` }));
  }
}

// ---------- Stages ----------
function setStage(st, stage, reason) {
  st.stage = stage;
  broadcast({ type: 'stage', callSid: st.callSid, stage, reason, ttype: st.ttype || 'phone', signs: [...st.firedSet] });
}

function escalate(st) {
  if (st.stage === 'takeover') return;
  const n = signCount(st);
  const warnText = st.ttype === 'courier' ? WHISPER.warn_courier : WHISPER.warn;
  let justWarned = false;

  if (n >= WARN_AT && st.stage === 'monitor') {
    setStage(st, 'warn', `${n} signs`);
    justWarned = true;
    if (!st.notified) { st.notified = true; notifyFamily(st, 'שיחה חשודה עכשיו'); }
  }
  if (n >= OFFER_AT && st.stage === 'warn') {
    setStage(st, 'offer', `${n} signs`);
    // If both thresholds were crossed at once, say the warning and the offer together.
    whisper(st, justWarned ? `${warnText} ${WHISPER.offer}` : WHISPER.offer, 'offer');
    return;
  }
  if (justWarned) whisper(st, warnText, 'warn');
}

// Only ever called after the person consented (phrase or keypress).
async function takeover(st, how) {
  if (st.stage === 'takeover') return;
  setStage(st, 'takeover', how);
  notifyFamily(st, `TAB נכנס לשיחה בהסכמת ${ELDER_NAME}`);

  const line = st.ttype === 'courier' ? PERSONA_LINE_COURIER : PERSONA_LINE;
  await whisper(st, WHISPER.handoff, 'handoff');

  if (!twClient) {
    broadcast({ type: 'takeover_sim', callSid: st.callSid, line, persona: PERSONA_NAME });
    return;
  }
  // Let the person hear the handoff first, then move the caller to the persona.
  // The caller leaving the room ends the conference, which releases the person.
  setTimeout(() => {
    const vr = new twilio.twiml.VoiceResponse();
    vr.say({ voice: PERSONA_VOICE, language: 'ru-RU' }, line);
    vr.pause({ length: 1 });
    vr.say({ voice: PERSONA_VOICE, language: 'ru-RU' }, 'До свидания.');
    vr.hangup();
    twClient.calls(st.callSid).update({ twiml: vr.toString() })
      .then(() => broadcast({ type: 'takeover', callSid: st.callSid, line, persona: PERSONA_NAME }))
      .catch(err => broadcast({ type: 'error', callSid: st.callSid, msg: 'takeover failed: ' + err.message }));
  }, speakMs(WHISPER.handoff));
}

// ---------- Speech handlers ----------
function onCallerSpeech(callSid, text) {
  const st = calls.get(callSid);
  if (!st) return;
  st.transcript.push({ who: 'caller', text });
  broadcast({ type: 'transcript', speaker: 'caller', text, callSid });

  // Threat type: the first courier marker flips the call to the physical track.
  const courierNow = detectCourier(text, STT_LANGUAGE);
  if (!st.ttype || (st.ttype === 'phone' && courierNow)) {
    st.ttype = courierNow ? 'courier' : 'phone';
    broadcast({ type: 'ttype', ttype: st.ttype, callSid });
  }

  const fired = detectSigns(text, STT_LANGUAGE);
  fired.forEach(id => st.firedSet.add(id));
  if (fired.length || courierNow) {
    broadcast({ type: 'signs', signs: [...st.firedSet], callSid });
    broadcast({ type: 'pressure', level: pressureLevel(st), callSid });
  }
  escalate(st);
}

function onPersonSpeech(callSid, text) {
  const st = calls.get(callSid);
  if (!st) return;
  st.transcript.push({ who: 'person', text });
  broadcast({ type: 'transcript', speaker: 'person', text, callSid });
  if (text.toLowerCase().includes(CONSENT_PHRASE)) takeover(st, 'person said the consent phrase');
}

function onPersonDigit(callSid, digit) {
  const st = calls.get(callSid);
  if (st && digit === CONSENT_DIGIT && st.stage !== 'monitor') takeover(st, `person pressed ${digit}`);
}

// ---------- Deepgram streaming STT (one socket per stream) ----------
function openDeepgram(onFinal, onInterim) {
  const params = new URLSearchParams({
    encoding: 'mulaw', sample_rate: '8000', channels: '1',
    language: STT_LANGUAGE, model: 'nova-2', punctuate: 'true', interim_results: 'true',
  });
  const dg = new WebSocket(`wss://api.deepgram.com/v1/listen?${params}`, {
    headers: { Authorization: `Token ${DEEPGRAM_API_KEY}` },
  });
  dg.on('message', (raw) => {
    try {
      const d = JSON.parse(raw.toString());
      const text = d.channel?.alternatives?.[0]?.transcript;
      if (!text) return;
      if (d.is_final) onFinal(text); else onInterim && onInterim(text);
    } catch (_) { /* ignore keepalives */ }
  });
  dg.on('error', () => {});
  return dg;
}

// ---------- WebSocket routing (Twilio media + operator dashboard) ----------
const wssMedia = new WebSocketServer({ noServer: true });
const wssOperator = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const { url } = req;
  if (url.startsWith('/media')) {
    wssMedia.handleUpgrade(req, socket, head, ws => wssMedia.emit('connection', ws, req));
  } else if (url.startsWith('/operator')) {
    // Live call transcripts are private: refuse any operator without the token.
    const token = new URL(url, 'http://localhost').searchParams.get('token');
    if (!tokenOk(token)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      return socket.destroy();
    }
    wssOperator.handleUpgrade(req, socket, head, ws => wssOperator.emit('connection', ws, req));
  } else {
    socket.destroy();
  }
});

wssOperator.on('connection', (ws) => {
  operators.add(ws);
  ws.send(JSON.stringify({ type: 'hello', ts: Date.now() }));
  ws.on('close', () => operators.delete(ws));
});

// One stream per leg: role 'caller' (scam detector) or 'person' (consent phrase, keypress).
wssMedia.on('connection', (twilioWs) => {
  let callSid = null;
  let role = null;
  let dg = null;

  twilioWs.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.event === 'start') {
      const p = msg.start?.customParameters || {};
      callSid = p.callSid;
      role = p.role === 'person' ? 'person' : 'caller';
      broadcast({ type: 'stream_start', callSid, role });
      if (DEEPGRAM_API_KEY) {
        dg = openDeepgram(
          (t) => (role === 'person' ? onPersonSpeech : onCallerSpeech)(callSid, t),
          (t) => broadcast({ type: 'interim', speaker: role, text: t, callSid }),
        );
      }
    } else if (msg.event === 'media') {
      if (dg && dg.readyState === WebSocket.OPEN) dg.send(Buffer.from(msg.media.payload, 'base64'));
    } else if (msg.event === 'dtmf') {
      // Keypress events are not sent on every Twilio setup; the spoken phrase always works.
      if (role === 'person') onPersonDigit(callSid, msg.dtmf?.digit);
    } else if (msg.event === 'stop') {
      if (dg && dg.readyState === WebSocket.OPEN) dg.send(JSON.stringify({ type: 'CloseStream' }));
    }
  });

  twilioWs.on('close', () => {
    if (dg) dg.close();
    if (callSid && role === 'caller') broadcast({ type: 'call_end', callSid });
  });
});

// ---------- Demo endpoints (DEMO_MODE=1 and token required) ----------
// Run the whole flow without a phone line or speech-to-text:
//   /demo/call?token=...                                   → returns a callSid
//   /demo/say/<callSid>?token=...&speaker=caller&text=...  → caller speech
//   /demo/say/<callSid>?token=...&speaker=person&text=...  → person speech (consent phrase)
//   /demo/press/<callSid>?token=...&digit=9                → person keypress
function demoGuard(req, res) {
  if (!DEMO_MODE) { res.status(404).end(); return false; }
  if (!tokenOk(req.query.token)) { res.status(401).json({ ok: false }); return false; }
  return true;
}
app.get('/demo/call', (req, res) => {
  if (!demoGuard(req, res)) return;
  const callSid = 'DEMO' + crypto.randomBytes(6).toString('hex');
  newCall(callSid, req.query.from || '+972500000000');
  broadcast({ type: 'call_start', callSid, from: calls.get(callSid).from });
  res.json({ ok: true, callSid });
});
app.get('/demo/say/:callSid', (req, res) => {
  if (!demoGuard(req, res)) return;
  const st = calls.get(req.params.callSid);
  if (!st) return res.status(404).json({ ok: false });
  (req.query.speaker === 'person' ? onPersonSpeech : onCallerSpeech)(st.callSid, String(req.query.text || ''));
  res.json({ ok: true, stage: st.stage, signs: [...st.firedSet], ttype: st.ttype });
});
app.get('/demo/press/:callSid', (req, res) => {
  if (!demoGuard(req, res)) return;
  const st = calls.get(req.params.callSid);
  if (!st) return res.status(404).json({ ok: false });
  onPersonDigit(st.callSid, String(req.query.digit || ''));
  res.json({ ok: true, stage: st.stage });
});

// ---------- Operator dashboard (served inline) — warm light, HE/RU ----------
app.get('/', (_req, res) => res.type('text/html').send(OPERATOR_HTML));

const OPERATOR_HTML = `<!doctype html><html lang="he"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TAB@Anti-Scam — Operator</title>
<style>
  :root{--paper:#FBF7F1;--card:#fff;--line:#EAE1D5;--ink:#241F1B;--mut:#8F857A;
    --teal:#0F766E;--tealBg:#E7F1EF;--amber:#DB7A34;--rose:#BE5348;--roseBg:#FBEAE7;--green:#3E9E74;--alarm:#D64545}
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,'Segoe UI',sans-serif;background:radial-gradient(900px 500px at 80% -10%,#FDF3E7,var(--paper));color:var(--ink);min-height:100vh}
  header{padding:14px 18px;display:flex;align-items:center;gap:10px}
  .orb{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#DB7A34,#F0A24B)}
  .dot{width:10px;height:10px;border-radius:50%;background:#C9BEB0;margin-inline-start:auto}
  .dot.on{background:var(--green)}
  .wrap{display:grid;grid-template-columns:1fr 300px;gap:16px;padding:0 16px 24px;max-width:1000px;margin:0 auto}
  @media(max-width:760px){.wrap{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:0 10px 40px -26px rgba(80,60,40,.3)}
  .ttype{display:none;align-items:center;gap:7px;padding:8px 13px;border-radius:11px;font-weight:700;font-size:13px;margin-bottom:12px;width:max-content}
  .ttype.phone{display:inline-flex;background:var(--roseBg);color:var(--rose);border:1.5px solid #EEC7C1}
  .ttype.courier{display:inline-flex;background:#FBEEE1;color:var(--amber);border:1.5px solid #F0D3B4}
  .bubble{max-width:86%;padding:10px 14px;border-radius:16px;margin:7px 0;font-size:14px;line-height:1.45}
  .caller{background:#F3EEE7}
  .person{background:var(--teal);color:#fff;margin-inline-start:auto}
  .guardian{background:linear-gradient(90deg,#F4B03C,#F0873A);color:#fff;margin-inline-start:auto;font-weight:600}
  .tag{font-size:10px;text-transform:uppercase;letter-spacing:.04em;opacity:.6;margin-bottom:2px}
  .meter{height:12px;border-radius:999px;background:#EFEAE2;overflow:hidden;margin-top:6px}
  .meter>div{height:100%;width:0;border-radius:999px;background:var(--green);transition:all .6s}
  .sign{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:10px;background:#F7F4EF;margin-bottom:7px;font-size:13.5px;color:var(--mut)}
  .sign.on{background:var(--roseBg);color:var(--rose);font-weight:600}
  .sign .b{width:18px;height:18px;border-radius:50%;background:#E2DACE}
  .sign.on .b{background:var(--alarm)}
  .banner{background:linear-gradient(90deg,#F4B03C,#F0873A);color:#fff;padding:11px 14px;border-radius:12px;font-weight:700;margin-bottom:12px;display:none}
  .banner.show{display:block}
  #feed{height:58vh;min-height:360px;overflow-y:auto;display:flex;flex-direction:column}
  h3{font-size:14px;margin:0 0 10px}
</style></head><body dir="rtl">
<header><span class="orb"></span><b>TAB@Anti-Scam — עמדת מפעיל</b><span class="dot" id="live"></span><span id="from" style="opacity:.6;font-size:13px;margin-inline-start:8px"></span></header>
<div class="wrap">
  <div class="card">
    <div class="ttype" id="ttype"></div>
    <div class="banner" id="banner"></div>
    <div id="feed"></div>
  </div>
  <div class="card">
    <h3>רמת לחץ <span id="prnum" style="float:left;color:var(--green)">0%</span></h3>
    <div class="meter"><div id="prbar"></div></div>
    <h3 style="margin-top:16px">סימני סכנה <span id="count" style="opacity:.5;float:left"></span></h3>
    <div id="signs"></div>
  </div>
</div>
<script>
  var LABELS=['דחיפות ולחץ','בקשה להעביר כסף','בקשה לקוד או מספר כרטיס','בקשה לא לספר לאף אחד','התחזות לבנק או לרשויות'];
  var TT={phone:'מסלול טלפוני · חילוץ מספרי כרטיס וקודים',courier:'שליח פיזי · איסוף מזומן או צ׳ק'};
  var signsEl=document.getElementById('signs'),fired=new Set();
  LABELS.forEach(function(l,i){var d=document.createElement('div');d.className='sign';d.id='sign'+i;d.innerHTML='<span class="b"></span>'+l;signsEl.appendChild(d);});
  var feed=document.getElementById('feed');
  function add(cls,tag,text){var b=document.createElement('div');b.className='bubble '+cls;var t=document.createElement('div');t.className='tag';t.textContent=tag;b.appendChild(t);b.appendChild(document.createTextNode(text||''));feed.appendChild(b);feed.scrollTop=feed.scrollHeight;}
  function renderSigns(){document.getElementById('count').textContent=fired.size+' / 5';LABELS.forEach(function(_,i){document.getElementById('sign'+i).classList.toggle('on',fired.has(i));});}
  function setPressure(p){document.getElementById('prbar').style.width=p+'%';var el=document.getElementById('prnum');el.textContent=p+'%';var c=p>=75?'var(--alarm)':p>=40?'#E8853A':'var(--green)';el.style.color=c;document.getElementById('prbar').style.background=c;}
  function setType(tt){var el=document.getElementById('ttype');el.className='ttype '+tt;el.textContent=TT[tt]||'';}
  var proto=location.protocol==='https:'?'wss':'ws';
  var tok=new URLSearchParams(location.search).get('token')||'';
  if(!tok){add('caller','מערכת','חסר טוקן מפעיל. פתחו את הכתובת עם ?token=... כפי שמודפס בטרמינל של השרת.');}
  var ws=new WebSocket(proto+'://'+location.host+'/operator?token='+encodeURIComponent(tok));
  ws.onopen=function(){document.getElementById('live').classList.add('on');};
  ws.onclose=function(){document.getElementById('live').classList.remove('on');};
  ws.onmessage=function(e){var m=JSON.parse(e.data);
    if(m.type==='call_start'){feed.innerHTML='';fired.clear();renderSigns();setPressure(0);document.getElementById('ttype').className='ttype';document.getElementById('banner').classList.remove('show');document.getElementById('from').textContent='מאת: '+(m.from||'');}
    if(m.type==='ttype'){setType(m.ttype);}
    if(m.type==='transcript'){add(m.speaker,m.speaker==='caller'?'נוכל':'האדם',m.text);}
    if(m.type==='signs'){m.signs.forEach(function(s){fired.add(s);});renderSigns();}
    if(m.type==='pressure'){setPressure(m.level||0);}
    if(m.type==='threat'){if(m.ttype)setType(m.ttype);var bn=document.getElementById('banner');bn.textContent='⚠ סכנה אפשרית — '+(m.reason||'');bn.classList.add('show');}
    if(m.type==='takeover'||m.type==='takeover_sim'){add('guardian',m.persona||'TAB',m.line);}
    if(m.type==='whisper'){add('guardian','TAB \u2190 '+'לאוזני האדם בלבד',m.line);}
    if(m.type==='notify'){add('caller','הודעה למשפחה'+(m.simulated?' (סימולציה)':''),m.body);}
    if(m.type==='stage'){var bn=document.getElementById('banner');var ST={warn:'\u26a0 שלב 1 · האדם הוזהר, המשפחה קיבלה הודעה',offer:'\u26a0 שלב 2 · הוצע לאדם להעביר את השיחה ל-TAB',takeover:'\u2714 שלב 3 · האדם הסכים, TAB בשיחה'};if(ST[m.stage]){bn.textContent=ST[m.stage];bn.classList.add('show');}if(m.ttype)setType(m.ttype);}
  };
</script></body></html>`;

server.listen(PORT, () => {
  console.log(`TAB@Anti-Scam guardian on :${PORT}`);
  console.log(`Operator view (inline): ${BASE}/?token=${OPERATOR_TOKEN}`);
  console.log(`Operator view (v2 external): wss://${PUBLIC_HOST}/operator?token=${OPERATOR_TOKEN}`);
  console.log(`Twilio Voice webhook → ${BASE}/voice`);
  if (!process.env.OPERATOR_TOKEN) console.log('ℹ OPERATOR_TOKEN not set — generated one for this run (shown above).');
  if (DEMO_MODE) console.log('⚠ DEMO_MODE on — /demo endpoints are enabled (token required).');
  if (!DEEPGRAM_API_KEY) console.log('⚠ No DEEPGRAM_API_KEY — speech-to-text disabled (use the /demo endpoints).');
  if (!twClient) console.log('⚠ No Twilio creds — whispers, WhatsApp and takeover are simulated only.');
  if (twClient && (!WHATSAPP_FROM || !FAMILY_WHATSAPP.length)) console.log('⚠ WhatsApp not configured — family messages are shown on the operator screen only.');
});

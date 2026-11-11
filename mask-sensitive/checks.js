"use strict";
// What a rule's value is, beyond matching its pattern: checksums, shapes, and
// what the words around it say. Ported from magpie's internal/redact
// (redact.go, more.go, phone.go, fieldvalue.go, ids.go), where each of these
// exists to keep a false positive out of a prompt. The comments here say which
// false positive, because that is the whole reason the check is here and it is
// not visible from the code.

const text = require("./text");

const { DIGITS, charAt, containsAny, isDigit, isLetter, isLower, isUpper, isWordByte, slice, trim, trimLeft, trimRight } = text;

// notAVariable turns away what stands in for a value: ${PASS}, <password>,
// ****. Nothing to mask, and masking it would break the placeholder a config
// interpolates.
function notAVariable(v) {
  if (v === "") {
    return false;
  }
  if ("$%{<[*".indexOf(v[0]) >= 0) {
    return false;
  }
  return trim(v, "*xX.") !== "";
}

// One letter and one digit both, or 16 characters or more. A value that is one
// word only is a name: `token 是 expired`, `key 是 value`.
function keyValue(v) {
  if (!notAVariable(v)) {
    return false;
  }
  const letter = containsAny(v, []) || /[A-Za-z]/.test(v);
  return letter && (/[0-9]/.test(v) || v.length >= 16);
}

// A secret's value: letters and digits both, and not a read from the
// environment or a call. `process.env.API_KEY` and `os.environ[...]` name where
// the secret is, they are not it.
function secretValue(v) {
  if (!notAVariable(v) || v.startsWith("process.env") || v.startsWith("os.")) {
    return false;
  }
  return /[0-9]/.test(v) && /[A-Za-z]/.test(v);
}

// A name in code, read through others or not: Uint8Array, details.2,
// opts.token2.
const IDENT_PATH = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$/;

// notCode turns away a value that is code naming a secret rather than the
// secret: a call (privateKey: toBase64Url(...), secretKey = fromBase64Url(...)),
// or, unquoted after a colon, a type or a read that code goes on from
// (secretKey: Uint8Array;, private_key: details.2,). A secret written in code is
// a string, so in quotes; one after = or at a line's end (.env files, logs,
// YAML) is kept.
function notCode(s, a, b) {
  const v = slice(s, a, b);
  if (!IDENT_PATH.test(v)) {
    return true;
  }
  const rest = trimLeft(s.slice(b), " \t");
  if (rest.startsWith("(")) {
    return false;
  }
  const quoted = a > 0 && (s[a - 1] === '"' || s[a - 1] === "'");
  if (quoted || !trimRight(s.slice(0, a), " \t").endsWith(":")) {
    return true;
  }
  return rest === "" || ";,)}]|?&<>".indexOf(rest[0]) < 0;
}

// inUserinfo says s[a] is inside a URL's authority, after its scheme:// and
// before the host: nothing from there back to the // is a /, ?, #, space,
// quote, < or > or @.
function inUserinfo(s, a) {
  let i = a;
  while (i > 0 && " \t\r\n/?#\"'<>@`".indexOf(s[i - 1]) < 0) {
    i--;
  }
  if (i < 3 || s[i - 1] !== "/" || s[i - 2] !== "/" || s[i - 3] !== ":") {
    return false;
  }
  const j = i - 3;
  let k = j;
  while (k > 0 && (isLetter(s[k - 1]) || isDigit(s[k - 1]) || "+.-".indexOf(s[k - 1]) >= 0)) {
    k--;
  }
  while (k < j && !isLetter(s[k])) {
    k++; // a scheme starts with a letter
  }
  return k < j;
}

// An email cannot be inside a URL's userinfo: postgres://app:hunter2pass@host
// is a password and a host, not one address. In a URL's path or query
// (?to=bob@acme.cn) and in mailto: it is an email still.
function emailAt(s, a, b) {
  if (a > 0 && s[a - 1] === ".") {
    return false;
  }
  if (b + 1 < s.length && s[b] === "." && text.TOKEN_CH.indexOf(s[b + 1]) >= 0) {
    return false;
  }
  return !inUserinfo(s, a);
}

// Hidden in its URL: a test database's URL often gives one word for the user,
// the password and the database
// (postgresql://geodatafusion:geodatafusion@127.0.0.1/geodatafusion). Masking
// that password made the word known, and the project's own folders and crate
// went to the vendor as a placeholder for the rest of the run. A password
// written again in the same URL is not masked.
function hiddenInURL(s, a, b) {
  const pw = slice(s, a, b);
  const i = s.slice(0, a).lastIndexOf("//");
  if (i < 0 || s[a - 1] !== ":") {
    return true;
  }
  if (s.slice(i + 2, a - 1) === pw) {
    return false; // the user name
  }
  let end = b + 1;
  while (end < s.length && " \t\r\n\"'<>`\\)]}".indexOf(s[end]) < 0) {
    end++;
  }
  if (b + 1 > end) {
    return true;
  }
  for (const part of s.slice(b + 1, end).split(/[/:.?#&=;,@]/)) {
    if (part === pw) {
      return false;
    }
  }
  return true;
}

// notASlug keeps a page's address out: a word in lower case joined by hyphens
// (…/sk-hynix-third-quarter-profit.html) read as a key. A key's characters are
// random: it has a capital, or a run of 16 or more with no hyphen, or hex
// digits alone as a UUID's groups are.
function notASlug(v) {
  if (/[A-Z]/.test(v)) {
    return true;
  }
  const tail = v.startsWith("sk-") ? v.slice(3) : v;
  if (!/[^\-_0-9a-f]/.test(tail)) {
    return true;
  }
  for (const w of v.split(/[-_]/)) {
    if (w.length >= 16) {
      return true;
    }
  }
  return false;
}

// The rest of an Authorization or Cookie line is a header's value, not prose
// that begins with the word ("Authorization: the user must sign in first"): a
// credential after a scheme word or alone, or a cookie's name=value pairs.
function headerValue(raw) {
  const v = trim(raw, " \t");
  if (v === "" || !notAVariable(v)) {
    return false;
  }
  const notLetter = (c) => !isLetter(c);
  const fields = v.split(/[ \t]+/).filter((f) => f !== "");
  if (fields.length === 1 || (fields.length === 2 && ![...fields[0]].some(notLetter))) {
    const cred = fields[fields.length - 1];
    return cred.length >= 8 && notAVariable(cred) && [...cred].some(notLetter);
  }
  for (const kv of v.split(";")) {
    const part = trim(kv, " \t");
    if (part === "") {
      continue;
    }
    const eq = part.indexOf("=");
    const name = eq < 0 ? part : part.slice(0, eq);
    if (eq < 0 || name === "" || /[ \t]/.test(name)) {
      return false;
    }
  }
  return v.indexOf("=") >= 0;
}

// An upper-case name that only ends in _KEY or _PASS holds no secret: a sort
// key, a cache key, a public key.
const PLAIN_KEYS = ["sort_key", "cache_key", "prompt_cache_key", "public_key"];
function notAPlainKey(s, a) {
  let i = a;
  while (i > 0 && "\"' \t:=".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  const end = i;
  while (i > 0 && (text.ALNUM + "_.-").indexOf(s[i - 1]) >= 0) {
    i--;
  }
  const name = s.slice(i, end).toLowerCase();
  return !PLAIN_KEYS.some((k) => name.endsWith(k));
}

function notPlainKeyOrCode(s, a, b) {
  return notAPlainKey(s, a) && notCode(s, a, b);
}

// File extensions that are no top-level domain: a Mac screenshot saved at twice
// its size (261020_14-16-11@2x.jpg) went to the model as {{EMAIL_…}} and the
// agent could no longer read the file.
const FILE_EXT = new Set([
  "jpg", "jpeg", "png", "gif", "webp", "svg", "heic", "heif", "avif", "bmp", "tif", "tiff", "ico", "icns",
  "pdf", "svgz", "apng", "jxl", "psd", "eps", "lottie",
  "mp4", "m4v", "webm", "mkv", "avi", "mp3", "m4a", "wav", "ogg", "flac", "aac",
  "ttf", "otf", "woff", "woff2", "eot",
  "json", "yaml", "yml", "toml", "xml", "txt", "csv", "tsv", "log", "html", "htm", "css", "scss", "less",
  "js", "mjs", "cjs", "jsx", "ts", "tsx", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "gz", "tgz", "tar", "rar", "7z", "dmg",
]);
// Extensions that are domains too (.zip, .mov, .md, .map): a name ending in one
// is a file's only with a scale before it, icon@2x.zip, while ops@files.zip is
// an address.
const SCALE_EXT = new Set(["zip", "mov", "md", "map"]);
const SCALE_RE = /^[0-9]+(?:\.[0-9]+)?x$/;

function fileHost(host) {
  const dot = host.lastIndexOf(".");
  const ext = host.slice(dot + 1);
  return FILE_EXT.has(ext) || (dot > 0 && SCALE_EXT.has(ext) && SCALE_RE.test(host.slice(0, dot)));
}

// Names a binary's tables are reached through (system@plt, puts@got.plt), never
// a domain's labels: a disassembly's symbols read as addresses.
const LINKER_WORDS = new Set(["plt", "got", "sec", "iplt", "igot"]);
// The files agents read by name, on a domain's ending: "@AGENTS.md" after a
// word is no address.
const DOC_FILES = new Set([
  "agents.md", "claude.md", "gemini.md", "readme.md", "skill.md", "changelog.md",
  "contributing.md", "license.md", "lessons.md", "todo.md", "copilot-instructions.md",
  "crush.md", "qwen.md", "iflow.md", "warp.md",
]);
// Names an organisation's own mail can end in that no registry has.
const LOCAL_TLDS = new Set(["local", "internal", "lan", "corp", "home", "intranet", "localdomain"]);
// Common two-letter country codes plus the generic TLDs a real address ends in.
// Magpie resolves this against the public suffix list; the plugin carries the
// list it needs instead, because a plugin cannot reach the network. A domain
// ending in a country or generic TLD is an address; one ending in a file
// extension, a binary's table or a word no registry has is not.
const TLDS = new Set([
  "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "mobi", "asia",
  "aero", "coop", "museum", "jobs", "travel", "tel", "cat", "post", "xxx",
  "io", "ai", "dev", "app", "sh", "co", "me", "tv", "cc", "ly", "to", "gg", "fm", "so", "rs", "is",
  "ac", "ad", "ae", "af", "ag", "al", "am", "ao", "aq", "ar", "at", "au", "aw", "ax", "az",
  "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "by", "bz",
  "ca", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "cr", "cu", "cv", "cw", "cx", "cy", "cz",
  "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fo", "fr",
  "ga", "gb", "gd", "ge", "gf", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gt", "gu", "gw", "gy",
  "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "iq", "ir", "it", "je", "jm", "jo", "jp",
  "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
  "ma", "mc", "md", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
  "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
  "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "ru", "rw",
  "sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "sr", "ss", "st", "sv", "sx", "sy", "sz",
  "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tw", "tz",
  "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
  "top", "site", "online", "store", "tech", "xyz", "cloud", "space", "website", "live", "life", "world",
  "agency", "digital", "studio", "design", "email", "link", "click", "page", "blog", "wiki", "zone",
  "moe", "ong", "art", "bar", "cafe", "club", "codes", "dev", "education", "finance", "global", "group",
  "health", "host", "industries", "institute", "land", "legal", "media", "network", "news", "now",
  "one", "plus", "press", "pro", "pub", "report", "review", "run", "school", "science", "services",
  "shop", "social", "software", "solutions", "studio", "support", "systems", "team", "tools", "trade",
  "training", "uno", "vet", "video", "vision", "works", "wow",
]);

// mailHost: after a local part and an @, the host has a dot, labels of letters,
// digits and hyphens, and is not a linker's table.
function mailHost(local, host) {
  if (local.endsWith("@") || host.indexOf(".") < 0 || trim(host, ".") !== host) {
    return false;
  }
  let linker = true;
  for (const label of host.split(".")) {
    if (label === "" || /[^a-z0-9-]/.test(label)) {
      return false;
    }
    if (!LINKER_WORDS.has(label)) {
      linker = false;
    }
  }
  return !linker;
}

function realEmail(v) {
  const at = v.lastIndexOf("@");
  if (v.slice(0, at).toLowerCase() === "git") {
    return false;
  }
  const host = v.slice(at + 1).toLowerCase();
  if (!mailHost(v.slice(0, at), host)) {
    return false;
  }
  const tld = host.slice(host.lastIndexOf(".") + 1);
  if (fileHost(host) || DOC_FILES.has(host) || !(LOCAL_TLDS.has(tld) || TLDS.has(tld))) {
    return false;
  }
  for (const fake of ["example.com", "example.org", "example.net", "localhost", ".test", ".invalid", ".example"]) {
    if (host === trimLeft(fake, ".") || host.endsWith(fake)) {
      return false;
    }
  }
  return !host.startsWith("noreply") && v.indexOf("noreply@") < 0;
}

// The Chinese resident ID card's check character: weights over the first
// seventeen digits, and the check character at the sum's place.
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
function chineseID(v) {
  if (v.length !== 18 || !/^[0-9]{17}[0-9Xx]$/.test(v)) {
    return false;
  }
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    sum += (v.charCodeAt(i) - 48) * ID_WEIGHTS[i];
  }
  return v[17].toUpperCase() === "10X98765432"[sum % 11];
}

// Luhn over 15 to 19 digits. An order number one digit away from a card number
// stays as written.
function luhn(v) {
  const ds = [];
  for (const c of v) {
    if (isDigit(c)) {
      ds.push(c.charCodeAt(0) - 48);
    }
  }
  if (ds.length < 15 || ds.length > 19) {
    return false;
  }
  let sum = 0;
  for (let i = 0; i < ds.length; i++) {
    let d = ds[ds.length - 1 - i];
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const SSN_EXAMPLES = new Set(["123456789", "078051120", "219099999"]);
function ssnOK(v) {
  const d = v.replace(/[- ]/g, "");
  if (d.length !== 9 || d.slice(0, 3) === "000" || d.slice(0, 3) === "666" || d[0] === "9" || d.slice(3, 5) === "00" || d.slice(5) === "0000") {
    return false;
  }
  if (SSN_EXAMPLES.has(d)) {
    return false;
  }
  return trim(d, d[0]) !== "";
}

function passportOK(v) {
  let n = 0;
  for (const c of v) {
    if (isDigit(c)) {
      n++;
    }
  }
  return n >= 5 && trim(v, v[0]) !== "";
}

// Each country's IBAN length. An IBAN's country and length are half its
// checksum: mod 97 of it, first four characters moved to the end, is 1.
const IBAN_LEN = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BI: 27, BR: 29, BY: 28,
  CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18,
  FK: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28,
  IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20,
  LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MN: 20, MR: 27, MT: 31, MU: 30, NI: 28,
  NL: 18, NO: 15, OM: 23, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, RU: 33, SA: 24,
  SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26,
  UA: 29, VA: 22, VG: 24, XK: 20, YE: 30,
};
function ibanOK(raw) {
  const v = raw.replace(/ /g, "");
  if (v.length < 15) {
    return false;
  }
  const want = IBAN_LEN[v.slice(0, 2)];
  if (want === undefined || want !== v.length) {
    return false;
  }
  const r = v.slice(4) + v.slice(0, 4);
  let m = 0;
  for (const c of r) {
    if (isDigit(c)) {
      m = (m * 10 + (c.charCodeAt(0) - 48)) % 97;
    } else if (c >= "A" && c <= "Z") {
      m = (m * 100 + (c.charCodeAt(0) - 65) + 10) % 97;
    } else {
      return false;
    }
  }
  return m === 1;
}

// An IBAN printed in groups of four followed by a word in capitals takes that
// word as its last group: BE68 5390 0754 7034 THEN. Each space is given back
// until the checksum passes.
function ibanAt(s, a, b) {
  for (;;) {
    if (ibanOK(slice(s, a, b))) {
      return { start: a, end: b };
    }
    const i = s.slice(a, b).lastIndexOf(" ");
    if (i < 0) {
      return null;
    }
    b = a + i;
  }
}

const MONTH_NAMES = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

// A date that can be someone's birthday: a real month and day, in a year from
// 1900 on, and over a year ago. A date in the last year or ahead is the day an
// agent runs on, a deadline or a log's, which a prompt holds far more often
// than a baby's birthday.
function dateOK(v, now) {
  const ns = v.match(/\d+/g) || [];
  const num = (x) => parseInt(x, 10);
  const yearAgo = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate()).getTime();
  const valid = (y, m, d) => {
    if (!(y >= 1900 && y <= 2099 && m >= 1 && m <= 12 && d >= 1 && d <= 31)) {
      return false;
    }
    const at = new Date(y, m - 1, d).getTime();
    return at < yearAgo;
  };
  if (ns.length === 2) {
    const l = v.toLowerCase();
    for (let i = 0; i < MONTH_NAMES.length; i++) {
      if (l.indexOf(MONTH_NAMES[i]) >= 0) {
        let d = num(ns[0]);
        let y = num(ns[1]);
        if (ns[0].length === 4) {
          d = y;
          y = num(ns[0]);
        }
        return valid(y, i + 1, d);
      }
    }
    return false;
  }
  if (ns.length !== 3) {
    return false;
  }
  if (ns[0].length === 4) {
    return valid(num(ns[0]), num(ns[1]), num(ns[2]));
  }
  const p = num(ns[0]);
  const q = num(ns[1]);
  const y = num(ns[2]);
  return valid(y, p, q) || valid(y, q, p);
}

// What stands for an address in docs and code, the broadcast one, and twelve
// decimal digits, which a MAC address almost never is and a date or a count in
// pairs may be.
const MAC_EXAMPLES = new Set([
  "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55",
  "aa:bb:cc:dd:ee:ff", "01:23:45:67:89:ab", "12:34:56:78:9a:bc", "xx:xx:xx:xx:xx:xx",
]);
function macOK(v) {
  const l = v.replace(/-/g, ":").toLowerCase();
  if (MAC_EXAMPLES.has(l)) {
    return false;
  }
  return containsAny(l, ["a", "b", "c", "d", "e", "f"]);
}

function serialOK(v) {
  return v.length >= 6 && /[0-9]/.test(v) && trim(v, v[0]) !== "";
}

// What a doc or a container writes for a user's name, and the folders under
// /Users that are no one's.
const NOT_NAMES = new Set([
  "shared", "public", "guest", "default", "default user", "all users",
  "user", "username", "user_name", "yourname", "your-name", "your_name", "yourusername",
  "you", "me", "name", "example", "foo", "bar", "someone", "john", "jdoe",
  "runner", "node", "vscode", "codespace", "linuxbrew", "...",
]);
// The users of a service or a cloud image, which say nothing of who the user
// is, and the words a "User:" line in a chat has.
const NOT_USERS = new Set([
  "git", "root", "ec2-user", "ubuntu", "admin", "postgres", "www-data", "nobody",
  "centos", "debian", "fedora", "azureuser", "opc", "core", "vagrant", "docker",
  "str", "string", "int", "bool", "any", "none", "null", "nil", "true", "false",
  "undefined", "hi", "hello", "hey", "yes", "no", "ok", "okay", "thanks",
  "continue", "go", "stop", "help", "test", "y", "n",
]);

// The user name in a home folder, without the full stop of a sentence after it.
function homeAt(s, a, b) {
  while (b > a && s[b - 1] === ".") {
    b--;
  }
  if (b === a || s[a] === "." || NOT_NAMES.has(slice(s, a, b).toLowerCase())) {
    return null;
  }
  return { start: a, end: b };
}

// What a value in code is read from: user = request.user,
// hostname = socket.gethostname.
const CODE_OBJECTS = new Set([
  "self", "this", "os", "process", "request", "req", "ctx", "context",
  "config", "cfg", "conf", "settings", "env", "args", "opts", "options",
  "props", "params", "session", "socket", "platform", "window", "location", "url",
  "u", "r", "c", "s", "m", "p", "x", "data", "info", "user",
]);
const PUBLIC_HOSTS = new Set([
  "github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com", "vs-ssh.visualstudio.com",
  "localhost", "host", "hostname", "server", "remote", "example", "your-server",
  "str", "string", "none", "null", "true", "false", "undefined",
]);

function inCode(v) {
  const lower = v.toLowerCase();
  const dot = lower.indexOf(".");
  if (dot < 0) {
    return false;
  }
  const first = lower.slice(0, dot);
  const last = lower.slice(lower.lastIndexOf(".") + 1);
  return CODE_OBJECTS.has(first) || NOT_USERS.has(last) || NOT_NAMES.has(last) || PUBLIC_HOSTS.has(last) || last === "login" || last === "username";
}

const CHAT_WORDS = new Set([
  "done", "why", "what", "how", "sure", "please", "retry", "next", "again",
  "great", "good", "nice", "cool", "fix", "go-ahead", "proceed", "lgtm",
  "required", "optional", "unknown", "anonymous", "guest", "current", "me",
]);
// The words of a variable's or a type's name that holds a user, and never a
// login of its own: user = current_user, user: UserInfo, login = loginName.
const IDENT_PARTS = new Set([
  "user", "users", "usr", "username", "name", "names", "login", "logname",
  "account", "acct", "owner", "author", "member", "person", "profile",
  "current", "cur", "default", "target", "new", "old", "my", "the",
  "obj", "object", "info", "id", "model", "data", "record", "entity",
  "row", "item", "input", "arg", "args", "param", "value", "val",
  "str", "type", "dto", "db", "auth", "session", "self",
]);
const DECL_WORDS = ["const", "let", "var", "val", "def", "func", "fn", "function", "class", "struct", "interface", "enum", "return", "import", "typeof"];
const PARAM_REST = /^(?:[,):]|[*[\]]*[A-Za-z_][\w.*[\]]*[ \t]*[,)])/;

// identWords are v's words: split at _ and ., and where a capital starts a word
// in camelCase (refreshToken2 is refresh and Token2).
function identWords(v) {
  const out = [];
  for (const part of v.split(/[_.]/)) {
    let start = 0;
    for (let i = 1; i < part.length; i++) {
      if (isUpper(part[i]) && isLower(part[i - 1])) {
        out.push(part.slice(start, i));
        start = i;
      }
    }
    out.push(part.slice(start));
  }
  return out;
}

function userOK(v) {
  const l = v.toLowerCase();
  return v.length >= 2 && !NOT_USERS.has(l) && !NOT_NAMES.has(l);
}

// The value on a "User:" line is written out, not a variable's or a type's name
// in code. Unquoted, a value made of words one of which is a name part is
// code's: an assignment, a type annotation, a struct's field. A quoted value is
// a string, written out, whatever its words; and a login of words of its own
// (deploy_bot, john_doe) is masked still.
function notLineIdent(s, a, b) {
  if (a > 0 && (s[a - 1] === '"' || s[a - 1] === "'")) {
    return true;
  }
  const words = identWords(slice(s, a, b));
  if (words.length < 2) {
    return true;
  }
  return !words.some((w) => IDENT_PARTS.has(w.toLowerCase()));
}

function lineUserOK(v) {
  return userOK(v) && !inCode(v) && !CHAT_WORDS.has(v.toLowerCase()) && !IDENT_PARTS.has(v.toLowerCase());
}

function hostOK(v) {
  const l = trimRight(v, ".").toLowerCase();
  if (l.length < 2 || PUBLIC_HOSTS.has(l) || l.startsWith("process.") || l.startsWith("os.") || l.startsWith("env.")) {
    return false;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(l)) {
    return false; // an address is the IP category's
  }
  for (const ex of ["example.com", "example.org", "example.net", ".example", ".test", ".invalid", ".localhost"]) {
    if (l === trimLeft(ex, ".") || l.endsWith(ex)) {
      return false;
    }
  }
  return true;
}

function lineHostOK(v) {
  return hostOK(v) && !inCode(v);
}

// A package pinned at its version reads as a shell prompt's user@host in a lock
// file: js-tokens@4.0.0: on a line of its own. No host's name is numbers and
// dots alone.
const VERSION_HOST_RE = /^v?\d+(?:\.\d+)+(?:-[0-9A-Za-z.-]+)?$/;
function versionHost(h) {
  if (!VERSION_HOST_RE.test(h)) {
    return false;
  }
  return !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h);
}
function notPackagePin(s, a, b) {
  if (b < s.length && s[b] === "@") {
    let e = b + 1;
    while (e < s.length && (text.ALNUM + "-.").indexOf(s[e]) >= 0) {
      e++;
    }
    return !versionHost(trimRight(s.slice(b + 1, e), "."));
  }
  return !(a > 0 && s[a - 1] === "@" && versionHost(slice(s, a, b)));
}

// Address ranges that are no one's in particular: private, shared (CGNAT),
// documentation, benchmarking, reserved.
const NOT_IP_RANGES = [
  ["0.0.0.0", 8], ["100.64.0.0", 10], ["192.0.0.0", 24], ["192.0.2.0", 24], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["240.0.0.0", 4],
];
// Public DNS resolvers everyone uses, which say nothing of the user.
const RESOLVERS = new Set([
  "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220", "114.114.114.114", "223.5.5.5", "223.6.6.6",
  "119.29.29.29", "180.76.76.76",
]);

function ipv4Parts(s) {
  const parts = s.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const nums = [];
  for (const p of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(p)) {
      return null;
    }
    const n = parseInt(p, 10);
    if (n > 255) {
      return null;
    }
    nums.push(n);
  }
  return nums;
}

function privateIPv4(nums) {
  const [a, b] = nums;
  if (a === 0 || a === 10 || a === 127) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a >= 224) {
    return true;
  }
  return false;
}

function inNotRange(nums) {
  for (const [base, bits] of NOT_IP_RANGES) {
    const bn = ipv4Parts(base);
    let shift = 32 - bits;
    const mask = shift === 32 ? 0 : (~0 >>> shift) << shift;
    const addr = ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
    const baddr = ((bn[0] << 24) | (bn[1] << 16) | (bn[2] << 8) | bn[3]) >>> 0;
    if ((addr & mask) >>> 0 === (baddr & mask) >>> 0) {
      return true;
    }
  }
  return false;
}

function publicIPv4(v) {
  const nums = ipv4Parts(v);
  if (nums === null || privateIPv4(nums) || RESOLVERS.has(v) || inNotRange(nums)) {
    return false;
  }
  return true;
}

// Only global unicast, 2000::/3, and not a documentation or transition prefix.
function publicIPv6(v) {
  const lower = v.toLowerCase();
  if ((lower.match(/:/g) || []).length < 2 || RESOLVERS.has(lower)) {
    return false;
  }
  const head = lower.split(":")[0];
  if (!/^[0-9a-f]{1,4}$/.test(head)) {
    return false;
  }
  const first = parseInt(head, 16);
  if ((first & 0xe000) !== 0x2000) {
    return false;
  }
  if (lower.startsWith("2001:db8") || lower.startsWith("2001:0db8") || lower.startsWith("64:ff9b") || lower.startsWith("100::")) {
    return false;
  }
  return true;
}

// A dotted quad is a public address, not a piece of a longer one or of a
// version: 1.2.3.4.5, v1.2.3.4, ==1.2.3.4, Chrome/120.0.6099.109, version
// 2.31.0.1.
const VERSION_WORDS = ["version", "ver", "release", "build", "rev", "版本"];
function ipv4At(s, a, b) {
  if (a > 0) {
    const c = s[a - 1];
    if ((text.ALNUM + "._-=~^").indexOf(c) >= 0) {
      return false;
    }
    if (c === "/" && a >= 2 && (text.ALNUM + "._-").indexOf(s[a - 2]) >= 0) {
      return false;
    }
  }
  if (b < s.length) {
    const c = s[b];
    if ((text.ALNUM + "_-").indexOf(c) >= 0 || (c === "." && b + 1 < s.length && isDigit(s[b + 1]))) {
      return false;
    }
  }
  const before = trimRight(s.slice(Math.max(0, a - 16), a), " \t:=\"'").toLowerCase();
  for (const w of VERSION_WORDS) {
    if (!before.endsWith(w)) {
      continue;
    }
    if (before.length === w.length || (text.ALNUM + "_").indexOf(before[before.length - w.length - 1]) < 0) {
      return false;
    }
  }
  return publicIPv4(slice(s, a, b));
}

function ipv6OK(v) {
  return publicIPv6(v);
}

// The buckets docs and examples name, and the first folder of an API's path on
// the same host, which is no bucket.
const NOT_BUCKETS = new Set([
  "bucket", "my-bucket", "mybucket", "bucket-name", "bucketname", "my-bucket-name",
  "your-bucket", "your-bucket-name", "yourbucket", "example-bucket", "examplebucket",
  "amzn-s3-demo-bucket", "doc-example-bucket", "s3", "www", "storage", "container",
  "mycontainer", "my-container", "mystorageaccount", "account",
  "upload", "download", "batch", "b", "v1", "v2", "api",
]);
function bucketOK(v) {
  const l = v.toLowerCase();
  return l.length >= 3 && !NOT_BUCKETS.has(l) && trim(l, DIGITS) !== "";
}

// A short digest after a key's name in a sentence (密钥为 5d41402abc4b2a76) is
// that key; in a field it is a long id.
function digestShaped(v) {
  if (v.length < 16 || v.length >= 32) {
    return false;
  }
  let lower = 0;
  let upper = 0;
  let digits = 0;
  for (const c of v) {
    if (isDigit(c)) {
      digits++;
    } else if (c >= "a" && c <= "f") {
      lower++;
    } else if (c >= "A" && c <= "F") {
      upper++;
    } else {
      return false;
    }
  }
  // A hash's digits are random: of 16, about 6 are letters and 10 digits. Two
  // letters among digits are an IBAN's or a code's, not a hash's.
  const letters = lower + upper;
  const floor = Math.max(3, Math.floor(v.length / 8));
  return (lower === 0 || upper === 0) && letters >= floor && digits >= floor;
}

function uuidShaped(v) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

// A UUID or 32 hex digits or more without a hyphen, or a shorter digest.
function idShaped(v) {
  return uuidShaped(v) || (v.length >= 32 && v.indexOf("-") < 0) || digestShaped(v);
}

// An element token cua-driver made for computer use: s and the snapshot's
// counter in 8 hex digits, a colon and the element's index (s0000002a:14). The
// model clicks by it, and a masked one is a click on nothing.
function elementToken(s, a, b) {
  if (b - a < 9 || s[a] !== "s" || (a > 0 && isWordByte(s[a - 1]))) {
    return false;
  }
  const head = slice(s, a + 1, a + 9);
  if (!/^[0-9a-f]{8}$/.test(head)) {
    return false;
  }
  let end = a + 9;
  if (end < s.length && s[end] === ":") {
    let i = end + 1;
    while (i < s.length && isDigit(s[i])) {
      i++;
    }
    if (i === end + 1) {
      return false;
    }
    end = i;
  }
  return !(end < s.length && (isWordByte(s[end]) || s[end] === ":"));
}

// The run of hex digits and hyphens around s[a:b], when that run is an id.
function idAround(s, a, b) {
  if (elementToken(s, a, b)) {
    return { start: a, end: b };
  }
  let l = a;
  let r = b;
  while (l > 0 && text.hexOrHyphen(s[l - 1])) {
    l--;
  }
  while (r < s.length && text.hexOrHyphen(s[r])) {
    r++;
  }
  while (l < r && s[l] === "-") {
    l++;
  }
  while (r > l && s[r - 1] === "-") {
    r--;
  }
  if (a < l || b > r) {
    return null;
  }
  const run = s.slice(l, r);
  for (const c of run) {
    if (!text.hexOrHyphen(c)) {
      return null;
    }
  }
  if (!idShaped(run)) {
    return null;
  }
  // A short digest is a word of its own, not the hex end of a longer one (a
  // key's sk_…deadbeef…).
  if (digestShaped(run) && ((l > 0 && isWordByte(s[l - 1])) || (r < s.length && isWordByte(s[r])))) {
    return null;
  }
  return { start: l, end: r };
}

// nameWords are a field's name's words in lower case: next_page_token,
// nextPageToken and X-Next-Page-Token are next, page, token.
function nameWords(name) {
  const out = [];
  let w = "";
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === "_" || c === "-" || c === ".") {
      if (w !== "") {
        out.push(w);
        w = "";
      }
    } else if (isUpper(c)) {
      if (i > 0 && isLower(name[i - 1]) && w !== "") {
        out.push(w);
        w = "";
      }
      w += c.toLowerCase();
    } else {
      w += c;
    }
  }
  if (w !== "") {
    out.push(w);
  }
  return out;
}

// The words of the name of the field whose value starts at s[at], none where no
// field's name is before it.
function fieldWords(s, at) {
  let i = at;
  while (i > 0 && " \t\"'\\".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  if (i === 0 || (s[i - 1] !== ":" && s[i - 1] !== "=")) {
    return [];
  }
  i--;
  while (i > 0 && " \t\"'\\".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  let j = i;
  while (j > 0 && (text.ALNUM + "_.-").indexOf(s[j - 1]) >= 0) {
    j--;
  }
  return nameWords(s.slice(j, i));
}

// A key for finding data, not for getting in: cache_key, cacheKey,
// object_key, dedupe_key. And never a field named for an id, a cursor, a
// request, a digest or a bare "key".
const NOT_CREDENTIAL_WORDS = new Set([
  "id", "ids", "uuid", "guid", "page", "next", "cursor", "continuation", "csrf", "xsrf", "trace", "request",
  "idempotency", "sync", "nonce", "hash", "digest", "checksum", "sha", "fingerprint", "etag",
  "cache", "commit", "object", "blob", "file", "content", "revision", "rev", "partition", "shard",
  "bucket", "dedup", "dedupe", "lookup", "row", "sort",
]);

// The bare key whose value starts at s[at] is the second word of a credential's
// name in words: api key, access key, secret key, private key.
function keyPhrase(s, at) {
  const before = s.slice(Math.max(0, at - 24), at).toLowerCase();
  const i = before.lastIndexOf("key");
  if (i < 0) {
    return false;
  }
  const head = trimRight(before.slice(0, i), " ");
  for (const w of ["api", "access", "secret", "private", "signing", "license", "licence"]) {
    if (head.endsWith(w) && (head.length === w.length || !isWordByte(head[head.length - w.length - 1]))) {
      return true;
    }
  }
  return false;
}

function credentialField(s, at) {
  const words = fieldWords(s, at);
  if (words.length === 1 && words[0] === "key" && keyPhrase(s, at)) {
    return true;
  }
  if (words.length < 2 || words.some((w) => NOT_CREDENTIAL_WORDS.has(w))) {
    return false;
  }
  return true;
}

// pointerName says s[l:r] is a field's name, not its value: a JSON object's key
// ({"5d41402abc4b2a76": {...}}), as data keyed by a hash has it.
function pointerName(s, l, r) {
  if (l === 0 || s[l - 1] !== '"') {
    return false;
  }
  let i = r;
  if (i < s.length && s[i] === "\\") {
    i++;
  }
  if (i >= s.length || s[i] !== '"') {
    return false;
  }
  i++;
  while (i < s.length && (s[i] === " " || s[i] === "\t")) {
    i++;
  }
  return i < s.length && s[i] === ":";
}

// A value that is code's: a place in a file, a path, a name in code, a package's
// version, a skill's name. Each of these went to the model as a placeholder for
// a real secret and the agent could no longer read what it was pointed at.
const VERSION_RANGE_RE = /^(?:[~^]|[<>=!~]=?|==)?[vV]?\d+(?:\.\d+)+(?:[-+._]?(?:(?:alpha|beta|rc|pre|preview|post|dev|canary|next|nightly|snapshot|release|final|ga|stable|build|incubating)\d*|[abcmABCM]\d+|\d+))*$/i;
const SKILL_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)+$/;
const LINE_REF_RE = /^L?\d+(?:[-–:]L?\d+)*[.,;:]?$/;
const PATH_ROOTS = new Set([
  "Users", "home", "tmp", "private", "var", "etc", "run", "opt", "usr", "mnt", "Volumes", "root", "srv",
  "data", "workspace", "workspaces", "app", "Applications", "Library", "System", "proc", "dev", "sys", "nix",
]);
const SOURCE_EXT = new Set([
  "go", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs",
  "py", "pyi", "rb", "rs", "java", "kt", "kts", "swift",
  "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "m", "mm",
  "cs", "fs", "php", "scala", "dart", "lua", "zig", "nim",
  "ex", "exs", "erl", "hs", "ml", "clj", "r", "jl",
  "sh", "bash", "zsh", "fish", "ps1", "vue", "svelte", "astro",
  "md", "mdx", "rst", "sql", "proto", "graphql", "gradle",
  "html", "css", "scss", "less", "json", "jsonc", "yaml", "yml",
  "toml", "xml", "tf", "ipynb",
]);

// A file's or a folder's path: one from home (~/), from here (./, ../), or from
// a root folder (/Users/…, /tmp/…), with no + or = in it as base64 has.
function pathValue(v) {
  if (/[+=]/.test(v)) {
    return false;
  }
  for (const p of ["~/", "./", "../"]) {
    if (v.startsWith(p) && v.length > p.length) {
      return true;
    }
  }
  if (!v.startsWith("/")) {
    return false;
  }
  const cut = v.indexOf("/", 1);
  if (cut < 0 || cut === v.length - 1) {
    return false;
  }
  return PATH_ROOTS.has(v.slice(1, cut));
}

function lineRef(v) {
  return LINE_REF_RE.test(v);
}

// The name before the value is a file's, or a path's last part, not a field's:
// token.go:L643-669, src/secret_store.ts:…, skills/secret-scanner:….
function fileField(s, a) {
  let i = a;
  while (i > 0 && " \t\"'\\".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  if (i === 0 || (s[i - 1] !== ":" && s[i - 1] !== "=")) {
    return false;
  }
  i--;
  while (i > 0 && " \t\"'\\".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  const end = i;
  while (i > 0 && (text.ALNUM + "_.-").indexOf(s[i - 1]) >= 0) {
    i--;
  }
  const name = s.slice(i, end);
  if (name === "") {
    return false;
  }
  if (i > 0 && (s[i - 1] === "/" || s[i - 1] === "\\")) {
    return true; // a path's last part
  }
  const dot = name.lastIndexOf(".");
  return dot > 0 && SOURCE_EXT.has(name.slice(dot + 1).toLowerCase());
}

// A name in code for a secret, not one: two words or more, one of them token,
// secret, password or key, written as code writes a name. refreshToken2,
// generate_token_v2, env.SECRET_V2 and countTokens4o are names; Passw0rd123
// and password123 are one word, and SuperSecret2024 is a password.
const SECRET_WORDS = new Set(["token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "key", "keys", "apikey", "credential", "credentials"]);
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
function namesASecret(v) {
  if (!IDENT_RE.test(v)) {
    return false;
  }
  if (!isLower(v[0]) && !/[_.]/.test(v)) {
    return false;
  }
  let words = 0;
  let named = false;
  for (let w of identWords(v)) {
    if (!/[A-Za-z]/.test(w)) {
      continue;
    }
    words++;
    const digit = w.search(/[0-9]/);
    if (digit >= 0) {
      w = w.slice(0, digit);
    }
    if (SECRET_WORDS.has(w.toLowerCase())) {
      named = true;
    }
  }
  return words >= 2 && named;
}

// The second half of plugin:skill, as Claude Code names a plugin's skill and
// command (design-tokens:generate-v2, secret-scan:audit-x7k2p9q1): words in
// lower case joined by hyphens on both sides of a colon with no space around
// it. A key has a capital or a long random run.
function skillName(s, a, b) {
  const v = slice(s, a, b);
  if (a < 2 || s[a - 1] !== ":" || !SKILL_SLUG_RE.test(v) || notASlug(v)) {
    return false;
  }
  let i = a - 1;
  while (i > 0 && "abcdefghijklmnopqrstuvwxyz0123456789-".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  return i < a - 1 && (i === 0 || (text.ALNUM + "_.").indexOf(s[i - 1]) < 0) && SKILL_SLUG_RE.test(s.slice(i, a - 1));
}

// A field being set at a value's start, as a command line, a logfmt line or a
// flag sets one: an env var's name in capitals (UI_ADDR=), one in lower case,
// or a flag (--listen=); then =, and something other than another =, so a
// base64 value's padding (dGVzdA==) is never taken for one.
const NEXT_FIELD_RE = /^(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_-]*|--?[A-Za-z][A-Za-z0-9_-]*)=[^=]/;
function nextField(s, a, b) {
  return a > 0 && (s[a - 1] === " " || s[a - 1] === "\t") && NEXT_FIELD_RE.test(slice(s, a, b));
}

// A value the SECRET rules found can be a secret: not code, and not a place in
// a file, a path, a name in code, a skill's name or a package's version.
function fieldAt(s, a, b) {
  if (!notCode(s, a, b)) {
    return false;
  }
  const v = slice(s, a, b);
  if (v[0] === "=") {
    return false; // Go's := with no space after it: secretKey:=base64Encode(raw)
  }
  return !fileField(s, a) && !lineRef(v) && !pathValue(v) && !namesASecret(v) && !skillName(s, a, b) && !VERSION_RANGE_RE.test(v);
}

function namedSecretAt(s, a, b) {
  return notPlainKeyOrCode(s, a, b) && fieldAt(s, a, b);
}

// What stands between a name and a key's value in a message.
const KEY_SEPARATORS = ["为", "為", "是", "：", ":", "=", "は", "는"];
// What a number counts when one follows it: bits, bytes, a time, a count. 密钥为
// 2048 位 is a size, not a key.
const QUANTITY_UNITS = ["位", "比特", "字节", "字節", "个", "個", "次", "秒", "毫秒", "分钟", "分鐘", "小时", "小時", "天", "年", "bit", "byte", "ms", "sec", "min", "ビット", "バイト", "비트", "바이트"];

// keyValue for s[a:b], or six digits or more right after 为, 為, 是, ：, :, =, は
// or 는 that count nothing: a key said in a message is often a number
// (密钥为12231241, token 是 20261025), while 密钥为 2048 位 is a size.
function keyAt(s, a, b) {
  const v = slice(s, a, b);
  if (pathValue(v) || VERSION_RANGE_RE.test(v)) {
    return false;
  }
  if (keyValue(v)) {
    return true;
  }
  if (v.length < 6 || trim(v, DIGITS) !== "") {
    return false;
  }
  const before = trimRight(s.slice(0, a), " \t\"'“「\\");
  const after = trimLeft(s.slice(b), " \t");
  return KEY_SEPARATORS.some((c) => before.endsWith(c)) && !QUANTITY_UNITS.some((u) => after.startsWith(u));
}

// Eleven digits that start 13 to 19 are a mainland mobile number's form, and an
// id's: an order's, a user's, a row's. The form alone is a phone only where
// nothing says it is something else.
const PHONE_WORDS = new Set(["phone", "phones", "mobile", "mobiles", "tel", "telephone", "cell", "cellphone", "contact", "contacts", "whatsapp", "sms", "msisdn", "fax"]);
const PHONE_MARKS = ["手机", "电话", "電話", "联系", "聯繫", "联络"];
const ID_WORDS = ["order", "id", "uid", "no", "no.", "#", "number", "ticket", "invoice", "订单", "订单号", "单号", "编号", "流水号", "工单", "工单号", "运单号", "快递单号", "订单编号", "交易号", "序号", "账单号", "id号"];

function phoneName(name) {
  for (const w of nameWords(name)) {
    if (PHONE_WORDS.has(w)) {
      return true;
    }
  }
  return PHONE_MARKS.some((m) => name.indexOf(m) >= 0);
}

// Where the name that ends at s[i] starts: letters, digits, _, . and - back
// from i, or Chinese characters.
function nameStart(s, i) {
  let j = i;
  while (j > 0) {
    const c = s[j - 1];
    if (!((text.ALNUM + "_.-").indexOf(c) >= 0 || (c.charCodeAt(0) >= 0x4e00 && c.charCodeAt(0) <= 0x9fff))) {
      break;
    }
    j--;
  }
  return j;
}

// The name of the field whose value starts at s[a], and the word before it with
// one space between (the phone of "phone no: …"). null in prose, where no such
// separator is right before the value.
function fieldName(s, a) {
  let i = a;
  while (i > 0 && " \t\"'".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  if (i > 0 && s[i - 1] === ">") {
    const from = Math.max(0, i - 65);
    const k = s.slice(from, i - 1).lastIndexOf("<");
    if (k < 0) {
      return null;
    }
    let tag = s.slice(from + k + 1, i - 1);
    const sp = tag.search(/[ \t]/);
    if (sp >= 0) {
      tag = tag.slice(0, sp);
    }
    if (tag === "" || /[^a-z0-9_.:\-]/i.test(tag)) {
      return null;
    }
    return { name: tag, prev: "" };
  }
  if (i > 0 && (s[i - 1] === ":" || s[i - 1] === "=")) {
    i--;
  } else if (i >= 1 && s[i - 1] === "：") {
    i -= 1;
  } else {
    return null;
  }
  while (i > 0 && " \t\"'".indexOf(s[i - 1]) >= 0) {
    i--;
  }
  const j = nameStart(s, i);
  if (j === i) {
    return null;
  }
  let name = s.slice(j, i);
  if (hasCJKRunes(name) && [...name].length > 6) {
    // a long run of CJK before a colon is a sentence's: its last six characters
    // name the value (我的手机号是：…)
    name = [...name].slice(-6).join("");
  }
  let prev = "";
  if (j >= 2 && s[j - 1] === " " && s[j - 2] !== " ") {
    prev = s.slice(nameStart(s, j - 1), j - 1);
  }
  return { name, prev };
}

function hasCJKRunes(s) {
  return text.hasCJK(s);
}

// A phone, not an id of the same form: with +86 before it, or as a field's
// value only where the field's name has a phone's word in it, or in prose
// unless an id's word is right before it.
function phoneAt(s, a, b) {
  if (b - a > 11) {
    return true; // +86, 86
  }
  const field = fieldName(s, a);
  if (field !== null) {
    return phoneName(field.name) || (field.prev !== "" && phoneName(field.prev)) || field.name.toLowerCase() === "number";
  }
  if (a > 0 && s[a - 1] === "#") {
    return false; // #13912345678
  }
  let before = trimRight(s.slice(Math.max(0, a - 32), a), " \t(\"'“「").toLowerCase();
  for (const c of ["是", "为", "為"]) {
    if (before.endsWith(c)) {
      before = trimRight(before.slice(0, before.length - c.length), " \t");
    }
  }
  for (const w of ID_WORDS) {
    if (!before.endsWith(w)) {
      continue;
    }
    // a whole word: "order", not the end of "recorder"
    let rest = before.slice(0, before.length - w.length);
    if (rest !== "" && /[a-z0-9_\u4e00-\u9fff]/.test(rest[rest.length - 1]) && /[a-z0-9_]/.test(w[0])) {
      continue;
    }
    // but a phone's number: phone no. 13800138000
    if (w === "no" || w === "no." || w === "number") {
      rest = trimRight(rest, " ");
      if (phoneName(rest.slice(nameStart(rest, rest.length)))) {
        return true;
      }
    }
    return false;
  }
  return true;
}

// A value that is all of a bare JSON number, by where it sits: digits only, an
// object's value or an element of an array of numbers, and nothing after it but
// the , } or ] that ends a value. "phone": "13800138000" is a string, and
// phone:13800138000 and "call 13800138000, thanks" are text, so each is still
// masked.
function jsonNumber(s, a, b) {
  if (a >= b || trim(slice(s, a, b), DIGITS) !== "") {
    return false;
  }
  const space = (c) => c === " " || c === "\t" || c === "\n" || c === "\r";
  let k = b;
  while (k < s.length && space(s[k])) {
    k++;
  }
  if (k < s.length && ",}]".indexOf(s[k]) < 0) {
    return false;
  }
  let i = a - 1;
  while (i >= 0 && space(s[i])) {
    i--;
  }
  if (i >= 0 && ":,[".indexOf(s[i]) >= 0) {
    return true;
  }
  if (i < 0) {
    return true;
  }
  return false;
}

// Not a piece of a decimal: 0.123456 is one number, not a phone.
function inDecimal(s, a, b) {
  const at = (i) => i >= 0 && i < s.length && isDigit(s[i]);
  return (at(a) && a >= 2 && s[a - 1] === "." && at(a - 2)) || (at(b - 1) && b + 1 < s.length && s[b] === "." && at(b + 1));
}

const EXPORTS = {
  notAVariable: notAVariable,
  keyValue: keyValue,
  secretValue: secretValue,
  notCode: notCode,
  emailAt: emailAt,
  hiddenInURL: hiddenInURL,
  notASlug: notASlug,
  headerValue: headerValue,
  notAPlainKey: notAPlainKey,
  notPlainKeyOrCode: notPlainKeyOrCode,
  realEmail: realEmail,
  chineseID: chineseID,
  luhn: luhn,
  ssnOK: ssnOK,
  passportOK: passportOK,
  ibanAt: ibanAt,
  dateOK: dateOK,
  macOK: macOK,
  serialOK: serialOK,
  homeAt: homeAt,
  userOK: userOK,
  notLineIdent: notLineIdent,
  lineUserOK: lineUserOK,
  hostOK: hostOK,
  lineHostOK: lineHostOK,
  notPackagePin: notPackagePin,
  ipv4At: ipv4At,
  ipv6OK: ipv6OK,
  bucketOK: bucketOK,
  digestShaped: digestShaped,
  idShaped: idShaped,
  uuidShaped: uuidShaped,
  elementToken: elementToken,
  idAround: idAround,
  fieldWords: fieldWords,
  credentialField: credentialField,
  pointerName: pointerName,
  fieldAt: fieldAt,
  namedSecretAt: namedSecretAt,
  keyAt: keyAt,
  phoneAt: phoneAt,
  jsonNumber: jsonNumber,
  inDecimal: inDecimal,
  versionTest: (v) => VERSION_RANGE_RE.test(v),
};

module.exports = EXPORTS;

"use strict";
// The rules: one pattern per kind of value, and the check that keeps its false
// positives out. Ported from magpie's internal/redact/redact.go and more.go.
//
// Each rule names its value as a group of its pattern, because the pattern also
// has to say where the value is allowed to be (after a field's name, after
// 密码). goja implements RegExp without the `d` flag, so a group's offset is
// found by locating the group's text inside the whole match; the rule's check
// then has the value and where it sits, which is what magpie's finders need.
//
// A rule's `markers` are substrings that any text it can match contains: the
// pattern only runs where one is present, which is what keeps a prompt's cost
// proportional to what it holds.

const checks = require("./checks");
const text = require("./text");

const ALNUM = text.ALNUM;
const DIGITS = text.DIGITS;

// quote is a field's or a value's quote, if it has one: " or ', or \" in JSON
// written inside a string.
const QUOTE = "(?:\\\\?[\"'])?";
// secretCh are the characters of a secret's value.
const SECRET_CH = "[A-Za-z0-9_\\-./+=~!@#%^&*]";

// What a field holding a secret has in its name: DB_PASSWORD, apiKey,
// x-api-key, client_secret.
const SECRET_NAMES = [
  ["password", "pass"], ["passwd", "pass"],
  ["secret", "secret"],
  ["token", "token"],
  ["api[_-]?key", "key"], ["access[_-]?key", "key"], ["private[_-]?key", "key"],
  ["credential", "credential"],
];
const SECRET_NAME_PATTERN = SECRET_NAMES.map(([re]) => re).join("|");

// Each name's marker as a name is written: lower case, upper case and
// capitalised, so apiKey is found as apiKey.
function nameMarkers(names) {
  const out = [];
  for (const marker of names) {
    for (const m of [marker, marker.toUpperCase(), marker[0].toUpperCase() + marker.slice(1)]) {
      if (out.indexOf(m) < 0) {
        out.push(m);
      }
    }
  }
  return out;
}
const SECRET_MARKERS = nameMarkers(["pass", "secret", "token", "key", "credential"]);

// A password is called, in Chinese, Japanese and Korean.
const CJK_PASSWORD_NAMES = ["密码", "密碼", "口令", "PIN码", "PIN碼", "PIN 码", "安全码", "安全碼", "パスワード", "暗証番号", "비밀번호", "암호", "비번"];
// A key, a secret or a token is called.
const CJK_KEY_NAMES = [
  "密钥", "密鑰", "秘钥", "秘鑰", "私钥", "私鑰", "金钥", "金鑰", "令牌", "权杖", "權杖", "授权码", "授權碼",
  "秘密鍵", "トークン", "シークレット", "APIキー", "アクセスキー",
  "토큰", "비밀키", "API 키", "API키",
];
// What stands between a name and its value in a message: 为, 為, 是.
const CJK_COPULAS = ["为", "為", "是", "："];

function lowerAll(names) {
  return names.map((n) => n.toLowerCase());
}

// A value after one of names: after ：, :, =, 为, 為, 是, は or 는, quoted or
// not, or after nothing but a space.
function cjkNamed(names) {
  return new RegExp(
    "(?:" + names.join("|") + ")[ \\t]*(?:[:：=][ \\t]*|[为為是][ \\t]*[:：]?[ \\t]*|は[ \\t]*|는[ \\t]*)?(?:\\\\?[\"'“「])?(" + SECRET_CH + "{3,63}[A-Za-z0-9_\\-/+=~!@#%^&*])",
    "i",
  );
}

// The rules, in the order they are tried. The order matters where two find the
// same value: the first keeps it, so a value's placeholder is the same every
// time (an API key in API_KEY=… is an API_KEY, not a SECRET).
const RULES = [
  // A private key's PEM block.
  {
    kind: "PRIVATE_KEY",
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
    markers: ["PRIVATE KEY"],
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /sk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
    markers: ["sk-"],
    bound: text.TOKEN_CH,
    ok: checks.notASlug,
    value: 0,
  },
  // A gateway's or a relay's own: oc_sk_…, or_sk_…
  {
    kind: "API_KEY",
    re: /[a-z]{2,4}_sk_[A-Za-z0-9_-]{20,}/g,
    markers: ["_sk_"],
    bound: text.TOKEN_CH,
    ok: checks.secretValue,
    value: 0,
  },
  // Volcano Ark and the relays in front of it issue keys with an ark- prefix.
  {
    kind: "API_KEY",
    re: /ark-[A-Za-z0-9][A-Za-z0-9_-]{15,}/g,
    markers: ["ark-"],
    bound: text.TOKEN_CH,
    ok: checks.secretValue,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})/g,
    markers: ["gh", "github_pat_", "glpat-"],
    bound: text.TOKEN_CH,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /AIza[0-9A-Za-z_-]{35}/g,
    markers: ["AIza"],
    bound: text.TOKEN_CH,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /xox[abposr]-[0-9A-Za-z-]{10,}/g,
    markers: ["xox"],
    bound: text.TOKEN_CH,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /(?:sk|rk)_live_[0-9A-Za-z]{20,}/g,
    markers: ["_live_"],
    bound: text.TOKEN_CH,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    markers: ["AKIA", "ASIA"],
    bound: ALNUM,
    value: 0,
  },
  {
    kind: "API_KEY",
    re: /(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/g,
    markers: ["hf_", "gsk_", "xai-", "npm_", "pypi-", "dop_v1_", "SG."],
    bound: text.TOKEN_CH,
    value: 0,
  },
  {
    kind: "TOKEN",
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    markers: ["eyJ"],
    bound: text.TOKEN_CH,
    value: 0,
  },
  // The password of user:password@host, or of :password@host as a Redis URL has
  // it with no user.
  {
    kind: "PASSWORD",
    re: /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@\/?#"'<>]*:([^\s@\/?#"'<>]{3,})@/g,
    markers: ["://"],
    ok: checks.notAVariable,
    at: checks.hiddenInURL,
    value: 1,
  },
  // password = …, API_KEY: "…", as .env files and configs have them.
  {
    kind: "SECRET",
    re: new RegExp("(?:" + SECRET_NAME_PATTERN + ")[A-Za-z0-9_.-]*" + QUOTE + "[ \\t]*[:=][ \\t]*" + QUOTE + "(" + SECRET_CH + "{8,})", "gi"),
    markers: SECRET_MARKERS,
    ok: checks.secretValue,
    at: checks.fieldAt,
    field: true,
    value: 1,
  },
  // An env var's name says what it holds in the upper case: a SERVICE_X_KEY, a
  // DB_PASS. In the lower case a name that ends in key is code's: a sort key, a
  // cache key, a public key.
  {
    kind: "SECRET",
    re: new RegExp("(?:^|[^A-Za-z0-9_.-])[A-Za-z0-9_.-]*_(?:KEY|PASS)" + QUOTE + "[ \\t]*[:=][ \\t]*" + QUOTE + "(" + SECRET_CH + "{8,})"),
    markers: nameMarkers(["key", "pass"]),
    ok: checks.secretValue,
    at: checks.namedSecretAt,
    field: true,
    value: 1,
  },
  // An Authorization or Cookie header's value is a secret whatever it looks
  // like: an opaque bearer token, a session value.
  {
    kind: "SECRET",
    re: /^[ \t]*(?:authorization|cookie)[ \t]*:[ \t]*(\S[^\r\n]{7,})/gim,
    markers: nameMarkers(["authorization", "cookie"]),
    ok: checks.headerValue,
    value: 1,
  },
  // A field called key and nothing more: "key": "oc_sk_…". Only a long value of
  // letters and digits both, since code calls anything a key.
  {
    kind: "SECRET",
    re: new RegExp("(?:^|[^A-Za-z0-9_.-])" + QUOTE + "key" + QUOTE + "[ \\t]*[:=][ \\t]*" + QUOTE + "(" + SECRET_CH + "{16,})", "gi"),
    markers: nameMarkers(["key"]),
    ok: checks.secretValue,
    at: checks.fieldAt,
    field: true,
    value: 1,
  },
  // A password after its name in Chinese, Japanese or Korean, as people write
  // one into a message: 密码：786kih, 密碼是 hunter2, パスワード: ….
  {
    kind: "PASSWORD",
    re: cjkNamed(CJK_PASSWORD_NAMES),
    fold: lowerAll(CJK_PASSWORD_NAMES),
    back: 64,
    ahead: 100,
    ok: checks.notAVariable,
    field: true,
    value: 1,
  },
  // A key, a secret or a token after its name the same way: 密钥为 …, 令牌是 ….
  {
    kind: "SECRET",
    re: cjkNamed(CJK_KEY_NAMES),
    fold: lowerAll(CJK_KEY_NAMES),
    back: 64,
    ahead: 100,
    at: checks.keyAt,
    field: true,
    value: 1,
  },
  // An English name for one before 为, 為, 是 or ：, as a Chinese message has
  // it: apikey 为 …, token 是 …, API Key：….
  {
    kind: "SECRET",
    re: new RegExp("(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|pwd|api[ ]key|access[ ]key|secret[ ]key|key|\\bpin(?:[ ]?code)?)" + QUOTE + "[ \\t]*(?:[为為是][ \\t]*[:：]?|：)[ \\t]*(?:\\\\?[\"'“「])?(" + SECRET_CH + "{3,}[A-Za-z0-9_\\-/+=~!@#%^&*])", "gi"),
    fold: CJK_COPULAS,
    back: 24,
    ahead: 260,
    at: checks.keyAt,
    field: true,
    value: 1,
  },

  // Personal data always masked with the personal toggle: an address, a
  // resident's ID, a mainland mobile number, a card number.
  {
    kind: "EMAIL",
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g,
    markers: ["@"],
    bound: ALNUM + "_%+-",
    ok: checks.realEmail,
    at: checks.emailAt,
    cat: "email",
    value: 0,
  },
  {
    kind: "ID_CARD",
    re: /[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]/g,
    bound: ALNUM,
    ok: checks.chineseID,
    cat: "id_card",
    value: 0,
  },
  {
    kind: "PHONE",
    re: /(?:\+?86[- ]?)?1[3-9]\d{9}/g,
    bound: ALNUM,
    at: checks.phoneAt,
    cat: "phone",
    value: 0,
  },
  {
    kind: "BANK_CARD",
    re: /[3-6]\d{3}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?/g,
    bound: ALNUM,
    ok: checks.luhn,
    cat: "bank_card",
    value: 0,
  },

  // US Social Security numbers: 123-45-6789 as it is written, or nine digits
  // after SSN, in the ranges the SSA gives out.
  {
    kind: "SSN",
    cat: "ssn",
    re: /\d{3}-\d{2}-\d{4}/g,
    markers: ["-"],
    bound: ALNUM + "-",
    ok: checks.ssnOK,
    value: 0,
  },
  {
    kind: "SSN",
    cat: "ssn",
    re: new RegExp("(?:ssn|social[ \\t]+security(?:[ \\t]+(?:number|no\\.?|#))?)[\"']?[ \\t]*(?:[:#=：][ \\t]*)?(?:is[ \\t]+)?[\"']?(\\d{9}|\\d{3} \\d{2} \\d{4})", "i"),
    fold: ["ssn", "social"],
    back: 8,
    ahead: 80,
    bound: DIGITS,
    ok: checks.ssnOK,
    value: 1,
  },

  // A passport number after the word for it.
  {
    kind: "PASSPORT",
    cat: "passport",
    re: new RegExp("(?:passport(?:[ \\t]*(?:no\\.?|number|num|#))?|reisepass(?:nummer)?)[\"']?[ \\t]*(?:[:#=：][ \\t]*)?(?:(?:is|was)[ \\t]+)?[\"']?([A-Z0-9]{6,9})" +
      "|(?:护照(?:号码|号)?|護照(?:號碼|号码|番号)?|パスポート(?:番号)?)[ \\t]*(?:[:：=][ \\t]*)?(?:是[ \\t]*|は[ \\t]*)?[\"']?([A-Z0-9]{6,9})", "gi"),
    fold: ["passport", "reisepass", "护照", "護照", "パスポート"],
    back: 8,
    ahead: 80,
    anyGroup: true,
    bound: ALNUM,
    ok: checks.passportOK,
    value: 0,
  },

  // An IBAN, as one word or printed in groups of four, by its checksum.
  {
    kind: "IBAN",
    cat: "iban",
    re: /[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)/g,
    bound: ALNUM,
    fix: checks.ibanAt,
    value: 0,
  },

  // A date after the words that say it is a birthday; a date alone is not.
  {
    kind: "BIRTHDAY",
    cat: "birthday",
    bound: DIGITS,
    ok: (v) => checks.dateOK(v, new Date()),
    re: new RegExp("(?:(?:date[ \\t]+of[ \\t]+birth|birth[ \\t_-]?date|birthday|dob|d\\.o\\.b\\.?|born(?:[ \\t]+on)?|geburtsdatum|geboren(?:[ \\t]+am)?)|生日|出生日期|出生年月日|出生于|出生於|出生|誕生日|生年月日)" +
      "[\"']?[ \\t]*(?:[:#=：][ \\t]*)?(?:(?:is|was)[ \\t]+|是[ \\t]*|为[ \\t]*|為[ \\t]*|は[ \\t]*)?[\"']?" +
      "(\\d{4}[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{4}[ \\t]*年[ \\t]*\\d{1,2}[ \\t]*月[ \\t]*\\d{1,2}[ \\t]*日?|\\d{1,2}[-/.]\\d{1,2}[-/.]\\d{4}" +
      "|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?[ \\t]+\\d{1,2}(?:st|nd|rd|th)?,?[ \\t]+\\d{4}|\\d{1,2}(?:st|nd|rd|th)?[ \\t]+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?,?[ \\t]+\\d{4})", "gi"),
    fold: ["birth", "dob", "d.o.b", "born", "geburt", "geboren", "生日", "出生", "誕生日", "生年月日"],
    back: 16,
    ahead: 80,
    value: 1,
  },

  // A MAC address; not a piece of an IPv6 address or a certificate's
  // fingerprint.
  {
    kind: "MAC",
    cat: "mac",
    re: /[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}/g,
    bound: ALNUM + ":-",
    ok: checks.macOK,
    value: 0,
  },

  // A serial number after S/N, Serial or 序列号, and a separator; not "serial
  // port" or Serial.println.
  {
    kind: "SERIAL",
    cat: "serial",
    re: new RegExp("(?:serial[ \\t_-]?(?:number|num|no\\.?|#)?|s\\/n|sn)(?:[ \\t]*\\([^)\\n]{1,20}\\))?[\"']?[ \\t]*[:#=：][ \\t]*[\"']?([A-Za-z0-9][A-Za-z0-9-]{4,39})" +
      "|(?:序列号|序列號|シリアル番号|seriennummer)[ \\t]*[:：=]?[ \\t]*[\"']?([A-Za-z0-9][A-Za-z0-9-]{4,39})", "gi"),
    fold: ["serial", "s/n", "sn", "序列", "シリアル", "seriennummer"],
    back: 8,
    ahead: 80,
    anyGroup: true,
    bound: ALNUM + "-",
    ok: checks.serialOK,
    value: 0,
  },

  // The user's name in a home folder: /Users/<name>, /home/<name>,
  // C:\Users\<name>; the rest of the path stays.
  {
    kind: "USERNAME",
    cat: "home",
    re: /(?:^|[^A-Za-z0-9_.~/\\-])(?:file:\/\/)?(?:\/mnt\/[a-z])?\/(?:Users|home)\/([^\s/\\:*?"'<>|,;()[\]{}`$%]{1,64})/g,
    fold: ["/users/", "/home/"],
    back: 16,
    ahead: 80,
    fix: checks.homeAt,
    value: 1,
  },
  {
    kind: "USERNAME",
    cat: "home",
    re: /(?:^|[^A-Za-z0-9])[A-Za-z]:(?:\\{1,4}|\/)(?:users|documents and settings)(?:\\{1,4}|\/)(?:([A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)+)(?:\\|\/)|([^\s/\\:*?"'<>|,;()[\]{}`$%]{1,64}))/gi,
    fold: ["users", "documents and settings"],
    back: 12,
    ahead: 100,
    anyGroup: true,
    fix: checks.homeAt,
    value: 0,
  },

  // user@host as a shell prompt has it (user@host:~$, [user@host ~]$) or as ssh,
  // scp and rsync are given it; git@github.com is no one's; a package pinned at
  // its version, js-tokens@4.0.0, is no login.
  {
    cat: "userhost",
    groups: ["USERNAME", "HOSTNAME"],
    groupOK: [checks.userOK, checks.hostOK],
    markers: ["@"],
    at: checks.notPackagePin,
    re: /(?:^|[^A-Za-z0-9._%+-])([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)(?::[~/]|:[ \t]*$|[ \t]+[~/]|[ \t]*[$%#>][ \t]|[ \t]*[$%#>]$)/gm,
  },
  {
    cat: "userhost",
    groups: ["USERNAME", "HOSTNAME"],
    groupOK: [checks.userOK, checks.hostOK],
    markers: ["@"],
    at: checks.notPackagePin,
    re: /(?:ssh|scp|sftp|rsync|mosh|ssh-copy-id)[^\n@]{0,80}?[ \t"']([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)/gi,
  },
  // hostname: x, HOSTNAME=x, a line with the value alone after it; or ssh
  // config's HostName x, indented under its Host.
  {
    kind: "HOSTNAME",
    cat: "userhost",
    anyGroup: true,
    ok: checks.lineHostOK,
    re: /^[ \t]*["']?(?:(?:host[ \t_-]?name|computer[ \t_-]?name|machine[ \t_-]?name|device[ \t_-]?name)|主机名|主機名|計算機名|コンピュータ名|コンピューター名)["']?[ \t]*[:=：][ \t]*(?:["']([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)["'][ \t]*[,;]?|([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*))[ \t]*$|^[ \t]+HostName[ \t]+([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)[ \t]*$/gim,
    fold: ["name", "主机", "主機", "計算機", "コンピュータ"],
  },
  // User: x, USER=x, a line with the name alone after it; or ssh config's User
  // x, indented under its Host.
  {
    kind: "USERNAME",
    cat: "userhost",
    anyGroup: true,
    ok: checks.lineUserOK,
    at: checks.notLineIdent,
    re: /^[ \t]*["']?(?:(?:user[ \t_-]?name|login[ \t_-]?name|user|login|logname)|用户名|用戶名|ユーザー名)["']?[ \t]*[:=：][ \t]*(?:["']([A-Za-z0-9_][A-Za-z0-9._-]{0,31})["'][ \t]*[,;]?|([A-Za-z0-9_][A-Za-z0-9._-]{0,31}))[ \t]*$|^[ \t]+User[ \t]+([A-Za-z0-9_][A-Za-z0-9._-]{0,31})[ \t]*$/gim,
    fold: ["user", "login", "logname", "用户", "用戶", "ユーザー"],
  },

  // A public IP address; not a private, loopback, link-local, CGNAT or
  // documentation one, nor a version.
  {
    kind: "IP",
    cat: "ip",
    markers: ["."],
    at: checks.ipv4At,
    re: /(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}/g,
    value: 0,
  },
  {
    kind: "IP",
    cat: "ip",
    markers: [":"],
    bound: ALNUM + ":_",
    ok: checks.ipv6OK,
    re: /[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}/g,
    value: 0,
  },

  // A cloud bucket: s3://<b>, gs://<b>, oss://, abfss://<c>@<account>…,
  // <b>.s3.amazonaws.com, s3.amazonaws.com/<b>.
  {
    cat: "bucket",
    groups: ["BUCKET", "BUCKET"],
    groupOK: [checks.bucketOK, checks.bucketOK],
    markers: ["://"],
    re: /(?:s3a?|s3n|gs|oss|cosn?|obs|r2|ks3|bos|tos|az|azure|wasbs?|abfss?):\/\/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)(?:@([a-z0-9]{3,24})\.(?:blob|dfs)\.core\.windows\.net)?/gi,
  },
  {
    kind: "BUCKET",
    cat: "bucket",
    ok: checks.bucketOK,
    fold: ["amazonaws.com", "googleapis.com", "cloud.google.com", "aliyuncs.com", "myqcloud.com", "windows.net", "cloudflarestorage.com", "digitaloceanspaces.com", "myhuaweicloud.com", "volces.com"],
    back: 128,
    ahead: 32,
    re: /(?:^|[^A-Za-z0-9.-])([a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?)\.(?:s3(?:[.-](?:dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?|s3-accelerate\.amazonaws\.com|storage\.googleapis\.com|oss-[a-z0-9-]+\.aliyuncs\.com|cos\.[a-z0-9-]+\.myqcloud\.com|obs\.[a-z0-9-]+\.myhuaweicloud\.com|r2\.cloudflarestorage\.com|(?:blob|dfs)\.core\.windows\.net|[a-z0-9-]+\.digitaloceanspaces\.com|tos-[a-z0-9-]+\.volces\.com)/g,
  },
  {
    kind: "BUCKET",
    cat: "bucket",
    ok: checks.bucketOK,
    fold: ["amazonaws.com", "googleapis.com", "cloud.google.com", "aliyuncs.com", "myqcloud.com", "windows.net", "cloudflarestorage.com", "digitaloceanspaces.com", "myhuaweicloud.com", "volces.com"],
    back: 48,
    ahead: 80,
    re: /(?:^|[^A-Za-z0-9.-])(?:s3(?:[.-](?:dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?|storage\.googleapis\.com|storage\.cloud\.google\.com|[a-z0-9]{3,24}\.blob\.core\.windows\.net|oss-[a-z0-9-]+\.aliyuncs\.com|[a-z0-9-]+\.digitaloceanspaces\.com)\/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)/g,
  },
];

const EXPORTS = { RULES: RULES, cjkNamed: cjkNamed, nameMarkers: nameMarkers, lowerAll: lowerAll, SECRET_CH: SECRET_CH, QUOTE: QUOTE };

module.exports = EXPORTS;;

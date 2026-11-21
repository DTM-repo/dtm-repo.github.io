// Reversible redaction with a gate. Runs entirely in the browser: nothing is sent anywhere.
// Ported from the redaction ledger in Henry Listens (github.com/DTM-repo/henry-listens, relay/redact.mjs).
(function (root) {
  const PATTERNS = [
    { kind: 'SEVIS_ID', label: 'Federal student record number', re: /\bN[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{4}\b|\bN\d{10}\b/gi },
    { kind: 'EMAIL', label: 'Email address', re: /[\w.+-]+@[\w-]+\.[\w.-]*\w/g },
    { kind: 'SSN', label: 'Social Security number', re: /\b\d{3}-\d{2}-\d{4}\b/g },
    { kind: 'PHONE', label: 'Phone number', re: /(?:\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
    { kind: 'PASSPORT', label: 'Passport number', re: /\b(?:passport(?:\s+(?:number|no\.?|#))?\s*(?:is|:)?\s*)([A-Z]{1,2}\d{6,9})\b/gi, group: 1 },
    { kind: 'ID_NUMBER', label: 'ID number', re: /\b(?:student id|id number|employee id|account(?:\s+number)?)\s*(?:is|:|#)?\s*(\d{6,10})\b/gi, group: 1 },
    { kind: 'BIRTH_DATE', label: 'Date of birth', re: /\b(?:born(?:\s+on)?|date of birth|dob)\s*(?:is|:)?\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}|[A-Z][a-z]+ \d{1,2},? \d{4})/gi, group: 1 },
  ];
  const HONORIFIC = /\b(?:Mr|Mrs|Ms|Mx|Dr|Prof)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/g;
  const NOT_NAMES = new Set(('Dear Hello Hi Thank Thanks Please Regards Sincerely Best Kind From To Subject Re Date Sent Case Note Notes Summary Office International Student Students Services Service Admissions Financial Aid Registrar University College School Department Program Form Bank Letter Statement Passport Visa United States America New York Jersey January February March April May June July August September October November December Monday Tuesday Wednesday Thursday Friday Saturday Sunday Spring Summer Fall Winter Optional Practical Training Curricular Computer Science Bachelor Master Business Administration The This That These Those We I You He She They It My Your Our Their His Her An A If When Then Also Not No Yes Action Follow Up Next Steps Step Adviser Advisor Sponsor Applicant Meeting Phone Email Called Spoke Sent Received Federal Social Security Number').split(' '));

  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  class Redactor {
    constructor(names) {
      this.ledger = new Map();   // token -> { value, kind, label }
      this.byValue = new Map();
      this.counts = {};
      this.nameRes = [];
      for (const n of names || []) this.addName(n);
    }
    token(kind, original, label) {
      const key = original.toLowerCase().replace(/\s+/g, ' ');
      if (this.byValue.has(key)) return this.byValue.get(key);
      this.counts[kind] = (this.counts[kind] || 0) + 1;
      const t = '[' + kind + '_' + this.counts[kind] + ']';
      this.ledger.set(t, { value: original, kind, label });
      this.byValue.set(key, t);
      return t;
    }
    addName(name) {
      name = name.trim().replace(/\s+/g, ' ');
      const parts = name.split(' ').filter((p) => p.length >= 3);
      if (!parts.length) return null;
      const t = this.token('PERSON', name, 'Person on your list');
      // full name first, then each part, so "Amara" alone still becomes the same token
      for (const p of [name, ...parts]) this.nameRes.push({ re: new RegExp('\\b' + esc(p) + '\\b', 'gi'), token: t });
      return t;
    }
    redact(text) {
      let out = text;
      for (const { kind, label, re, group } of PATTERNS) {
        out = out.replace(re, (m, g1) => (group ? m.replace(g1, this.token(kind, g1, label)) : this.token(kind, m, label)));
      }
      for (const { re, token } of this.nameRes) out = out.replace(re, token);
      return out;
    }
  }

  // The gate: after redaction, look for anything that still looks like a person or an identifier.
  function gate(redacted, dismissed) {
    dismissed = dismissed || new Set();
    const flags = [];
    const seen = new Set();
    const add = (text, why, type) => { const k = type + ':' + text.toLowerCase(); if (!seen.has(k) && !dismissed.has(text.toLowerCase())) { seen.add(k); flags.push({ text, why, type }); } };
    const plain = redacted.replace(/\[[A-Z_]+_\d+\]/g, ' • ');
    let m;
    HONORIFIC.lastIndex = 0;
    while ((m = HONORIFIC.exec(plain))) add(m[1], 'follows a title such as Mr. or Dr.', 'name');
    const caps = /\b[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,3}\b/g;
    while ((m = caps.exec(plain))) {
      const words = m[0].split(/\s+/);
      while (words.length && NOT_NAMES.has(words[0])) words.shift();
      while (words.length && NOT_NAMES.has(words[words.length - 1])) words.pop();
      if (words.length >= 2 && words.length <= 3 && !words.some((w) => NOT_NAMES.has(w))) add(words.join(' '), 'looks like a name that is not on your list', 'name');
    }
    const digits = /\b\d[\d\s-]{6,}\d\b/g;
    while ((m = digits.exec(plain))) if (m[0].replace(/\D/g, '').length >= 7) add(m[0].trim(), 'a long number that no rule recognized', 'number');
    return flags;
  }

  // Put the real values back, and report any token the answer uses that was never issued.
  function restore(answer, ledger) {
    const unknown = [];
    const used = [];
    const text = answer.replace(/\[[A-Z_]+_\d+\]/g, (t) => {
      if (ledger.has(t)) { used.push(t); return ledger.get(t).value; }
      unknown.push(t); return t;
    });
    return { text, unknown: [...new Set(unknown)], used: [...new Set(used)] };
  }

  root.Redaction = { Redactor, gate, restore, PATTERNS };
})(typeof window !== 'undefined' ? window : globalThis);

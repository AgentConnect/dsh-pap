/** Bounded RFC 8259 parser: fatal UTF-8 and duplicate object member rejection. */
export function strictJson(bytes: Uint8Array, maxBytes = 1024 * 1024): unknown {
  if (bytes.length > maxBytes) throw new Error('Invalid JSON');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0; let nodes = 0;
  const fail = (): never => { throw new Error('Invalid JSON'); };
  const ws = () => { while (at < text.length && /[\x20\t\r\n]/.test(text[at]!)) at++; };
  const string = (): string => {
    if (text[at] !== '"') return fail();
    const start = at++;
    for (;;) {
      if (at >= text.length) return fail();
      const char = text.charCodeAt(at++);
      if (char === 0x22) {
        // JSON.parse validates string escapes and control characters, after token boundaries are fixed.
        return JSON.parse(text.slice(start, at));
      }
      if (char < 0x20) return fail();
      if (char === 0x5c) {
        if (at >= text.length) return fail();
        const escape = text[at++]!;
        if (escape === 'u') { if (!/^[a-fA-F0-9]{4}$/.test(text.slice(at, at + 4))) return fail(); at += 4; }
        else if (!'"\\/bfnrt'.includes(escape)) return fail();
      }
    }
  };
  const value = (depth: number): unknown => {
    if (++nodes > 65536 || depth > 32) return fail();
    ws(); const char = text[at];
    if (char === '"') return string();
    if (char === '{') {
      at++; ws(); const result: Record<string, unknown> = Object.create(null); const seen = new Set<string>();
      if (text[at] === '}') { at++; return result; }
      for (;;) {
        ws(); const key = string(); if (seen.has(key)) return fail(); seen.add(key);
        ws(); if (text[at++] !== ':') return fail(); result[key] = value(depth + 1); ws();
        const end = text[at++]; if (end === '}') return result; if (end !== ',') return fail();
      }
    }
    if (char === '[') {
      at++; ws(); const result: unknown[] = [];
      if (text[at] === ']') { at++; return result; }
      for (;;) {
        result.push(value(depth + 1)); ws(); const end = text[at++];
        if (end === ']') return result; if (end !== ',') return fail();
      }
    }
    for (const [literal, parsed] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(literal, at)) { at += literal.length; return parsed; }
    }
    const number = text.slice(at).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!number) return fail(); at += number[0].length; const parsed = Number(number[0]); if (!Number.isFinite(parsed)) return fail(); return parsed;
  };
  const parsed = value(0); ws(); if (at !== text.length) return fail(); return parsed;
}

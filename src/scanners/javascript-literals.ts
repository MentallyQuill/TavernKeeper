import type { DecodedLiteral } from "./javascript-analysis-types.js";

interface ParsedString {
  value: string;
  end: number;
  escaped: boolean;
}

interface ParsedLiteralExpression {
  value: string;
  end: number;
  literals: number;
  escaped: boolean;
}

const simpleEscapes: Record<string, string> = {
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "0": "\0",
};

function skipWhitespace(source: string, offset: number) {
  let cursor = offset;
  while (/\s/u.test(source[cursor] ?? "")) cursor += 1;
  return cursor;
}

function parseString(source: string, offset: number): ParsedString | null {
  const quote = source[offset];
  if (quote !== '"' && quote !== "'") return null;
  let cursor = offset + 1;
  let value = "";
  let escaped = false;
  while (cursor < source.length) {
    const character = source[cursor];
    if (character === quote) return { value, end: cursor + 1, escaped };
    if (character === "\n" || character === "\r" || character === undefined)
      return null;
    if (character !== "\\") {
      value += character;
      cursor += 1;
      continue;
    }
    escaped = true;
    const escape = source[cursor + 1];
    if (escape === undefined) return null;
    if (escape === "\n") {
      cursor += 2;
      continue;
    }
    if (escape === "\r") {
      cursor += source[cursor + 2] === "\n" ? 3 : 2;
      continue;
    }
    if (escape === "x") {
      const digits = source.slice(cursor + 2, cursor + 4);
      if (!/^[0-9a-f]{2}$/iu.test(digits)) return null;
      value += String.fromCodePoint(Number.parseInt(digits, 16));
      cursor += 4;
      continue;
    }
    if (escape === "u") {
      if (source[cursor + 2] === "{") {
        const close = source.indexOf("}", cursor + 3);
        if (close < 0) return null;
        const digits = source.slice(cursor + 3, close);
        if (!/^[0-9a-f]{1,6}$/iu.test(digits)) return null;
        const point = Number.parseInt(digits, 16);
        if (point > 0x10ffff) return null;
        value += String.fromCodePoint(point);
        cursor = close + 1;
        continue;
      }
      const digits = source.slice(cursor + 2, cursor + 6);
      if (!/^[0-9a-f]{4}$/iu.test(digits)) return null;
      value += String.fromCharCode(Number.parseInt(digits, 16));
      cursor += 6;
      continue;
    }
    value += simpleEscapes[escape] ?? escape;
    cursor += 2;
  }
  return null;
}

function parseLiteralExpression(
  source: string,
  offset: number,
): ParsedLiteralExpression | null {
  let cursor = skipWhitespace(source, offset);
  const first = parseString(source, cursor);
  if (first === null) return null;
  let value = first.value;
  let literals = 1;
  let escaped = first.escaped;
  cursor = skipWhitespace(source, first.end);
  while (source[cursor] === "+") {
    cursor = skipWhitespace(source, cursor + 1);
    const next = parseString(source, cursor);
    if (next === null) return null;
    value += next.value;
    literals += 1;
    escaped ||= next.escaped;
    cursor = skipWhitespace(source, next.end);
  }
  return { value, end: cursor, literals, escaped };
}

function printable(value: string) {
  if (value.length === 0 || value.includes("\uFFFD")) return false;
  let accepted = 0;
  let total = 0;
  for (const character of value) {
    total += 1;
    const point = character.codePointAt(0) ?? 0;
    if (character === "\n" || character === "\r" || character === "\t") {
      accepted += 1;
    } else if (point >= 0x20 && point !== 0x7f) {
      accepted += 1;
    }
  }
  return total > 0 && accepted / total >= 0.85;
}

function decodeBase64(value: string) {
  const compact = value.trim();
  if (
    compact.length < 4 ||
    compact.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      compact,
    )
  )
    return null;
  try {
    const bytes = Buffer.from(compact, "base64");
    if (
      bytes.toString("base64").replace(/=+$/u, "") !==
      compact.replace(/=+$/u, "")
    )
      return null;
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function decodeHex(value: string) {
  if (
    value.length === 0 ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]+$/iu.test(value)
  )
    return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.from(value, "hex"),
    );
  } catch {
    return null;
  }
}

export function decodeJavascriptLiterals(input: {
  source: string;
  maxOutputs: number;
  maxOutputBytes: number;
}): DecodedLiteral[] {
  if (
    !Number.isInteger(input.maxOutputs) ||
    input.maxOutputs < 0 ||
    !Number.isInteger(input.maxOutputBytes) ||
    input.maxOutputBytes < 1
  )
    throw new Error("JavaScript literal limits must be valid integers.");

  const outputs: DecodedLiteral[] = [];
  const identities = new Set<string>();
  const add = (
    content: string | null,
    transform: DecodedLiteral["transform"],
    sourceStart: number,
    sourceEnd: number,
  ) => {
    if (
      content === null ||
      !printable(content) ||
      Buffer.byteLength(content, "utf8") > input.maxOutputBytes ||
      outputs.length >= input.maxOutputs
    )
      return;
    const identity = `${transform}\u0000${content}`;
    if (identities.has(identity)) return;
    identities.add(identity);
    outputs.push({ content, transform, sourceStart, sourceEnd });
  };

  const literalCalls = [
    { expression: /\batob\s*\(/gu, transform: "base64" as const },
    {
      expression: /\bdecodeURIComponent\s*\(/gu,
      transform: "percent" as const,
    },
  ];
  for (const call of literalCalls) {
    for (const match of input.source.matchAll(call.expression)) {
      if (outputs.length >= input.maxOutputs) break;
      const expression = parseLiteralExpression(
        input.source,
        match.index + match[0].length,
      );
      if (expression === null || input.source[expression.end] !== ")") continue;
      let decoded: string | null = null;
      if (call.transform === "base64") decoded = decodeBase64(expression.value);
      else {
        try {
          decoded = decodeURIComponent(expression.value);
        } catch {
          decoded = null;
        }
      }
      add(decoded, call.transform, match.index, expression.end + 1);
    }
  }

  for (const match of input.source.matchAll(/\bBuffer\s*\.\s*from\s*\(/gu)) {
    if (outputs.length >= input.maxOutputs) break;
    const value = parseLiteralExpression(
      input.source,
      match.index + match[0].length,
    );
    if (value === null || input.source[value.end] !== ",") continue;
    const encoding = parseLiteralExpression(input.source, value.end + 1);
    if (encoding === null || input.source[encoding.end] !== ")") continue;
    const normalized = encoding.value.toLowerCase();
    if (normalized === "base64") {
      add(decodeBase64(value.value), "base64", match.index, encoding.end + 1);
    } else if (normalized === "hex") {
      add(decodeHex(value.value), "hex", match.index, encoding.end + 1);
    }
  }

  const charCodePattern =
    /\bString\s*\.\s*from(CharCode|CodePoint)\s*\(([^()]*)\)/gu;
  for (const match of input.source.matchAll(charCodePattern)) {
    if (outputs.length >= input.maxOutputs) break;
    const rawArguments = match[2] ?? "";
    const tokens = rawArguments.split(",").map((value) => value.trim());
    if (
      tokens.length === 0 ||
      tokens.some((value) => !/^(?:0[xX][0-9a-f]+|\d+)$/u.test(value))
    )
      continue;
    const values = tokens.map((value) => Number(value));
    if (
      values.some(
        (value) =>
          !Number.isSafeInteger(value) ||
          value < 0 ||
          value > (match[1] === "CodePoint" ? 0x10ffff : 0xffff),
      )
    )
      continue;
    try {
      const decoded =
        match[1] === "CodePoint"
          ? String.fromCodePoint(...values)
          : String.fromCharCode(...values);
      add(decoded, "char-code", match.index, match.index + match[0].length);
    } catch {
      // Invalid numeric sequences are deliberately ignored.
    }
  }

  for (let offset = 0; offset < input.source.length; offset += 1) {
    if (outputs.length >= input.maxOutputs) break;
    if (input.source[offset] !== '"' && input.source[offset] !== "'") continue;
    const expression = parseLiteralExpression(input.source, offset);
    if (expression === null) continue;
    if (expression.escaped) {
      const raw = input.source.slice(offset, expression.end);
      if (/\\(?:x[0-9a-f]{2}|u(?:[0-9a-f]{4}|\{[0-9a-f]{1,6}\}))/iu.test(raw))
        add(expression.value, "hex", offset, expression.end);
    }
    if (expression.literals > 1)
      add(expression.value, "literal-concat", offset, expression.end);
    offset = Math.max(offset, expression.end - 1);
  }

  return outputs;
}

const COMMON_BASES = ["password", "qwerty", "letmein", "admin", "iloveyou", "123456", "abcdef"];

function asciiLowercase(value: string): string {
  return value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}

function isAsciiDigitOrPunctuation(value: string): boolean {
  return Array.from(value).every((character) => {
    const code = character.charCodeAt(0);
    return (code >= 0x21 && code <= 0x7e) && !/[A-Za-z]/.test(character);
  });
}

export function hasObviousMasterPasswordPattern(value: string): boolean {
  const compact = asciiLowercase(value.normalize("NFC")).replace(/\p{White_Space}/gu, "");
  if (compact === "correcthorsebatterystaple" || COMMON_BASES.some((base) => {
    if (!compact.startsWith(base)) return false;
    const tail = compact.slice(base.length);
    return tail.length <= 16 && isAsciiDigitOrPunctuation(tail);
  })) return true;

  const chars = Array.from(compact);
  if (chars.length === 0) return true;
  let longestRun = 1;
  let currentRun = 1;
  for (let index = 1; index < chars.length; index += 1) {
    currentRun = chars[index] === chars[index - 1] ? currentRun + 1 : 1;
    longestRun = Math.max(longestRun, currentRun);
  }
  if (longestRun >= 8 && longestRun >= Math.ceil(chars.length / 2)) return true;

  for (let period = 1; period <= Math.min(4, Math.floor(chars.length / 3)); period += 1) {
    let mismatches = 0;
    for (let index = 0; index < chars.length; index += 1) {
      if (chars[index] !== chars[index % period]) mismatches += 1;
    }
    if (mismatches <= Math.max(3, Math.floor(chars.length / 4))) return true;
  }

  const bytes = Array.from(compact).map((character) => character.charCodeAt(0));
  const allDigits = /^[0-9]+$/.test(compact);
  const allLetters = /^[a-z]+$/.test(compact);
  return (allDigits || allLetters) && bytes.slice(1).every((next, index) => {
    const previous = bytes[index]!;
    if (allDigits) {
      return (previous - 48 + 1) % 10 === next - 48
        || (previous - 48 + 9) % 10 === next - 48;
    }
    return next === previous + 1 || next === previous - 1;
  });
}

export function estimateMasterPassword(value: string): { label: string; level: string } {
  if (!value) return { label: "尚未输入", level: "empty" };
  const length = Array.from(value.normalize("NFC")).length;
  if (length < 12) return { label: "长度不足", level: "0" };
  if (hasObviousMasterPasswordPattern(value)) return { label: "模式过于可预测", level: "0" };
  const wordCount = value.split(/\p{White_Space}+/u).filter(Boolean).length;
  if (wordCount >= 5 && length >= 20) return { label: "长词组 · 请确认词语随机", level: "4" };
  if (length >= 24) return { label: "长度较充足", level: "4" };
  if (length >= 18) return { label: "长度良好", level: "3" };
  if (length >= 15) return { label: "建议再增加长度", level: "2" };
  return { label: "仅达到最低长度", level: "1" };
}

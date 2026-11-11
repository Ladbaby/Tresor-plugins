"use strict";
// String predicates the finders share. Every helper here is a pure function of
// its arguments: nothing is cached and nothing is stateful.

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TOKEN_CH = ALNUM + "_-";
const DIGITS = "0123456789";

function isDigit(c) {
  return c >= "0" && c <= "9";
}
function isLower(c) {
  return c >= "a" && c <= "z";
}
function isUpper(c) {
  return c >= "A" && c <= "Z";
}
function isLetter(c) {
  return isLower(c) || isUpper(c);
}
// A byte of a word: what may not touch a value on either side for it to be a
// value of its own.
function isWordByte(c) {
  return c === "_" || isLower(c) || isUpper(c) || isDigit(c);
}
function hexOrHyphen(c) {
  return c === "-" || isDigit(c) || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
}
function hasCJK(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x4e00 && c <= 0x9fff) {
      return true;
    }
  }
  return false;
}
// A character index into `s` is a code unit index, exactly as a RegExp match
// reports it, so slices taken here and offsets compared against a match are
// the same unit. `charAt` returning "" past the end is what the callers rely
// on: it is neither a word byte nor a digit.
function charAt(s, i) {
  return i >= 0 && i < s.length ? s[i] : "";
}
function trimRight(s, chars) {
  let end = s.length;
  while (end > 0 && chars.indexOf(s[end - 1]) >= 0) {
    end--;
  }
  return s.slice(0, end);
}
function trimLeft(s, chars) {
  let i = 0;
  while (i < s.length && chars.indexOf(s[i]) >= 0) {
    i++;
  }
  return s.slice(i);
}
function trim(s, chars) {
  return trimLeft(trimRight(s, chars), chars);
}
function containsAny(s, subs) {
  for (const sub of subs) {
    if (s.indexOf(sub) >= 0) {
      return true;
    }
  }
  return false;
}
// The text between two offsets, or "" where the range is not inside it. A
// finder narrows a match before taking the value, so every read goes through
// this rather than slicing blind.
function slice(s, a, b) {
  return a >= 0 && b >= a && b <= s.length ? s.slice(a, b) : "";
}

const EXPORTS = {
  ALNUM: ALNUM,
  TOKEN_CH: TOKEN_CH,
  DIGITS: DIGITS,
  isDigit: isDigit,
  isLower: isLower,
  isUpper: isUpper,
  isLetter: isLetter,
  isWordByte: isWordByte,
  hexOrHyphen: hexOrHyphen,
  hasCJK: hasCJK,
  charAt: charAt,
  trim: trim,
  trimLeft: trimLeft,
  trimRight: trimRight,
  containsAny: containsAny,
  slice: slice,
};

module.exports = EXPORTS;

/* ml-core.js — a tiny, self-contained inference engine shared across the projects.
 *
 * Models are trained offline (scikit-learn) and shipped as a small model.json of learned
 * weights; this runs the forward pass in plain JS in the browser. No API key, no server,
 * no network, works offline. Mirrors scikit-learn's TfidfVectorizer(analyzer='char') +
 * LogisticRegression exactly, so the probabilities match the trained model.
 *
 * Exposes window.MLCore = { normalize, charTfidf, predictProba, loadModel }.
 */
(function (global) {
  'use strict';

  const ZERO_WIDTH = /[​‌‍⁠﻿]/g;
  const SPACED = /\b(?:\w ){4,}\w\b/g;              // "i g n o r e", spaced to dodge word matching
  const B64 = /[A-Za-z0-9+/]{24,}={0,2}/g;

  function b64decode(blob) {
    try {
      const padded = blob + '='.repeat((4 - (blob.length % 4)) % 4);
      const bin = atob(padded);
      // to UTF-8 string
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const txt = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return /^[\x20-\x7e\s]*$/.test(txt) ? txt : null;   // printable only
    } catch (e) { return null; }
  }

  // Port of doorman/guard.py normalize(): what the text says once the usual disguises are gone.
  function normalize(text) {
    let t = (text || '').normalize('NFKC').replace(ZERO_WIDTH, '');
    t = t.replace(SPACED, (m) => m.replace(/ /g, ''));
    const stripped = t.replace(/\s+/g, '');
    const decoded = [];
    let m;
    B64.lastIndex = 0;
    while ((m = B64.exec(stripped)) !== null) {
      const plain = b64decode(m[0]);
      if (plain) decoded.push(plain);
    }
    return [t, ...decoded].join(' ').replace(/\s+/g, ' ').trim().toLowerCase();
  }

  // char n-gram counts over the whole string (matches sklearn analyzer='char')
  function charCounts(s, nmin, nmax) {
    const counts = new Map();
    for (let n = nmin; n <= nmax; n++) {
      for (let i = 0; i + n <= s.length; i++) {
        const g = s.slice(i, i + n);
        counts.set(g, (counts.get(g) || 0) + 1);
      }
    }
    return counts;
  }

  // sklearn TfidfVectorizer(norm='l2', sublinear_tf=False): tf*idf over vocab, then L2-normalise
  function charTfidf(normText, model) {
    const [nmin, nmax] = model.ngram;
    const counts = charCounts(normText, nmin, nmax);
    const idx = [], val = [];
    let ss = 0;
    counts.forEach((tf, g) => {
      const j = model.vocab[g];
      if (j !== undefined) { const v = tf * model.idf[j]; idx.push(j); val.push(v); ss += v * v; }
    });
    const norm = Math.sqrt(ss) || 1;
    for (let k = 0; k < val.length; k++) val[k] /= norm;
    return { idx, val };
  }

  // probability of the positive class for a char_tfidf_logreg model
  function predictProba(text, model) {
    const { idx, val } = charTfidf(normalize(text), model);
    let z = model.intercept;
    for (let k = 0; k < idx.length; k++) z += val[k] * model.coef[idx[k]];
    return 1 / (1 + Math.exp(-z));
  }

  async function loadModel(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('model load failed: ' + r.status);
    return r.json();
  }

  global.MLCore = { normalize, charTfidf, predictProba, loadModel };
})(typeof window !== 'undefined' ? window : globalThis);

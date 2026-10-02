/* Doorman's input guard, running live in the browser.
 * normalize() + the regex rules are ported verbatim from doorman/guard.py; the character
 * n-gram model (guard-model.json) is trained offline and run by ml-core.js. The guard flags
 * text that tries to instruct the agent — but, as the project measures, a classifier is a
 * triage signal, not a control: a reworded attack can still slip past it.
 */
(() => {
  'use strict';
  // Rules ported from doorman/guard.py (run on the normalised text)
  const RULES = [
    ['ignore-instructions', /\b(ignore|disregard|forget|override|ignorez|oubliez)\b.{0,40}\b(instructions?|rules|prompt|directions|consignes)\b/i],
    ['addressed-to-an-ai', /\b(note|message|instructions?)\s+(to|for)\s+(the\s+|any\s+)?(ai|llm|chatgpt|gpt|language model)\b/i],
    ['role-override', /\b(system prompt|you are now|new instructions|developer mode|jailbreak)\b/i],
    ['decode-and-follow', /\bdecode\b.{0,60}\b(follow|carry (it|them) out|execute|run|obey)\b/i],
  ];
  const THRESHOLD = 0.45; // benign train lines score ~0.09; injections ~0.5+

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const ready = (fn) => (document.readyState !== 'loading' ? fn() : document.addEventListener('DOMContentLoaded', fn));

  ready(async () => {
    const inEl = document.getElementById('g-in');
    const outEl = document.getElementById('g-out');
    if (!inEl || !outEl || !window.MLCore) return;
    let model = null;
    try { model = await MLCore.loadModel('guard-model.json'); }
    catch (e) { /* rules still work without the model */ }

    function run(text) {
      if (!text.trim()) { outEl.innerHTML = '<p class="g-empty">Type or paste something above to see what the guard does with it.</p>'; return; }
      const norm = MLCore.normalize(text);
      const fired = RULES.filter(([, re]) => re.test(norm)).map(([n]) => n);
      const proba = model ? MLCore.predictProba(text, model) : null;
      const flagged = fired.length > 0 || (proba !== null && proba >= THRESHOLD);
      const disguised = norm !== text.trim().toLowerCase().replace(/\s+/g, ' ');

      let html = `<div class="g-verdict ${flagged ? 'bad' : 'good'}">${flagged ? '⚑ Flagged — sent to a human' : '✓ Looks clean — allowed through'}</div>`;
      if (disguised) html += `<div class="g-row"><span class="g-k">After stripping disguises</span><code class="g-norm">${esc(norm.slice(0, 240))}</code></div>`;
      html += `<div class="g-row"><span class="g-k">Rules triggered</span>${fired.length ? fired.map((f) => `<span class="g-chip bad">${f}</span>`).join('') : '<span class="g-chip">none</span>'}</div>`;
      if (proba !== null) {
        const pct = Math.round(proba * 100);
        html += `<div class="g-row"><span class="g-k">Model: chance it is an instruction</span>`
          + `<span class="g-bar"><span class="g-fill ${proba >= THRESHOLD ? 'bad' : 'good'}" style="width:${pct}%"></span></span>`
          + `<b class="g-pct">${pct}%</b></div>`;
      }
      html += `<p class="g-note">The guard combines disguise-stripping, the hand-written rules and the trained model. It is triage, not a control: a reworded attack can still pass — which is why Doorman's real defence is isolating what the agent reads from what it can do.</p>`;
      outEl.innerHTML = html;
    }

    let t;
    inEl.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => run(inEl.value), 120); });
    document.querySelectorAll('[data-g-example]').forEach((b) =>
      b.addEventListener('click', () => { inEl.value = b.getAttribute('data-g-example'); run(inEl.value); inEl.focus(); }));
    run('');
  });
})();

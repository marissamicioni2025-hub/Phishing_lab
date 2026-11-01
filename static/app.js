/* All sample content uses textContent; never interpret email HTML or create URL links. */
'use strict';
let emails = [], selected = null, dirty = false;
const $ = (selector, root = document) => root.querySelector(selector);
const announce = text => { $('#message').textContent = text; };
async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function renderQueue() {
  const counts = label => emails.filter(e => e.risk === label).length;
  const metrics = $('#metrics'); metrics.replaceChildren();
  const investigating = emails.filter(e => e.status === 'Investigating').length;
  const closed = emails.filter(e => e.status === 'Closed').length;
  for (const [label, count] of [['Total emails', emails.length], ['Low risk', counts('Low')], ['Medium risk', counts('Medium')], ['High risk', counts('High')], ['Investigating', investigating], ['Closed', closed]]) {
    const card = document.createElement('div'); card.className = 'metric';
    const value = document.createElement('strong'); value.textContent = count;
    const caption = document.createElement('span'); caption.textContent = label;
    card.append(value, caption); metrics.append(card);
  }
  $('#case-count').textContent = `${emails.length} cases · ${emails.filter(e => e.status === 'New').length} new`;
  const queue = $('#cases'); queue.replaceChildren();
  for (const email of emails.filter(e => $('#filter').value === 'All' || e.risk === $('#filter').value)) {
    const button = document.createElement('button'); button.className = 'case' + (selected === email.id ? ' active' : '');
    button.setAttribute('aria-pressed', String(selected === email.id));
    const top = document.createElement('span'); top.className = 'case-top';
    const id = document.createElement('span'); id.textContent = email.id.toUpperCase();
    const badge = document.createElement('span'); badge.className = `badge ${email.risk.toLowerCase()}`; badge.textContent = `${email.risk} · ${email.score}`;
    top.append(id, badge);
    const subject = document.createElement('strong'); subject.textContent = email.subject;
    const meta = document.createElement('span'); meta.className = 'muted small'; meta.textContent = `${email.difficulty} · ${email.status}`;
    button.append(top, subject, meta);
    button.addEventListener('click', () => openCase(email.id)); queue.append(button);
  }
}
function list(root, name, values) {
  const target = $(`[data-field="${name}"]`, root); target.replaceChildren();
  for (const value of values) { const li = document.createElement('li'); li.textContent = value; target.append(li); }
}
async function openCase(id) {
  if (dirty && !window.confirm('Discard unsaved investigation notes?')) return;
  try {
    const {email, analysis, investigation} = await api(`/api/emails/${id}`);
    selected = id; dirty = false;
    const root = $('#detail-template').content.cloneNode(true);
    const field = name => $(`[data-field="${name}"]`, root);
    for (const name of ['subject', 'display_name', 'from_address', 'reply_to', 'body', 'scenario']) field(name).textContent = email[name];
    field('case-label').textContent = `${id.toUpperCase()} / ${email.difficulty} / SYNTHETIC`;
    field('risk').textContent = `${analysis.risk} risk`; field('risk').classList.add(analysis.risk.toLowerCase());
    field('authentication').textContent = Object.entries(email.authentication).map(([k,v]) => `${k.toUpperCase()}: ${v}`).join(' · ');
    field('authentication_note').textContent = analysis.authentication_note;
    field('score').textContent = `${analysis.score} / 100`; field('meter').value = analysis.score;
    list(root, 'urls', email.urls.length ? email.urls : ['No URLs in this message.']);
    list(root, 'findings', analysis.findings.length ? analysis.findings.map(f => `+${f.weight} · ${f.rule}: ${f.explanation}`) : ['No configured rule matched. This does not establish that the email is safe.']);
    list(root, 'actions', analysis.actions);
    const iocs = Object.entries(analysis.iocs).map(([k,v]) => `${k.replaceAll('_',' ').toUpperCase()}\n${v.join('\n') || '(none)'}`).join('\n\n');
    field('iocs').textContent = iocs;
    $('[data-action="copy"]', root).addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(iocs); announce('IOCs copied. Treat them as inert evidence.'); }
      catch { announce('Clipboard unavailable. Select and copy the IOC text manually.'); }
    });
    const form = $('#notes-form', root);
    form.elements.status.value = investigation.status; form.elements.notes.value = investigation.notes;
    field('updated_at').textContent = `Updated: ${investigation.updated_at}`;
    for (const format of ['json', 'txt']) field(`export-${format}`).href = `/api/emails/${id}/export?format=${format}`;
    form.addEventListener('input', () => { dirty = true; });
    form.addEventListener('submit', async event => {
      event.preventDefault(); const button = $('button[type="submit"]', form); button.disabled = true;
      try {
        const saved = await api(`/api/emails/${id}/investigation`, {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token':$('meta[name="csrf-token"]').content}, body:JSON.stringify({status:form.elements.status.value, notes:form.elements.notes.value})});
        dirty = false; $('[data-field="updated_at"]').textContent = `Updated: ${saved.updated_at}`;
        emails = await api('/api/emails'); renderQueue(); announce('Investigation saved. Exports now include these notes.');
      } catch(error) { announce(error.message); } finally { button.disabled = false; }
    });
    $('#detail').replaceChildren(root); renderQueue(); announce(`Opened ${id}.`);
  } catch(error) { announce(error.message); }
}
$('#filter').addEventListener('change', renderQueue);
window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
(async () => { try { emails = await api('/api/emails'); renderQueue(); if (emails.length) await openCase(emails[0].id); } catch(error) { announce(error.message); } })();

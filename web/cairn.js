/*
  Cairn, the site.

  No framework and no build step. What is served is what was written, which
  matters more here than convenience: anyone can read this file and check that
  the page does what it says, and that it never touches a key.

  Amounts arrive from the API as decimal strings and are handled as BigInt.
  A pebble count runs past what a double holds exactly, and money that is
  quietly rounded in the last digits is the kind of wrong nobody notices.
*/

'use strict';

const PEBBLES_PER_CAIRN = 100000000n;
const LEVELS = ['plain', 'curious', 'technical'];
const STORE_LEVEL = 'cairn.level';
const STORE_LANGUAGE = 'cairn.language';
const TICKER_PERIOD = 5000;

const state = {
  level: 'curious',
  language: 'en',
  strings: {},
  fallback: {},
  languages: [{ code: 'en', name: 'English' }],
  status: null,
  timers: [],
};

/* ---------- storage, which may be refused ---------- */

function remember(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch (error) {
    /* A private window or blocked site data. The page works without it. */
  }
}

function recall(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (error) {
    return null;
  }
}

/* ---------- text ---------- */

/*
  Resolves a dotted key against the translation file.

  A translator may nest or flatten as reads best in their language, so at each
  step the longest remaining key that exists wins. That lets tier.hot be a
  short label and tier.hot.name a longer one, in the same object.
*/
function lookup(strings, path) {
  const parts = path.split('.');
  let node = strings;
  let index = 0;
  while (index < parts.length) {
    if (!node || typeof node !== 'object') return undefined;
    let matched = false;
    for (let take = parts.length - index; take >= 1; take -= 1) {
      const key = parts.slice(index, index + take).join('.');
      if (Object.prototype.hasOwnProperty.call(node, key)) {
        node = node[key];
        index += take;
        matched = true;
        break;
      }
    }
    if (!matched) return undefined;
  }
  return node;
}

/*
  Resolves one key at the current reading level.

  A value can be a plain string, or an object keyed by level. When a level is
  missing the next simpler one answers, so a translation that has only started
  still renders a page instead of a wall of key names.
*/
function t(path, replacements) {
  let value = lookup(state.strings, path);
  if (value === undefined) value = lookup(state.fallback, path);
  if (value === undefined) return path;

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const order = LEVELS.slice(0, LEVELS.indexOf(state.level) + 1).reverse();
    let chosen;
    for (const level of order) {
      if (typeof value[level] === 'string' || Array.isArray(value[level])) {
        chosen = value[level];
        break;
      }
    }
    if (chosen === undefined) chosen = value.plain || value.curious || value.technical;
    value = chosen;
  }
  if (value === undefined) return path;

  if (replacements) {
    const apply = (text) =>
      text.replace(/\{(\w+)\}/g, (whole, name) =>
        Object.prototype.hasOwnProperty.call(replacements, name) ? String(replacements[name]) : whole
      );
    return Array.isArray(value) ? value.map(apply) : apply(value);
  }
  return value;
}

/* Paragraphs for a key, whether it holds one string or several. */
function paragraphs(path, replacements) {
  const value = t(path, replacements);
  if (Array.isArray(value)) return value;
  return typeof value === 'string' ? [value] : [];
}

/* ---------- formatting ---------- */

function locale() {
  return state.language === 'en' ? 'en' : state.language;
}

function count(value) {
  const number = typeof value === 'bigint' ? value : Number(value);
  if (!Number.isFinite(Number(number)) && typeof number !== 'bigint') return '-';
  return new Intl.NumberFormat(locale()).format(number);
}

/*
  The decimal separator this language uses.

  Read from the locale rather than assumed: a French reader writing 0,05 and
  reading 0.05 has to stop and work out which one they are looking at, and a
  page about money should never make anyone do that.
*/
function decimalSeparator() {
  const parts = new Intl.NumberFormat(locale()).formatToParts(1.1);
  const decimal = parts.find((part) => part.type === 'decimal');
  return decimal ? decimal.value : '.';
}

/* A pebble string rendered as CAIRN, trailing zeros trimmed. */
function cairn(pebbles) {
  let value;
  try {
    value = BigInt(pebbles);
  } catch (error) {
    return '-';
  }
  const negative = value < 0n;
  if (negative) value = -value;
  const whole = value / PEBBLES_PER_CAIRN;
  const fraction = (value % PEBBLES_PER_CAIRN).toString().padStart(8, '0').replace(/0+$/, '');
  const text = count(whole) + (fraction ? decimalSeparator() + fraction : '');
  return (negative ? '-' : '') + text;
}

function bytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size)) return '-';
  if (size < 1024) return count(size) + ' B';
  if (size < 1024 * 1024) return (size / 1024).toFixed(size < 10240 ? 1 : 0) + ' kB';
  if (size < 1024 * 1024 * 1024) return (size / 1048576).toFixed(size < 10485760 ? 1 : 0) + ' MB';
  return (size / 1073741824).toFixed(2) + ' GB';
}

function moment(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return '-';
  return new Intl.DateTimeFormat(locale(), {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value * 1000));
}

function ago(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return '';
  const elapsed = Math.round(Date.now() / 1000) - value;
  const format = new Intl.RelativeTimeFormat(locale(), { numeric: 'auto' });
  const steps = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [2592000, 'day', 86400],
    [31536000, 'month', 2592000],
    [Infinity, 'year', 31536000],
  ];
  const size = Math.abs(elapsed);
  for (const [limit, unit, divisor] of steps) {
    if (size < limit) return format.format(-Math.round(elapsed / divisor), unit);
  }
  return '';
}

function duration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value)) return '-';
  if (value < 120) return t('unit.seconds', { n: count(value) });
  if (value < 7200) return t('unit.minutes', { n: count(Math.round(value / 60)) });
  if (value < 172800) return t('unit.hours', { n: count(Math.round(value / 3600)) });
  if (value < 63072000) return t('unit.days', { n: count(Math.round(value / 86400)) });
  return t('unit.years', { n: (value / 31536000).toFixed(1) });
}

function shorten(text, head = 10, tail = 6) {
  if (typeof text !== 'string' || text.length <= head + tail + 1) return text || '';
  return text.slice(0, head) + '…' + text.slice(-tail);
}

/* ---------- DOM ---------- */

function el(tag, attributes, ...children) {
  const node = document.createElement(tag);
  if (attributes) {
    for (const [name, value] of Object.entries(attributes)) {
      if (value === null || value === undefined || value === false) continue;
      if (name === 'class') node.className = value;
      else if (name === 'text') node.textContent = value;
      else if (name === 'html') throw new Error('markup is never built from data');
      else if (name.startsWith('on')) node.addEventListener(name.slice(2), value);
      else if (name === 'variable') node.style.setProperty(value[0], value[1]);
      else node.setAttribute(name, value === true ? '' : value);
    }
  }
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/*
  A hash, with its leading zeros picked out.

  Those zeros are the work: they are what a miner spent time to find, and the
  only visible trace of it on the page.
*/
function hashLink(value, href, options = {}) {
  const text = shorten(String(value), options.head ?? 12, options.tail ?? 8);
  const zeros = /^0+/.exec(text);
  const node = href ? el('a', { class: 'hash', href, 'data-link': true }) : el('span', { class: 'hash' });
  node.title = String(value);
  if (zeros) {
    node.append(el('span', { class: 'lead', text: zeros[0] }), document.createTextNode(text.slice(zeros[0].length)));
  } else {
    node.textContent = text;
  }
  return node;
}

function tierChip(tier) {
  if (!tier) return null;
  return el('span', { class: 'chip ' + tier, text: t('tier.' + tier) });
}

function row(label, ...value) {
  return el('div', { class: 'row' }, el('div', { class: 'row-label', text: label }), el('div', { class: 'row-value' }, value));
}

function stat(label, value, note) {
  return el(
    'div',
    { class: 'stat' },
    el('div', { class: 'stat-label', text: label }),
    el('div', { class: 'stat-value' }, value),
    note ? el('div', { class: 'stat-note', text: note }) : null
  );
}

function prose(key, replacements) {
  return el('div', { class: 'prose' }, paragraphs(key, replacements).map((text) => el('p', { text })));
}

/*
  The explanation that sits alongside a page of data.

  It is not decoration. Someone landing on a block from a link they were sent
  should be able to find out what a block is without leaving the page.
*/
function explainer(key, replacements) {
  const body = paragraphs(key, replacements);
  if (!body.length) return null;
  return el('div', { class: 'note-aside' }, body.map((text) => el('p', { text })));
}

function panel(title, ...children) {
  const head = title ? el('div', { class: 'panel-head' }, el('h2', { text: title })) : null;
  return el('section', { class: 'panel' }, head, children);
}

function table(headers, rows) {
  if (!rows.length) return el('div', { class: 'empty', text: t('common.nothing') });
  return el(
    'div',
    { class: 'scroller' },
    el(
      'table',
      null,
      el(
        'thead',
        null,
        el('tr', null, headers.map((header) => el('th', { class: header.numeric ? 'numeric' : null, text: header.label })))
      ),
      el('tbody', null, rows)
    )
  );
}

function cell(content, options = {}) {
  return el('td', { class: [options.mono ? 'mono' : '', options.numeric ? 'numeric' : ''].filter(Boolean).join(' ') || null }, content);
}

/* ---------- the API ---------- */

async function api(path) {
  const response = await fetch('/api/' + path, { headers: { accept: 'application/json' } });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error((body && body.error) || 'request failed');
    error.status = response.status;
    throw error;
  }
  return body;
}

/* ---------- views ---------- */

const view = document.getElementById('view');

function showLoading() {
  clear(view);
  view.append(el('div', { class: 'loading', text: t('common.loading') }));
}

function showError(error) {
  clear(view);
  view.append(
    panel(
      t('error.title'),
      el('div', { class: 'prose' }, el('p', { text: error && error.status === 404 ? t('error.missing') : t('error.unreachable') })),
      el('p', { class: 'small dim', text: String((error && error.message) || error) })
    )
  );
}

async function home() {
  const status = await api('status');
  state.status = status;
  const recent = await api('blocks?limit=10');

  clear(view);
  const hotShare = status.hot.capacity ? Math.min(100, (status.hot.notes / status.hot.capacity) * 100) : 0;

  view.append(
    el('div', { class: 'stack' }, [
      el('div', { class: 'hero-grid' },
      el(
        'section',
        { class: 'hero' },
        el('p', { class: 'eyebrow', text: t('home.eyebrow', { network: status.network.name }) }),
        heroTitle(),
        prose('home.lede'),
        el(
          'div',
          { class: 'hero-actions' },
          el('a', { class: 'action primary', href: '/learn', 'data-link': true, text: t('home.action.learn') }),
          el('a', { class: 'action', href: '/blocks', 'data-link': true, text: t('home.action.explore') }),
          el('a', { class: 'action', href: '/download', 'data-link': true, text: t('home.action.run') })
        )
      ),

      el(
        'div',
        { class: 'stats' },
        stat(t('stat.height'), count(status.tip ? status.tip.height : 0), status.tip ? ago(status.tip.timestamp) : ''),
        stat(t('stat.difficulty'), count(BigInt(status.tip ? status.tip.difficulty : '0'))),
        stat(t('stat.supply'), cairn(status.supply.issued) + ' CAIRN', t('stat.supply.note', { reward: cairn(status.supply.nextReward) })),
        stat(t('stat.holders'), count(status.chain.holders)),
        stat(t('stat.pool'), count(status.pool), t('stat.pool.note')),
        stat(t('stat.peers'), count(status.peers))
      )
      ),

      panel(
        t('home.cost.title'),
        prose('home.cost.body', {
          megabytes: bytes(Number(status.hot.bytesAtCapacity)),
          capacity: count(status.hot.capacity),
        }),
        el(
          'div',
          { class: 'tiers' },
          el(
            'div',
            { class: 'tier' },
            el(
              'div',
              { class: 'tier-line' },
              el('span', { class: 'tier-name', text: t('tier.hot.name') }),
              el('span', {
                class: 'tier-figure',
                text: count(status.hot.notes) + ' / ' + count(status.hot.capacity),
              })
            ),
            el('div', { class: 'tier-bar', variable: ['--fill', hotShare.toFixed(2) + '%'] }),
            el('p', { class: 'small dim', text: t('tier.hot.note', { size: bytes(Number(status.hot.bytesAtCapacity)) }) })
          ),
          el(
            'div',
            { class: 'tier cold' },
            el(
              'div',
              { class: 'tier-line' },
              el('span', { class: 'tier-name', text: t('tier.cold.name') }),
              el('span', { class: 'tier-figure', text: count(BigInt(status.cold.notes)) })
            ),
            el('div', { class: 'tier-bar cold' }),
            el('p', { class: 'small dim', text: t('tier.cold.note', { roots: status.cold.roots }) })
          )
        )
      ),

      panel(
        t('home.recent.title'),
        explainer('explain.blocks'),
        blocksTable(recent.blocks),
        el('div', { class: 'more' }, el('a', { class: 'action', href: '/blocks', 'data-link': true, text: t('common.seeAll') }))
      ),
    ])
  );
}

/* The one sentence the whole project is about, with its emphasis intact. */
function heroTitle() {
  const heading = el('h1');
  const parts = t('home.title').split('|');
  parts.forEach((part, index) => {
    heading.append(index % 2 ? el('em', { text: part }) : document.createTextNode(part));
  });
  return heading;
}

function blocksTable(blocks) {
  return table(
    [
      { label: t('field.height') },
      { label: t('field.block') },
      { label: t('field.age') },
      { label: t('field.transfers'), numeric: true },
      { label: t('field.paid.column'), numeric: true },
      { label: t('field.size'), numeric: true },
    ],
    blocks.map((block) =>
      el(
        'tr',
        null,
        cell(el('a', { class: 'hash', href: '/block/' + block.height, 'data-link': true, text: count(block.height) })),
        cell(hashLink(block.id, '/block/' + block.height)),
        cell(el('span', { class: 'dim', text: ago(block.timestamp) })),
        cell(count(block.transfers), { numeric: true }),
        cell(cairn(block.paidToMiner), { numeric: true, mono: true }),
        cell(bytes(block.size), { numeric: true })
      )
    )
  );
}

async function blocks(parameters) {
  const from = parameters.get('from');
  const page = await api('blocks?limit=25' + (from ? '&from=' + encodeURIComponent(from) : ''));
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      panel(t('blocks.title'), explainer('explain.blocks'), blocksTable(page.blocks),
        page.next !== null && page.next !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: '/blocks?from=' + page.next, 'data-link': true, text: t('common.older') }))
          : null
      )
    )
  );
}

async function block(reference) {
  const data = await api('block/' + encodeURIComponent(reference));
  clear(view);

  const rows = el(
    'div',
    { class: 'rows' },
    row(t('field.block'), hashLink(data.id, null, { head: 64, tail: 0 })),
    row(t('field.time'), moment(data.timestamp), el('span', { class: 'row-note', text: ' ' + ago(data.timestamp) })),
    row(t('field.confirmations'), count(data.confirmations)),
    row(t('field.difficulty'), count(BigInt(data.difficulty))),
    row(t('field.work'), count(BigInt(data.work))),
    row(t('field.nonce'), count(BigInt(data.nonce))),
    row(t('field.previous'), data.height > 0 ? hashLink(data.previous, '/block/' + (data.height - 1)) : t('field.none')),
    row(t('field.next'), data.next ? hashLink(data.next, '/block/' + (data.height + 1)) : t('field.pending')),
    row(t('field.size'), bytes(data.size)),
    row(t('field.reward'), cairn(data.reward) + ' CAIRN'),
    row(t('field.fees'), cairn(data.fees) + ' CAIRN'),
    el(
      'div',
      { class: 'row lv-technical' },
      el('div', { class: 'row-label', text: t('field.stateRoot') }),
      el('div', { class: 'row-value' }, hashLink(data.stateRoot, null, { head: 64, tail: 0 }))
    ),
    el(
      'div',
      { class: 'row lv-technical' },
      el('div', { class: 'row-label', text: t('field.transactionsRoot') }),
      el('div', { class: 'row-value' }, hashLink(data.transactionsRoot, null, { head: 64, tail: 0 }))
    )
  );

  const coinbase = data.coinbase;
  const coinbasePanel = panel(
    t('block.coinbase.title'),
    explainer('explain.coinbase'),
    el(
      'div',
      { class: 'rows' },
      row(t('field.transaction'), hashLink(coinbase.id, '/tx/' + coinbase.id)),
      row(t('field.paid'), cairn(coinbase.total) + ' CAIRN'),
      coinbase.extraText ? row(t('field.message'), el('span', { text: coinbase.extraText })) : null,
      coinbase.extra && !coinbase.extraText ? row(t('field.extra'), el('span', { class: 'hash', text: coinbase.extra })) : null
    ),
    outputsTable(coinbase.outputs)
  );

  view.append(
    el(
      'div',
      { class: 'stack' },
      el(
        'section',
        null,
        el('p', { class: 'eyebrow', text: t('block.eyebrow') }),
        el('h1', { text: t('block.title', { height: count(data.height) }) })
      ),
      panel(null, explainer('explain.block'), rows),
      coinbasePanel,
      panel(
        t('block.transfers.title', { n: count(data.transfers.length) }),
        explainer('explain.transfers'),
        data.transfers.length ? el('div', { class: 'stack' }, data.transfers.map((transfer) => transferCard(transfer))) : el('div', { class: 'empty', text: t('block.transfers.none') })
      )
    )
  );
}

function outputsTable(outputs) {
  return table(
    [
      { label: '#', numeric: false },
      { label: t('field.owner') },
      { label: t('field.value'), numeric: true },
      { label: t('field.state') },
    ],
    outputs.map((output) =>
      el(
        'tr',
        null,
        cell(el('a', { class: 'hash', href: '/note/' + output.note, 'data-link': true, text: String(output.index) })),
        cell(hashLink(output.owner, '/address/' + output.owner)),
        cell(cairn(output.value) + ' CAIRN', { numeric: true, mono: true }),
        cell(output.spent ? el('a', { class: 'hash', href: '/tx/' + output.spentBy, 'data-link': true, text: t('tier.spent') }) : tierChip(output.tier))
      )
    )
  );
}

function transferCard(transfer) {
  const inputs = el(
    'div',
    null,
    el('p', { class: 'eyebrow', text: t('transfer.spends', { n: count(transfer.inputs.length) }) }),
    table(
      [{ label: t('field.note') }, { label: t('field.owner') }, { label: t('field.value'), numeric: true }, { label: t('field.proof') }],
      transfer.inputs.map((input) =>
        el(
          'tr',
          null,
          cell(hashLink(input.note, '/note/' + input.note, { head: 10, tail: 4 })),
          cell(input.owner ? hashLink(input.owner, '/address/' + input.owner) : el('span', { class: 'dim', text: t('field.unknown') })),
          cell(input.value ? cairn(input.value) + ' CAIRN' : '-', { numeric: true, mono: true }),
          cell(tierChip(input.witness))
        )
      )
    )
  );

  const outputs = el(
    'div',
    null,
    el('p', { class: 'eyebrow', text: t('transfer.creates', { n: count(transfer.outputs.length) }) }),
    outputsTable(transfer.outputs)
  );

  return el(
    'section',
    { class: 'panel' },
    el(
      'div',
      { class: 'panel-head' },
      hashLink(transfer.id, '/tx/' + transfer.id, { head: 18, tail: 8 }),
      el('span', { class: 'small dim', text: t('transfer.fee', { fee: cairn(transfer.fee || '0') }) })
    ),
    el('div', { class: 'split' }, inputs, outputs)
  );
}

async function transaction(id) {
  const data = await api('tx/' + encodeURIComponent(id));
  const it = data.transaction;
  clear(view);

  const rows = el(
    'div',
    { class: 'rows' },
    row(t('field.transaction'), hashLink(it.id, null, { head: 64, tail: 0 })),
    row(t('field.kind'), t('kind.' + it.kind)),
    data.pooled
      ? row(t('field.status'), el('span', { class: 'chip grace', text: t('transfer.waiting') }))
      : row(t('field.status'), el('span', { class: 'chip hot', text: t('transfer.included', { n: count(it.confirmations) }) })),
    !data.pooled && it.block ? row(t('field.block'), hashLink(it.block, '/block/' + it.height)) : null,
    !data.pooled && it.timestamp ? row(t('field.time'), moment(it.timestamp), el('span', { class: 'row-note', text: ' ' + ago(it.timestamp) })) : null,
    row(t('field.totalIn'), cairn(it.totalIn) + ' CAIRN'),
    row(t('field.totalOut'), cairn(it.totalOut) + ' CAIRN'),
    row(t('field.fee'), it.fee === null || it.fee === undefined ? t('field.none') : cairn(it.fee) + ' CAIRN'),
    row(t('field.size'), bytes(it.size)),
    it.extraText ? row(t('field.message'), el('span', { text: it.extraText })) : null
  );

  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('tx.eyebrow') }), el('h1', { text: t('tx.title') })),
      panel(null, explainer('explain.transaction'), rows),
      panel(
        t('transfer.spends', { n: count(it.inputs.length) }),
        explainer('explain.inputs'),
        it.inputs.length
          ? table(
              [{ label: t('field.note') }, { label: t('field.owner') }, { label: t('field.value'), numeric: true }, { label: t('field.proof') }],
              it.inputs.map((input) =>
                el(
                  'tr',
                  null,
                  cell(hashLink(input.note, '/note/' + input.note, { head: 10, tail: 4 })),
                  cell(input.owner ? hashLink(input.owner, '/address/' + input.owner) : el('span', { class: 'dim', text: t('field.unknown') })),
                  cell(input.value ? cairn(input.value) + ' CAIRN' : '-', { numeric: true, mono: true }),
                  cell(tierChip(input.witness))
                )
              )
            )
          : el('div', { class: 'empty', text: t('tx.noInputs') })
      ),
      panel(t('transfer.creates', { n: count(it.outputs.length) }), explainer('explain.outputs'), outputsTable(it.outputs))
    )
  );
}

async function address(owner, parameters) {
  const from = parameters.get('from');
  const data = await api('address/' + encodeURIComponent(owner) + (from ? '?from=' + encodeURIComponent(from) : ''));
  clear(view);

  view.append(
    el(
      'div',
      { class: 'stack' },
      el(
        'section',
        null,
        el('p', { class: 'eyebrow', text: t('address.eyebrow') }),
        el('h1', { class: 'hash', text: shorten(data.address, 20, 12) }),
        el('p', { class: 'small dim', text: data.address })
      ),
      explainer('explain.address') || el('div'),
      el(
        'div',
        { class: 'stats' },
        stat(t('stat.balance'), cairn(data.balance) + ' CAIRN'),
        stat(t('stat.received'), cairn(data.received) + ' CAIRN'),
        stat(t('stat.sent'), cairn(data.spent) + ' CAIRN'),
        stat(t('stat.notesHeld'), count(data.unspentNotes), t('stat.notesHeld.note', { total: count(data.notes) }))
      ),
      panel(
        t('address.holdings'),
        explainer('explain.holdings'),
        data.moreNotes
          ? el('p', { class: 'small dim', text: t('address.moreNotes', { shown: count(data.unspent.length), total: count(data.unspentNotes) }) })
          : null,
        table(
          [{ label: t('field.note') }, { label: t('field.value'), numeric: true }, { label: t('field.since'), numeric: true }, { label: t('field.state') }],
          data.unspent.map((note) =>
            el(
              'tr',
              null,
              cell(hashLink(note.note, '/note/' + note.note, { head: 12, tail: 4 })),
              cell(cairn(note.value) + ' CAIRN', { numeric: true, mono: true }),
              cell(el('a', { class: 'hash', href: '/block/' + note.createdAt, 'data-link': true, text: count(note.createdAt) }), { numeric: true }),
              cell(tierChip(note.tier))
            )
          )
        )
      ),
      panel(
        t('address.history'),
        table(
          [{ label: t('field.height'), numeric: true }, { label: t('field.direction') }, { label: t('field.value'), numeric: true }, { label: t('field.transaction') }, { label: t('field.age') }],
          data.history.map((event) =>
            el(
              'tr',
              null,
              cell(el('a', { class: 'hash', href: '/block/' + event.height, 'data-link': true, text: count(event.height) }), { numeric: true }),
              cell(el('span', { class: event.direction === 'in' ? 'in' : 'out', text: t('direction.' + event.direction) })),
              cell(cairn(event.value) + ' CAIRN', { numeric: true, mono: true }),
              cell(hashLink(event.transaction, '/tx/' + event.transaction, { head: 12, tail: 6 })),
              cell(el('span', { class: 'dim', text: ago(event.timestamp) }))
            )
          )
        ),
        data.next !== null && data.next !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: '/address/' + data.address + '?from=' + data.next, 'data-link': true, text: t('common.older') }))
          : null
      )
    )
  );
}

async function note(reference) {
  const data = await api('note/' + encodeURIComponent(reference));
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('note.eyebrow') }), el('h1', { text: t('note.title') })),
      panel(
        null,
        explainer('explain.note'),
        el(
          'div',
          { class: 'rows' },
          row(t('field.value'), cairn(data.value) + ' CAIRN'),
          row(t('field.owner'), hashLink(data.owner, '/address/' + data.owner)),
          row(t('field.state'), tierChip(data.tier), ' ', el('span', { class: 'row-note', text: t('tier.' + data.tier + '.explain') })),
          row(t('field.madeBy'), hashLink(data.source, '/tx/' + data.source)),
          row(t('field.madeAt'), el('a', { class: 'hash', href: '/block/' + data.createdAt, 'data-link': true, text: count(data.createdAt) })),
          data.spentBy ? row(t('field.spentBy'), hashLink(data.spentBy, '/tx/' + data.spentBy)) : null,
          data.spentAt !== null && data.spentAt !== undefined
            ? row(t('field.spentAt'), el('a', { class: 'hash', href: '/block/' + data.spentAt, 'data-link': true, text: count(data.spentAt) }))
            : null,
          data.position !== null && data.position !== undefined
            ? el(
                'div',
                { class: 'row lv-curious' },
                el('div', { class: 'row-label', text: t('field.position') }),
                el('div', { class: 'row-value' }, count(BigInt(data.position)), el('span', { class: 'row-note', text: ' ' + t('field.position.note') }))
              )
            : null
        )
      )
    )
  );
}

async function pool() {
  const data = await api('pool');
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('pool.eyebrow') }), el('h1', { text: t('pool.title') })),
      panel(
        null,
        explainer('explain.pool'),
        data.transfers.length ? el('div', { class: 'stack' }, data.transfers.map((transfer) => transferCard(transfer))) : el('div', { class: 'empty', text: t('pool.empty') })
      )
    )
  );
}

async function holders() {
  const data = await api('holders');
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('holders.eyebrow') }), el('h1', { text: t('holders.title') })),
      panel(
        null,
        explainer('explain.holders'),
        table(
          [{ label: '#', numeric: true }, { label: t('field.address') }, { label: t('field.balance'), numeric: true }],
          data.richest.map((holder, index) =>
            el(
              'tr',
              null,
              cell(String(index + 1), { numeric: true }),
              cell(hashLink(holder.address, '/address/' + holder.address, { head: 20, tail: 10 })),
              cell(cairn(holder.balance) + ' CAIRN', { numeric: true, mono: true })
            )
          )
        )
      )
    )
  );
}

async function rules() {
  const data = await api('params');
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('rules.eyebrow') }), el('h1', { text: t('rules.title') }), prose('rules.lede')),
      panel(
        t('rules.identity'),
        el(
          'div',
          { class: 'rows' },
          row(t('field.network'), data.network.name),
          row(t('field.networkId'), data.network.id),
          row(t('field.genesis'), data.network.genesis ? hashLink(data.network.genesis, '/block/0', { head: 64, tail: 0 }) : t('field.none')),
          row(t('field.opensAt'), moment(data.network.opensAt), el('span', { class: 'row-note', text: ' ' + t('field.opensAt.note') }))
        )
      ),
      panel(
        t('rules.money'),
        el(
          'div',
          { class: 'rows' },
          row(t('field.initialReward'), cairn(data.initialReward) + ' CAIRN'),
          row(t('field.halvingInterval'), count(data.halvingInterval), el('span', { class: 'row-note', text: ' ' + t('field.halvingInterval.note', { time: duration(data.halvingInterval * data.targetBlockTime) }) })),
          row(t('field.tailReward'), cairn(data.tailReward) + ' CAIRN', el('span', { class: 'row-note', text: ' ' + t('field.tailReward.note') })),
          row(t('field.pebble'), count(BigInt(data.pebblesPerCairn)), el('span', { class: 'row-note', text: ' ' + t('field.pebble.note') }))
        ),
        explainer('explain.emission')
      ),
      panel(
        t('rules.cost'),
        el(
          'div',
          { class: 'rows' },
          row(t('field.hotCapacity'), count(data.hotCapacity), el('span', { class: 'row-note', text: ' ' + t('field.hotCapacity.note') })),
          row(t('field.perNote'), bytes(data.bytesPerNote)),
          row(t('field.atCapacity'), bytes(data.hotCapacity * data.bytesPerNote)),
          row(t('field.coldCost'), t('field.coldCost.value'))
        ),
        explainer('explain.cost')
      ),
      panel(
        t('rules.blocks'),
        el(
          'div',
          { class: 'rows' },
          row(t('field.blockTime'), duration(data.targetBlockTime)),
          row(t('field.genesisDifficulty'), count(BigInt(data.genesisDifficulty))),
          row(t('field.maxTransfers'), count(data.maxTransfersPerBlock)),
          row(t('field.maxInputs'), count(data.maxInputsPerTransfer)),
          row(t('field.maxOutputs'), count(data.maxOutputsPerTransfer)),
          row(t('field.drift'), duration(data.maxTimestampDrift), el('span', { class: 'row-note', text: ' ' + t('field.drift.note') }))
        )
      )
    )
  );
}

function learn() {
  clear(view);
  const lessons = ['problem', 'notes', 'drawer', 'cave', 'proof', 'work', 'money', 'trust'];
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('learn.eyebrow') }), el('h1', { text: t('learn.title') }), prose('learn.lede')),
      panel(
        null,
        el(
          'div',
          { class: 'lesson' },
          lessons.map((name, index) =>
            el(
              'div',
              { class: 'lesson-item' },
              el('div', { class: 'lesson-number', text: String(index + 1).padStart(2, '0') }),
              el(
                'div',
                { class: 'lesson-body' },
                el('h3', { text: t('learn.' + name + '.title') }),
                prose('learn.' + name + '.body')
              )
            )
          )
        )
      ),
      panel(t('learn.next.title'), prose('learn.next.body'),
        el(
          'div',
          { class: 'hero-actions' },
          el('a', { class: 'action', href: '/rules', 'data-link': true, text: t('nav.rules') }),
          el('a', { class: 'action', href: '/blocks', 'data-link': true, text: t('nav.explore') }),
          el('a', { class: 'action', href: '/download', 'data-link': true, text: t('nav.run') })
        )
      )
    )
  );
}

function download() {
  clear(view);
  const network = state.status && state.status.network ? state.status.network.name : 'testnet-1';
  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('run.eyebrow') }), el('h1', { text: t('run.title') }), prose('run.lede')),
      panel(t('run.warning.title'), el('div', { class: 'note-aside' }, paragraphs('run.warning.body').map((text) => el('p', { text })))),
      panel(
        t('run.build.title'),
        prose('run.build.body'),
        el('pre', { class: 'code', text: 'git clone https://github.com/cairn-protocol/cairn\ncd cairn\ncargo build --release' })
      ),
      panel(
        t('run.node.title'),
        prose('run.node.body'),
        el('pre', { class: 'code', text: './target/release/cairnd --network ' + network })
      ),
      panel(
        t('run.wallet.title'),
        prose('run.wallet.body'),
        el('pre', { class: 'code', text: './target/release/cairn-wallet new\n./target/release/cairn-wallet address\n./target/release/cairn-wallet balance' })
      ),
      panel(
        t('run.mine.title'),
        prose('run.mine.body'),
        el('pre', { class: 'code', text: './target/release/cairnd --network ' + network + ' --mine <your address>' })
      ),
      panel(t('run.explorer.title'), prose('run.explorer.body'), el('pre', { class: 'code', text: './target/release/cairn-explorer --network ' + network }))
    )
  );
}

/* ---------- routing ---------- */

const routes = [
  [/^\/$/, () => home()],
  [/^\/blocks$/, (match, parameters) => blocks(parameters)],
  [/^\/block\/(.+)$/, (match) => block(match[1])],
  [/^\/tx\/(.+)$/, (match) => transaction(match[1])],
  [/^\/address\/(.+)$/, (match, parameters) => address(match[1], parameters)],
  [/^\/note\/(.+)$/, (match) => note(match[1])],
  [/^\/pool$/, () => pool()],
  [/^\/holders$/, () => holders()],
  [/^\/learn$/, () => learn()],
  [/^\/rules$/, () => rules()],
  [/^\/download$/, () => download()],
];

async function render() {
  const path = window.location.pathname;
  const parameters = new URLSearchParams(window.location.search);
  markCurrent(path);

  for (const [pattern, handler] of routes) {
    const match = pattern.exec(path);
    if (!match) continue;
    showLoading();
    try {
      await handler(match, parameters);
    } catch (error) {
      showError(error);
    }
    return;
  }

  clear(view);
  view.append(panel(t('error.title'), el('div', { class: 'prose' }, el('p', { text: t('error.noPage') }))));
}

function markCurrent(path) {
  for (const link of document.querySelectorAll('.links a')) {
    const target = link.getAttribute('href');
    const current = target === '/' ? path === '/' : path.startsWith(target) || (target === '/blocks' && /^\/(block|tx|address|note|pool|holders)/.test(path));
    if (current) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function go(href, replace) {
  if (replace) window.history.replaceState({}, '', href);
  else window.history.pushState({}, '', href);
  window.scrollTo(0, 0);
  render();
}

document.addEventListener('click', (event) => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const link = event.target.closest('a[data-link]');
  if (!link) return;
  const href = link.getAttribute('href');
  if (!href || !href.startsWith('/')) return;
  event.preventDefault();
  go(href);
});

window.addEventListener('popstate', () => render());

/* ---------- search ---------- */

const searchForm = document.getElementById('search');
const searchInput = document.getElementById('query');
const searchNote = document.getElementById('search-note');

searchForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const query = searchInput.value.trim();
  searchNote.hidden = true;
  if (!query) return;
  try {
    const answer = await api('search?q=' + encodeURIComponent(query));
    if (answer.target) {
      searchInput.value = '';
      go(answer.target);
    } else {
      searchNote.textContent = t('search.nothing');
      searchNote.hidden = false;
    }
  } catch (error) {
    searchNote.textContent = t('error.unreachable');
    searchNote.hidden = false;
  }
});

/* ---------- the ticker ---------- */

const ticker = document.getElementById('ticker');
const footNode = document.getElementById('foot-node');

async function refreshTicker() {
  let status;
  try {
    status = await api('status');
  } catch (error) {
    return;
  }
  state.status = status;

  const items = [
    [t('tick.network'), status.network.name, true],
    [t('tick.height'), status.tip ? count(status.tip.height) : '-', false],
    [t('tick.hot'), count(status.hot.notes) + ' / ' + count(status.hot.capacity), false],
    [t('tick.cold'), count(BigInt(status.cold.notes)), false],
    [t('tick.pool'), count(status.pool), false],
    [t('tick.peers'), count(status.peers), false],
    [t('tick.supply'), cairn(status.supply.issued) + ' CAIRN', false],
  ];

  clear(ticker);
  ticker.append(
    el(
      'div',
      { class: 'ticker-inner' },
      items.map(([label, value, on]) =>
        el('span', { class: 'tick' }, el('span', { class: 'tick-label', text: label }), el('span', { class: 'tick-value' + (on ? ' on' : ''), text: value }))
      )
    )
  );
  ticker.hidden = false;

  footNode.textContent = t('foot.node', {
    network: status.network.name,
    blocks: count(status.indexed),
    genesis: shorten(status.network.genesis || '-', 12, 8),
  });
}

/* ---------- level and language ---------- */

const levelSelect = document.getElementById('level');
const languageSelect = document.getElementById('language');
const welcome = document.getElementById('welcome');

function applyLevel(level, persist) {
  state.level = LEVELS.includes(level) ? level : 'curious';
  document.documentElement.setAttribute('data-level', state.level);
  levelSelect.value = state.level;
  if (persist) remember(STORE_LEVEL, state.level);
}

async function applyLanguage(code, persist) {
  try {
    const response = await fetch('/i18n/' + encodeURIComponent(code) + '.json');
    if (!response.ok) throw new Error('missing');
    state.strings = await response.json();
    state.language = code;
    document.documentElement.setAttribute('lang', code);
    if (persist) remember(STORE_LANGUAGE, code);
  } catch (error) {
    if (code !== 'en') return applyLanguage('en', false);
  }
  translateStatic();
}

function translateStatic() {
  for (const node of document.querySelectorAll('[data-t]')) {
    const value = t(node.getAttribute('data-t'));
    if (typeof value === 'string') node.textContent = value;
  }
  for (const node of document.querySelectorAll('[data-t-placeholder]')) {
    const value = t(node.getAttribute('data-t-placeholder'));
    if (typeof value === 'string') node.setAttribute('placeholder', value);
  }
  document.title = t('site.title');
}

levelSelect.addEventListener('change', () => {
  applyLevel(levelSelect.value, true);
  translateStatic();
  render();
  refreshTicker();
});

languageSelect.addEventListener('change', async () => {
  await applyLanguage(languageSelect.value, true);
  render();
  refreshTicker();
});

for (const button of document.querySelectorAll('[data-choose]')) {
  button.addEventListener('click', () => {
    applyLevel(button.getAttribute('data-choose'), true);
    welcome.hidden = true;
    translateStatic();
    render();
  });
}

/* ---------- start ---------- */

async function start() {
  try {
    const response = await fetch('/languages.json');
    if (response.ok) state.languages = await response.json();
  } catch (error) {
    /* Keep the built-in list. */
  }

  clear(languageSelect);
  for (const language of state.languages) {
    languageSelect.append(el('option', { value: language.code, text: language.name }));
  }

  const preferred =
    recall(STORE_LANGUAGE) ||
    state.languages.map((language) => language.code).find((code) => navigator.languages.some((tag) => tag.toLowerCase().startsWith(code))) ||
    'en';
  languageSelect.value = preferred;

  /* English is loaded first and kept, so a partial translation still renders. */
  try {
    const response = await fetch('/i18n/en.json');
    if (response.ok) state.fallback = await response.json();
  } catch (error) {
    /* Keys will show through, which is at least honest. */
  }

  await applyLanguage(preferred, false);

  const level = recall(STORE_LEVEL);
  applyLevel(level || 'curious', false);
  if (!level) welcome.hidden = false;

  await render();
  await refreshTicker();
  state.timers.push(window.setInterval(refreshTicker, TICKER_PERIOD));
}

start();

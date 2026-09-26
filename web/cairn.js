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
  params: null,
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
  // A field the node could not work out comes back null, and BigInt(null) is
  // zero rather than an error, so a number nobody knows would read as a
  // number somebody measured.
  if (pebbles === null || pebbles === undefined) return '-';
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

/*
  A size in the units the papers count in, which are thousands.

  It divided by 1024 and said MB, so the home page printed the drawer at
  capacity as 65 MB three panels above a lesson, and a design paper, that say
  68. The figure is the thesis, and it was two numbers on one site.
*/
function bytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size)) return '-';
  if (size < 1000) return count(size) + ' B';
  if (size < 1000000) return (size / 1000).toFixed(size < 10000 ? 1 : 0) + ' kB';
  if (size < 1000000000) return (size / 1000000).toFixed(size < 10000000 ? 1 : 0) + ' MB';
  return (size / 1000000000).toFixed(2) + ' GB';
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

/*
  A quantity with its unit, in the form the language uses for that number.

  French counts zero as singular and English does not, so the form comes from
  the locale rather than from a comparison against one written here. The site
  said `1 secondes` in French and `1 seconds` in English for as long as there
  has been a page with a five second block time on it.
*/
function plural(key, value, shown) {
  const rule = new Intl.PluralRules(locale()).select(Math.abs(Number(value)));
  return t(key + '.' + rule, { n: shown === undefined ? count(value) : shown });
}

/*
  A span of time in the largest unit that keeps it readable.

  The size is measured without its sign, so a gap that runs backwards is named
  in the same unit as the same gap forwards rather than falling through every
  bound into seconds.
*/
function duration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value)) return '-';
  const size = Math.abs(value);
  if (size < 120) return plural('unit.seconds', value);
  if (size < 7200) return plural('unit.minutes', Math.round(value / 60));
  if (size < 172800) return plural('unit.hours', Math.round(value / 3600));
  if (size < 63072000) return plural('unit.days', Math.round(value / 86400));
  const years = value / 31536000;
  return plural('unit.years', years, years.toFixed(1));
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
      else if (name === 'variable')
        for (const [property, setting] of Array.isArray(value[0]) ? value : [value]) node.style.setProperty(property, setting);
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
  The same builder, in the namespace createElement cannot reach.

  An SVG element made with createElement is an unknown HTML element that
  happens to be spelled `path`: it parses, it appears in the tree, and it
  draws nothing at all.
*/
function svg(tag, attributes, ...children) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (attributes) {
    for (const [name, value] of Object.entries(attributes)) {
      if (value === null || value === undefined || value === false) continue;
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
  return node;
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
        el('tr', null, headers.map((header) => el('th', { class: header.numeric ? 'numeric' : null, scope: 'col', text: header.label })))
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
    // How much of the chain was looked in before this came back empty. A
    // refusal from a site that has read a tenth of the chain is not the same
    // answer as one from a site that has read all of it, and the page says
    // different words for the two.
    error.coverage = body && body.coverage;
    // And the rest of the answer: a "not here" says why, at what height, and
    // how far the chain reaches.
    error.body = body || {};
    throw error;
  }
  return body;
}

/*
  What this site has read, in one sentence, or nothing when it has read the
  chain from its first block to where the chain now reaches.

  Every answer that comes out of the index carries this, because the index is
  not the chain: it is however much of the chain this site has read since it
  started, and for the first minutes of every run that is a small part of it.
  A page that leaves that out states as a fact about the chain something that
  is only a fact about its own reading.
*/
function readSoFar(coverage) {
  if (!coverage || coverage.whole !== false) return null;
  if (coverage.through === null || coverage.through === undefined) {
    return t('coverage.none', { blocks: count(coverage.behind) });
  }
  return t('coverage.part', {
    from: count(coverage.from),
    through: count(coverage.through),
    blocks: count(coverage.behind),
  });
}

/* The same, as a line to put at the foot of a panel. */
function coverageLine(coverage) {
  const said = readSoFar(coverage);
  return said ? el('p', { class: 'small dim', text: said }) : null;
}

/* ---------- views ---------- */

const view = document.getElementById('view');

/*
  Which navigation is the current one.

  Two in flight drew whichever answer arrived last, so a block could be drawn
  under /blocks with Explore marked as the current section. Every render takes
  a number before it waits, and one that comes back to find a newer number
  draws nothing.
*/
let rendering = 0;

/* The tab's title, for the view on screen: a screen reader reads it first. */
function setTitle(text) {
  document.title = text ? text + ' \u00b7 ' + t('site.title') : t('site.title');
}

function showLoading() {
  clear(view);
  view.append(el('div', { class: 'loading', text: t('common.loading') }));
}

/*
  Why the page is empty, in the words the answer supports.

  "There is nothing on this chain with that name" is a statement about the
  chain, and the site is only entitled to it once it has read the chain. Asked
  about a transaction while it was still reading, it said exactly that about a
  transfer it was printing on another page at the same moment.
*/
function showError(error, mine) {
  // A failure that arrives after another page was asked for is about a page
  // nobody is looking at any more.
  if (mine !== undefined && mine !== rendering) return;
  const status = error && error.status;
  const coverage = error && error.coverage;
  const body = (error && error.body) || {};
  const kept = coverage && coverage.kept;
  const height = count(body.height);
  // Everything that was not a 404 used to be the node not answering, so a
  // malformed address in the bar was announced as the node being down.
  let said = t('error.unreachable');
  if (status === 400) {
    said = t('error.malformed');
  } else if (status === 500) {
    said = t('error.server');
  } else if (status === 404) {
    // On the chain and not here: the API says which of four things it is,
    // and none of them is "there is nothing on this chain with that name".
    switch (body.error) {
      case 'not kept':
        said = t('error.notKept', { height, from: kept ? count(kept.from) : '-' });
        break;
      case 'unreadable':
        said = t('error.unreadable', { height });
        break;
      case 'not written yet':
        said = t('error.notWritten', { height });
        break;
      case 'above the tip':
        said = t('error.aboveTip', { height, tip: count(body.tip) });
        break;
      default: {
        const partial = coverage && coverage.whole === false;
        if (partial && (coverage.through === null || coverage.through === undefined)) {
          said = t('error.notReadAny', { blocks: count(coverage.behind) });
        } else if (partial) {
          said = t('error.notRead', { through: count(coverage.through), blocks: count(coverage.behind) });
        } else {
          said = t('error.missing');
        }
      }
    }
  }
  clear(view);
  view.append(
    panel(
      t('error.title'),
      el('div', { class: 'prose' }, el('p', { text: said })),
      el('p', { class: 'small dim', text: String((error && error.message) || error) })
    )
  );
}

async function home() {
  const mine = rendering;
  // One read of the window serves the chart and the table under it, and the
  // three go out together rather than one after another: the page is not
  // waiting on the rules to know what a block is.
  const [status, recent, rules] = await Promise.all([
    api('status'),
    api('blocks?limit=' + CHART_WINDOW),
    chainRules(),
  ]);
  if (mine !== rendering) return;
  state.status = status;

  setTitle(null);
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
        stat(t('stat.difficulty'), status.tip && status.tip.difficulty ? count(BigInt(status.tip.difficulty)) : '-'),
        stat(t('stat.supply'), cairn(status.supply.issued) + ' CAIRN', t('stat.supply.note', { reward: cairn(status.supply.nextReward) })),
        stat(t('stat.holders'), count(status.chain.holders)),
        stat(t('stat.pool'), count(status.pool), t('stat.pool.note')),
        stat(t('stat.peers'), count(status.peers))
      )
      ),

      chartPanel(recent.blocks, rules),

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

      indexPanel(status),

      panel(
        t('home.recent.title'),
        explainer('explain.blocks'),
        blocksTable(recent.blocks.slice(0, 10)),
        el('div', { class: 'more' }, el('a', { class: 'action', href: '/blocks', 'data-link': true, text: t('common.seeAll') }))
      ),
    ])
  );
}

/*
  What this website costs, as against what a node costs.

  The site named the cold set as the explorer's growing cost, and the cold set
  is the smaller half of it by nearly nine times: a node that keeps the whole
  cave carries a fixed handful of bytes for each note that has fallen, a node
  that keeps none carries nothing at all, and the index above both of them
  carries that whole ratio again for every note that has ever existed. None of
  that was written down anywhere, so nobody thinking of running one of these
  could find out what they were taking on.

  Both figures reach the page from `/api/status`, which is why the panel below
  cannot go stale. This paragraph could, and did, twice: it named five hundred
  and seven bytes a note, was corrected to five hundred and sixty five, and
  stayed at five hundred and sixty five for as long as the constant said six
  hundred and twenty seven. So it names no byte count at all now. The ratio
  stays, because `the_ratio_the_site_calls_nine_is_the_one_this_program_serves`
  holds this sentence against both constants and fails when either moves; the
  byte counts were held by nothing, which is the whole difference.
*/
function indexPanel(status) {
  const index = status.index;
  if (!index) return null;
  return panel(
    t('home.index.title'),
    prose('home.index.body', {
      perNote: count(index.bytesPerNote),
      coldPerNote: count(status.cold.bytesPerNote),
    }),
    el(
      'div',
      { class: 'rows' },
      row(t('field.indexNotes'), count(BigInt(index.notes))),
      row(t('field.indexTransactions'), count(BigInt(index.transactions))),
      row(t('field.indexOwners'), count(BigInt(index.owners))),
      row(t('field.indexBytes'), bytes(Number(index.bytes)), el('span', { class: 'row-note', text: ' ' + t('field.indexBytes.note', { perNote: count(index.bytesPerNote) }) })),
      row(
        t('field.indexCovers'),
        index.from === null
          ? t('field.indexCovers.none')
          : t('field.indexCovers.value', { from: count(index.from), through: count(index.through) }),
        el('span', { class: 'row-note', text: ' ' + t('field.indexCovers.note', { height: count(status.tip ? status.tip.height : 0) }) })
      )
    )
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

/* ---------- the chain, drawn ---------- */

/*
  One window of blocks, read three ways.

  Difficulty is what the rules demanded of the miners; spacing is what the
  miners then claimed; the work rate is the first divided by the second, which
  is why it is an estimate and the other two are not. Keeping them as three
  readings of one window rather than three charts is the point: they disagree,
  and the disagreement is the interesting part.

  The window is a fixed number of blocks, not a stretch of time. A site whose
  front page cost grew with the chain would be arguing against the thing the
  chain is for.
*/
const CHART_WINDOW = 128;
const CHART_WIDTH = 720;
const CHART_HEIGHT = 200;

/*
  A margin at both ends of the drawing.

  The newest block sits at the right edge and is marked with a dot, and a
  dot centred on the edge of a box that clips is half a dot.
*/
const CHART_INSET = 6;

/* How many blocks a single work rate reading is measured over. */
const RATE_SPAN = 12;

const STORE_READING = 'cairn.reading';
const READINGS = ['difficulty', 'spacing', 'rate'];

const chart = {
  panel: null,
  body: null,
  buttons: new Map(),
  heading: null,
  reading: 'difficulty',
  blocks: [],
  at: null,
};

function median(values) {
  const sorted = values.filter((value) => value !== null && Number.isFinite(value)).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

/*
  A rate of hashing, in the prefixes the quantity is usually spoken in.

  Not translated, for the same reason kB is not: these are symbols, and a
  reader who knows what a terahash is knows it under that spelling in every
  language this site is written in.
*/
function hashes(rate) {
  if (rate === null || !Number.isFinite(rate) || rate <= 0) return '-';
  const steps = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
  let value = rate;
  let step = 0;
  while (value >= 1000 && step < steps.length - 1) {
    value /= 1000;
    step += 1;
  }
  const places = value < 10 ? 2 : value < 100 ? 1 : 0;
  return value.toFixed(places) + ' ' + steps[step];
}

/*
  The three series, oldest first.

  Difficulty arrives as a decimal string because it is a sixty four bit number
  and JSON has no such thing. Drawing it as a double loses the low bits of a
  value that would need a quintillion hashes to reach, which is beyond what a
  chart two hundred units tall could show; the figure printed beside the chart
  is parsed exactly, so no reader is ever shown a rounded number as an exact
  one.
*/
function chartSeries(blocks) {
  const order = blocks.slice().reverse();
  const times = order.map((block) => Number(block.timestamp));
  const work = order.map((block) => Number(block.difficulty));

  const spacing = times.map((at, index) => (index === 0 ? null : at - times[index - 1]));

  const rate = work.map((_, index) => {
    const start = index - RATE_SPAN;
    if (start < 0) return null;
    const span = times[index] - times[start];
    if (span <= 0) return null;
    let sum = 0;
    for (let step = start + 1; step <= index; step += 1) sum += work[step];
    return sum / span;
  });

  return { blocks: order, times, work, spacing, rate };
}

/*
  The band the drawing covers, which is exactly what the readings did.

  It was widened by a margin at first, and the margin was printed: the figures
  at the top and bottom of the frame are read as the highest and lowest values
  in the window, and eight per cent under the lowest difficulty on a young
  chain is a negative difficulty, which is not a number this chain can hold.
  The room a stroke needs in order not to be clipped is taken in pixels inside
  the drawing instead, where it costs nothing true.

  `anchor` is a value the band must reach whatever the readings did: zero for
  the bars, because a bar measured from anywhere else draws a difference and
  calls it a quantity.
*/
function band(values, anchor) {
  const present = values.filter((value) => value !== null && Number.isFinite(value));
  if (!present.length) return null;
  let low = Math.min(...present);
  let high = Math.max(...present);
  if (anchor !== null && anchor !== undefined && Number.isFinite(anchor)) {
    low = Math.min(low, anchor);
    high = Math.max(high, anchor);
  }
  return { low, high };
}

/* A reading that never moved sits in the middle, rather than dividing by nothing. */
function heightOf(value, scale) {
  const reach = scale.high - scale.low;
  const floor = CHART_HEIGHT - CHART_INSET;
  if (reach <= 0) return CHART_HEIGHT / 2;
  return floor - ((value - scale.low) / reach) * (floor - CHART_INSET);
}

function place(values, scale) {
  const span = CHART_WIDTH - CHART_INSET * 2;
  const step = values.length > 1 ? span / (values.length - 1) : 0;
  return values.map((value, index) =>
    value === null || !Number.isFinite(value) ? null : [CHART_INSET + index * step, heightOf(value, scale)]
  );
}

/* Unbroken stretches, so a gap in the readings is a gap in the drawing. */
function runs(points) {
  const found = [];
  let run = [];
  for (const point of points) {
    if (point) {
      run.push(point);
    } else if (run.length) {
      found.push(run);
      run = [];
    }
  }
  if (run.length) found.push(run);
  return found;
}

function snap(value) {
  return Math.round(value * 100) / 100;
}

function linePath(run) {
  return run.map((point, index) => (index ? 'L' : 'M') + snap(point[0]) + ' ' + snap(point[1])).join('');
}

function areaPath(run, floor) {
  const first = run[0];
  const last = run[run.length - 1];
  return linePath(run) + 'L' + snap(last[0]) + ' ' + snap(floor) + 'L' + snap(first[0]) + ' ' + snap(floor) + 'Z';
}

function lineShape(points, floor) {
  return runs(points).map((run) => [
    run.length > 1 ? svg('path', { class: 'spark-area', d: areaPath(run, floor) }) : null,
    svg('path', { class: 'spark-line', d: linePath(run) }),
  ]);
}

/*
  One bar per block, measured from zero rather than from the lowest reading.

  A gap that runs backwards is drawn below the line and in the one colour this
  palette keeps for something wrong, because that is what it is: a miner that
  put an earlier time in its header than the block it builds on. The rules
  allow it, so the chart has to be able to show it.
*/
function barShape(points, values, floor) {
  const span = CHART_WIDTH - CHART_INSET * 2;
  const width = points.length ? span / points.length : span;
  const bar = Math.max(1, width - Math.min(2, width * 0.3));
  return points.map((point, index) => {
    if (!point) return null;
    const top = Math.min(point[1], floor);
    const tall = Math.max(1, Math.abs(floor - point[1]));
    return svg('rect', {
      class: values[index] < 0 ? 'spark-bar back' : 'spark-bar',
      x: snap(CHART_INSET + index * width + (width - bar) / 2),
      y: snap(top),
      width: snap(bar),
      height: snap(tall),
    });
  });
}

function gridLines(scale, floor, target, ruled) {
  const lines = ruled
    ? [svg('line', { class: 'spark-grid', x1: 0, x2: CHART_WIDTH, y1: CHART_HEIGHT / 2, y2: CHART_HEIGHT / 2 })]
    : [];
  if (target !== null && target > scale.low && target < scale.high) {
    const y = snap(heightOf(target, scale));
    lines.push(svg('line', { class: 'spark-target', x1: 0, x2: CHART_WIDTH, y1: y, y2: y }));
  }
  if (floor > 0 && floor < CHART_HEIGHT) {
    lines.push(svg('line', { class: 'spark-floor', x1: 0, x2: CHART_WIDTH, y1: snap(floor), y2: snap(floor) }));
  }
  return lines;
}

/*
  What each reading is, in one place.

  `anchor` says which value the band must contain: zero for the bars, because
  a bar not measured from zero is a drawing of a difference pretending to be a
  drawing of a quantity, and nothing for the lines, which carry their own low
  and high printed beside them.
*/
const READING = {
  difficulty: {
    pick: (series) => series.work,
    shape: 'line',
    anchor: null,
    target: () => null,
    latest: (series) => {
      const block = series.blocks[series.blocks.length - 1];
      return block ? count(BigInt(block.difficulty)) : '-';
    },
    format: (value) => count(Math.round(value)),
  },
  spacing: {
    pick: (series) => series.spacing,
    shape: 'bars',
    anchor: 0,
    target: (rules) => (rules && Number.isFinite(Number(rules.targetBlockTime)) ? Number(rules.targetBlockTime) : null),
    latest: (series) => {
      const last = series.spacing[series.spacing.length - 1];
      return last === null ? '-' : duration(last);
    },
    format: (value) => duration(Math.round(value)),
  },
  rate: {
    pick: (series) => series.rate,
    shape: 'line',
    anchor: null,
    target: () => null,
    latest: (series) => hashes(series.rate[series.rate.length - 1]),
    format: hashes,
  },
};

function readingNow() {
  const kept = recall(STORE_READING);
  return READINGS.includes(kept) ? kept : 'difficulty';
}

function chartFigure(reading, series, values, scale) {
  const middle = median(values);
  return el(
    'div',
    { class: 'chart-readout' },
    el(
      'div',
      null,
      el('div', { class: 'chart-label', text: t('chart.label.' + reading) }),
      el('div', { class: 'chart-figure', text: READING[reading].latest(series) })
    ),
    el(
      'div',
      { class: 'chart-aside' },
      el('div', {
        class: 'chart-middle',
        text: middle === null ? '' : t('chart.middle', { value: READING[reading].format(middle), n: count(values.filter((v) => v !== null).length) }),
      }),
      series.blocks.length ? sinceNode(series.times[series.times.length - 1]) : null
    ),
  );
}

function chartFrame(reading, series, values, scale, rules, fresh) {
  const points = place(values, scale);
  const anchored = READING[reading].anchor;
  const floor = anchored === null ? CHART_HEIGHT : Math.min(CHART_HEIGHT, Math.max(0, heightOf(0, scale)));
  const target = READING[reading].target(rules);
  const drawn = READING[reading].shape === 'bars' ? barShape(points, values, floor) : lineShape(points, floor);
  const last = points.filter(Boolean).pop();

  const face = svg(
    'svg',
    {
      class: 'spark',
      viewBox: '0 0 ' + CHART_WIDTH + ' ' + CHART_HEIGHT,
      preserveAspectRatio: 'none',
      role: 'img',
      'aria-label': t('chart.alt', {
        reading: t('chart.reading.' + reading),
        n: count(values.filter((value) => value !== null).length),
        low: READING[reading].format(scale.low),
        high: READING[reading].format(scale.high),
      }),
    },
    gridLines(scale, floor, target, READING[reading].shape !== 'bars'),
    drawn
  );

  return el(
    'div',
    { class: 'chart-frame' },
    face,
    last
      ? el('span', {
          class: fresh ? 'chart-dot arrived' : 'chart-dot',
          variable: [
            ['--x', ((last[0] / CHART_WIDTH) * 100).toFixed(3) + '%'],
            ['--y', ((last[1] / CHART_HEIGHT) * 100).toFixed(3) + '%'],
          ],
        })
      : null,
    el('span', { class: 'chart-bound high', text: READING[reading].format(scale.high) }),
    el('span', { class: 'chart-bound low', text: READING[reading].format(scale.low) }),
    target === null ? null : el('span', { class: 'chart-mark', text: t('chart.target', { value: duration(target) }) })
  );
}

function drawChart(fresh) {
  if (!chart.body) return;
  const rules = state.params;
  const series = chartSeries(chart.blocks.slice(0, CHART_WINDOW));
  const reading = chart.reading;
  const values = READING[reading].pick(series);
  const scale = band(values, READING[reading].anchor);

  for (const [key, button] of chart.buttons) {
    button.setAttribute('aria-pressed', key === reading ? 'true' : 'false');
  }

  if (chart.heading) {
    chart.heading.textContent = t('chart.title', { n: count(Math.min(CHART_WINDOW, chart.blocks.length)) });
  }

  clear(chart.body);
  chart.body.append(
    chartFigure(reading, series, values, scale),
    scale ? chartFrame(reading, series, values, scale, rules, fresh) : el('div', { class: 'empty', text: t('chart.none') }),
    el('p', { class: 'small dim', text: t('chart.note.' + reading) })
  );
}

function chooseReading(reading) {
  if (!READINGS.includes(reading) || reading === chart.reading) return;
  chart.reading = reading;
  remember(STORE_READING, reading);
  drawChart();
}

function chartPanel(blocks, rules) {
  chart.reading = readingNow();
  chart.blocks = blocks;
  chart.at = blocks.length ? Number(blocks[0].height) : null;
  state.params = rules || state.params;

  chart.buttons = new Map();
  const modes = el(
    'div',
    { class: 'chart-modes', role: 'group', 'aria-label': t('chart.modes') },
    READINGS.map((reading) => {
      const button = el('button', {
        type: 'button',
        class: 'mode',
        'aria-pressed': reading === chart.reading ? 'true' : 'false',
        text: t('chart.reading.' + reading),
        onclick: () => chooseReading(reading),
      });
      chart.buttons.set(reading, button);
      return button;
    })
  );

  chart.body = el('div', { class: 'chart-body' });
  chart.heading = el('h2');
  chart.panel = el(
    'section',
    { class: 'panel chart-panel' },
    el('div', { class: 'panel-head' }, chart.heading, modes),
    chart.body
  );
  drawChart();
  return chart.panel;
}

/*
  The chain moved, so the drawing does.

  Asked only when the tip is not the block the chart was built from, which is
  once a block rather than once every ticker beat: the window is a hundred and
  twenty eight blocks and re-reading it every five seconds to redraw the same
  line would be work nobody asked for.
*/
async function refreshChart(height) {
  if (!chart.panel || !chart.panel.isConnected) return;
  if (height === null || height === undefined || height === chart.at) return;
  // Taken before the read rather than after it, so a read that fails is not
  // retried on every beat of the ticker until the next block happens to land.
  chart.at = height;
  let page;
  try {
    page = await api('blocks?limit=' + CHART_WINDOW);
  } catch (error) {
    return;
  }
  chart.blocks = page.blocks;
  drawChart(true);
}

/*
  The one number on the page that moves without being asked.

  It is our clock against a time the miner wrote in its own header, so it
  measures the gap between the two and not the age of anything. A miner is
  allowed to be a little ahead of us, and then this counts up from zero rather
  than down from a claim.
*/
function sinceSaid(written) {
  if (!Number.isFinite(written) || written <= 0) return '';
  return t('chart.since', { gap: duration(Math.max(0, Math.round(Date.now() / 1000) - written)) });
}

/* Written once when the node is made, so it is never blank for a second. */
function sinceNode(written) {
  return el('div', { class: 'chart-since', 'data-since': String(written), text: sinceSaid(written) });
}

function tickLive() {
  for (const node of document.querySelectorAll('[data-since]')) {
    node.textContent = sinceSaid(Number(node.getAttribute('data-since')));
  }
}

/* The rules, read once: they cannot change while this page is open. */
async function chainRules() {
  if (state.params) return state.params;
  try {
    state.params = await api('params');
  } catch (error) {
    return null;
  }
  return state.params;
}

async function blocks(parameters) {
  const mine = rendering;
  const from = parameters.get('from');
  const page = await api('blocks?limit=25' + (from ? '&from=' + encodeURIComponent(from) : ''));
  if (mine !== rendering) return;
  setTitle(t('blocks.title'));
  clear(view);
  // A run of heights this site no longer keeps is said as that. The page used
  // to list nothing over it and say nothing, which is what a shorter chain
  // looks like.
  const notKept = page.notKept
    ? el('p', { class: 'small dim', text: t('blocks.notKept', { from: count(page.notKept.from), through: count(page.notKept.through) }) })
    : null;
  view.append(
    el(
      'div',
      { class: 'stack' },
      panel(t('blocks.title'), explainer('explain.blocks'), blocksTable(page.blocks), notKept,
        page.next !== null && page.next !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: '/blocks?from=' + page.next, 'data-link': true, text: t('common.older') }))
          : null
      )
    )
  );
}

async function block(reference, parameters) {
  const mine = rendering;
  const from = parameters.get('from');
  const data = await api('block/' + encodeURIComponent(reference) + (from ? '?from=' + encodeURIComponent(from) : ''));
  if (mine !== rendering) return;
  setTitle(t('block.title', { height: count(data.height) }));
  clear(view);
  // Only the tip has nothing mined on it. A block whose successor this site
  // cannot read printed "Not mined yet" too, a hundred blocks deep.
  const isTip = data.confirmations === 1;

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
    row(t('field.next'), data.next ? hashLink(data.next, '/block/' + (data.height + 1)) : isTip ? t('field.pending') : t('field.nextUnavailable')),
    row(t('field.size'), bytes(data.size)),
    row(t('field.reward'), cairn(data.reward) + ' CAIRN'),
    row(t('field.fees'), data.fees === null ? t('field.unknown') : cairn(data.fees) + ' CAIRN'),
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
    ),
    el(
      'div',
      { class: 'row lv-technical' },
      el('div', { class: 'row-label', text: t('field.history') }),
      el(
        'div',
        { class: 'row-value' },
        hashLink(data.history, null, { head: 64, tail: 0 }),
        el('span', { class: 'row-note', text: ' ' + t('field.history.note') })
      )
    ),
    el(
      'div',
      { class: 'row lv-curious' },
      el('div', { class: 'row-label', text: t('field.totalWork') }),
      el('div', { class: 'row-value' }, count(BigInt(data.totalWork)))
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
      coinbase.extraText ? row(t('field.message'), el('bdi', { text: coinbase.extraText })) : null,
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
      // This page comes off the chain and the state of its notes comes off
      // the index, so it is where the two can be seen disagreeing: the block
      // is here, and whether what it paid has since been spent may not be
      // known yet.
      panel(null, explainer('explain.block'), rows, coverageLine(data.coverage)),
      coinbasePanel,
      panel(
        t('block.transfers.title', { n: count(data.transferCount ?? data.transfers.length) }),
        explainer('explain.transfers'),
        data.transfers.length ? el('div', { class: 'stack' }, data.transfers.map((transfer) => transferCard(transfer))) : el('div', { class: 'empty', text: t('block.transfers.none') }),
        data.transfersNext !== null && data.transfersNext !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: '/block/' + data.height + '?from=' + data.transfersNext, 'data-link': true, text: t('common.more') }))
          : null
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

/*
  A fee the explorer could not work out is not a fee of nothing.

  It used to render a null as `fee 0 CAIRN`, so a block page could say
  "Fees: Not indexed" at the top and "fee 0 CAIRN" on every transfer under it,
  from one request. A number is only printed where the API sent one.
*/
function feeLine(transfer) {
  if (transfer.fee === null || transfer.fee === undefined) return t('transfer.fee.unknown');
  return t('transfer.fee', { fee: cairn(transfer.fee) });
}

/*
  The same on the transaction page, where a null used to render as "None".

  "None" is the right word for a coinbase: nobody paid it, and there is
  nothing to work out. For a transfer it was a statement the site had no
  grounds for.
*/
function feeValue(it) {
  if (it.fee !== null && it.fee !== undefined) return cairn(it.fee) + ' CAIRN';
  return it.kind === 'coinbase' ? t('field.none') : t('field.unknown');
}

function amountOrUnknown(value) {
  if (value === null || value === undefined) return t('field.unknown');
  return cairn(value) + ' CAIRN';
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
      el('span', { class: 'small dim', text: feeLine(transfer) })
    ),
    el('div', { class: 'split' }, inputs, outputs)
  );
}

async function transaction(id) {
  const mine = rendering;
  const data = await api('tx/' + encodeURIComponent(id));
  if (mine !== rendering) return;
  const it = data.transaction;
  setTitle(t('tx.title'));
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
    row(t('field.totalIn'), amountOrUnknown(it.totalIn)),
    row(t('field.totalOut'), amountOrUnknown(it.totalOut)),
    row(t('field.fee'), feeValue(it)),
    row(t('field.size'), bytes(it.size)),
    it.extraText ? row(t('field.message'), el('bdi', { text: it.extraText })) : null
  );

  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('tx.eyebrow') }), el('h1', { text: t('tx.title') })),
      // Whether its outputs have been spent comes off the index, which may
      // not have read that far.
      panel(null, explainer('explain.transaction'), rows, coverageLine(data.coverage)),
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

// An address holding more notes than the explorer will walk is answered with a
// floor rather than a total: the API says so with `counted`, and a number
// printed as though it were exact would be the one thing worse than a slow
// page. The sign says it without a sentence, and without a translation.
function atLeast(data, text) {
  return data.counted === false ? '\u2265\u202f' + text : text;
}

/*
  What an address was paid, or paid out, as far as this site can tell.

  Both only grow, so a figure off part of the chain is at least the real one,
  and so is one that has passed what a count of pebbles holds, which the API
  says with `turnoverCounted`. Both were printed bare beside a note count that
  already carried the sign.
*/
function turnover(data, pebbles) {
  const floor = data.turnoverCounted === false || (data.coverage && data.coverage.whole === false);
  return (floor ? '\u2265\u202f' : '') + cairn(pebbles) + ' CAIRN';
}

async function address(owner, parameters) {
  const mine = rendering;
  const from = parameters.get('from');
  const notes = parameters.get('notes');
  const asked = [from ? 'from=' + encodeURIComponent(from) : null, notes ? 'notes=' + encodeURIComponent(notes) : null].filter(Boolean);
  const data = await api('address/' + encodeURIComponent(owner) + (asked.length ? '?' + asked.join('&') : ''));
  if (mine !== rendering) return;
  setTitle(shorten(data.address, 10, 6));
  clear(view);
  // The next page of notes keeps the page of history the reader is on, and the
  // next page of history keeps the notes.
  const here = (name, value) => {
    const kept = new URLSearchParams(parameters);
    kept.set(name, value);
    return '/address/' + data.address + '?' + kept.toString();
  };

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
        stat(t('stat.received'), turnover(data, data.received)),
        stat(t('stat.sent'), turnover(data, data.spent)),
        stat(t('stat.notesHeld'), atLeast(data, count(data.unspentNotes)), t('stat.notesHeld.note', { total: count(data.notes) }))
      ),
      coverageLine(data.coverage),
      panel(
        t('address.holdings'),
        explainer('explain.holdings'),
        data.moreNotes
          ? el('p', { class: 'small dim', text: t('address.moreNotes', { shown: count(data.unspent.length), total: atLeast(data, count(data.unspentNotes)) }) })
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
        ),
        data.notesNext !== null && data.notesNext !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: here('notes', data.notesNext), 'data-link': true, text: t('common.more') }))
          : null
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
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: here('from', data.next), 'data-link': true, text: t('common.older') }))
          : null
      )
    )
  );
}

async function note(reference) {
  const mine = rendering;
  const data = await api('note/' + encodeURIComponent(reference));
  if (mine !== rendering) return;
  setTitle(t('note.title'));
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
        ),
        // Whether it has been spent comes off the index, which may not have
        // read as far as the block that spent it.
        coverageLine(data.coverage)
      )
    )
  );
}

async function pool(parameters) {
  const mine = rendering;
  const from = parameters.get('from');
  const data = await api('pool' + (from ? '?from=' + encodeURIComponent(from) : ''));
  if (mine !== rendering) return;
  setTitle(t('pool.title'));
  clear(view);
  view.append(
    el(
      'div',
      { class: 'stack' },
      el(
        'section',
        null,
        el('p', { class: 'eyebrow', text: t('pool.eyebrow') }),
        el('h1', { text: t('pool.title') }),
        // The whole of it, which a page of it is not: the ticker above said
        // forty while this said nothing and showed twenty five.
        el('p', { class: 'small dim', text: plural('pool.count', data.count) })
      ),
      panel(
        null,
        explainer('explain.pool'),
        data.transfers.length ? el('div', { class: 'stack' }, data.transfers.map((transfer) => transferCard(transfer))) : el('div', { class: 'empty', text: t('pool.empty') }),
        data.next !== null && data.next !== undefined
          ? el('div', { class: 'more' }, el('a', { class: 'action', href: '/pool?from=' + data.next, 'data-link': true, text: t('common.more') }))
          : null
      )
    )
  );
}

async function holders() {
  const mine = rendering;
  const data = await api('holders');
  if (mine !== rendering) return;
  setTitle(t('holders.title'));
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
        ),
        // The whole of this page is a claim about every owner on the chain,
        // so it is the last place that should leave out how much of the chain
        // was counted. An unread chain used to answer it with an empty table
        // and nothing else, which is what a chain nobody owns anything on
        // would look like too.
        coverageLine(data.coverage),
        // And when it was counted, which is a different question. Working the
        // distribution out costs the whole index rather than the block just
        // read, so it is done on a block in sixteen; a table a few blocks old
        // is worth having and is not worth passing off as current.
        data.countedAt !== null && data.countedAt !== undefined
          ? el('p', { class: 'small dim', text: t('holders.countedAt', { n: count(data.countedAt) }) })
          : null
      )
    )
  );
}

async function rules() {
  const mine = rendering;
  const data = await api('params');
  if (mine !== rendering) return;
  setTitle(t('rules.title'));
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
  setTitle(t('learn.title'));
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

/* ---------- downloading ---------- */

/*
  Where the programs are.

  The name carries no version, so this link never has to be edited: GitHub
  hands over whatever the newest release is. Every release also keeps its own
  copy under its own tag, so an older one stays reachable for good.
*/
const RELEASES = 'https://github.com/cairnchain/cairn/releases';
const NEWEST = RELEASES + '/latest/download/';

const BUILDS = [
  { key: 'macos-apple-silicon', file: 'cairn-macos-apple-silicon.tar.gz', tar: true },
  { key: 'macos-intel', file: 'cairn-macos-intel.tar.gz', tar: true },
  { key: 'linux-x86_64', file: 'cairn-linux-x86_64.tar.gz', tar: true },
  { key: 'linux-arm64', file: 'cairn-linux-arm64.tar.gz', tar: true },
  { key: 'windows-x86_64', file: 'cairn-windows-x86_64.zip', tar: false },
];

/*
  Which build this machine would run.

  Read from what the browser volunteers about itself and nothing more. There
  is a way to tell an Apple silicon Mac from an Intel one, by asking a graphics
  context which chip drew it, and it is not used here: a page about a chain
  that asks you to trust nobody should not fingerprint the person reading it.
  Both Macs are offered, newest first, with the year that separates them.
*/
function thisMachine() {
  const agent = (navigator.userAgent || '').toLowerCase();
  const platform = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '').toLowerCase();
  const touch = navigator.maxTouchPoints || 0;

  // A phone or a tablet runs none of these, and an iPad says it is a Mac.
  if (/android|iphone|ipad|ipod/.test(agent) || (platform.startsWith('mac') && touch > 1)) return 'phone';

  if (platform.includes('win') || agent.includes('windows')) return 'windows-x86_64';
  if (platform.includes('mac') || agent.includes('mac os')) return 'macos-apple-silicon';
  if (platform.includes('linux') || agent.includes('linux')) {
    return /aarch64|arm64/.test(agent) ? 'linux-arm64' : 'linux-x86_64';
  }
  return null;
}

function outward(href, text, extra) {
  return el('a', Object.assign({ href, rel: 'noreferrer', text }, extra || {}));
}

/* How a program in the unpacked folder is run, which the shell decides. */
function invoke(key, program) {
  return key === 'windows-x86_64' ? program + '.exe' : './' + program;
}

function unpack(build) {
  if (!build || !build.tar) return null;
  return 'tar xzf ' + build.file + '\ncd cairn-*-' + build.key;
}

function download() {
  setTitle(t('nav.run'));
  clear(view);
  const network = state.status && state.status.network ? state.status.network.name : 'testnet-6';
  const here = thisMachine();
  const mine = BUILDS.find((build) => build.key === here) || null;
  const rest = BUILDS.filter((build) => build !== mine);
  const run = (program) => invoke(mine ? mine.key : 'linux-x86_64', program);
  const archive = mine ? mine.file : 'cairn-linux-x86_64.tar.gz';
  const opening = unpack(mine);

  const choice = el(
    'div',
    { class: 'get-list' },
    rest.map((build) =>
      el(
        'a',
        { class: 'get-row', href: NEWEST + build.file, rel: 'noreferrer' },
        el('span', { class: 'get-name', text: t('run.platform.' + build.key + '.name') }),
        el('span', { class: 'get-note', text: t('run.platform.' + build.key + '.note') }),
        el('span', { class: 'get-file', text: build.file })
      )
    )
  );

  view.append(
    el(
      'div',
      { class: 'stack' },
      el('section', null, el('p', { class: 'eyebrow', text: t('run.eyebrow') }), el('h1', { text: t('run.title') }), prose('run.lede')),
      panel(t('run.warning.title'), el('div', { class: 'note-aside' }, paragraphs('run.warning.body').map((text) => el('p', { text })))),

      panel(
        t('run.get.title'),
        prose('run.get.body'),
        el(
          'div',
          { class: 'get' },
          mine
            ? el(
                'div',
                { class: 'get-main' },
                outward(NEWEST + mine.file, t('run.get.action', { platform: t('run.platform.' + mine.key + '.name') }), {
                  class: 'action primary get-action',
                }),
                el('p', { class: 'small dim', text: mine.file + ' · ' + t('run.get.newest') })
              )
            : el('div', { class: 'note-aside' }, el('p', { text: t(here === 'phone' ? 'run.get.phone' : 'run.get.unknown') })),
          el('p', { class: 'get-else', text: mine ? t('run.get.else') : t('run.get.all') }),
          choice,
          el(
            'p',
            { class: 'small dim' },
            outward(RELEASES, t('run.get.every')),
            document.createTextNode(' · '),
            outward(NEWEST + 'SHA256SUMS', t('run.get.sums'))
          )
        ),
        el('div', { class: 'note-aside' }, el('p', { text: t('run.get.inside') }))
      ),

      panel(
        t('run.check.title'),
        prose('run.check.body'),
        el('pre', { class: 'code', text: 'gh attestation verify ' + archive + ' --repo cairnchain/cairn' }),
        el('pre', {
          class: 'code',
          text: mine && mine.key === 'windows-x86_64' ? 'certutil -hashfile ' + archive + ' SHA256' : 'shasum -a 256 ' + archive,
        }),
        el('div', { class: 'note-aside' }, paragraphs('run.check.warning').map((text) => el('p', { text })))
      ),

      panel(
        t('run.node.title'),
        prose('run.node.body'),
        el('pre', { class: 'code', text: (opening ? opening + '\n' : '') + run('cairnd') })
      ),

      panel(
        t('run.wallet.title'),
        prose('run.wallet.body'),
        el('pre', {
          class: 'code',
          text: [
            run('cairn-wallet') + ' new mine.key',
            run('cairn-wallet') + ' address mine.key',
            run('cairn-wallet') + ' open mine.key',
          ].join('\n'),
        })
      ),

      panel(t('run.mine.title'), prose('run.mine.body'), el('pre', { class: 'code', text: run('cairnd') + ' --mine ' + t('run.mine.placeholder') })),

      panel(
        t('run.server.title'),
        prose('run.server.body'),
        el('pre', { class: 'code', text: 'apt install -y git\ngit clone https://github.com/cairnchain/cairn /usr/local/src/cairn\nsh /usr/local/src/cairn/deploy/install.sh' })
      ),

      panel(t('run.explorer.title'), prose('run.explorer.body'), el('pre', { class: 'code', text: run('cairn-explorer') + ' --network ' + network })),

      panel(
        t('run.build.title'),
        prose('run.build.body'),
        el('pre', { class: 'code', text: 'git clone https://github.com/cairnchain/cairn\ncd cairn\ncargo build --release' })
      )
    )
  );
}

/* ---------- routing ---------- */

const routes = [
  [/^\/$/, () => home()],
  [/^\/blocks$/, (match, parameters) => blocks(parameters)],
  [/^\/block\/(.+)$/, (match, parameters) => block(match[1], parameters)],
  [/^\/tx\/(.+)$/, (match) => transaction(match[1])],
  [/^\/address\/(.+)$/, (match, parameters) => address(match[1], parameters)],
  [/^\/note\/(.+)$/, (match) => note(match[1])],
  [/^\/pool$/, (match, parameters) => pool(parameters)],
  [/^\/holders$/, () => holders()],
  [/^\/learn$/, () => learn()],
  [/^\/rules$/, () => rules()],
  [/^\/download$/, () => download()],
];

async function render() {
  const path = window.location.pathname;
  const parameters = new URLSearchParams(window.location.search);
  const mine = ++rendering;
  markCurrent(path);

  for (const [pattern, handler] of routes) {
    const match = pattern.exec(path);
    if (!match) continue;
    showLoading();
    try {
      await handler(match, parameters);
    } catch (error) {
      showError(error, mine);
    }
    if (mine !== rendering) return;
    // Where a screen reader goes on, and where the keyboard does: a view
    // drawn without moving either leaves both on the link that was followed.
    view.focus({ preventScroll: true });
    return;
  }

  setTitle(null);
  clear(view);
  view.append(panel(t('error.title'), el('div', { class: 'prose' }, el('p', { text: t('error.noPage') }))));
}

function markCurrent(path) {
  for (const link of document.querySelectorAll('.links a')) {
    const target = link.getAttribute('href');
    // A section's own address or one under it, and not any path that happens
    // to begin with the same letters: `/learnx` used to light up Learn.
    const own = path === target || path.startsWith(target + '/');
    const current = target === '/' ? path === '/' : own || (target === '/blocks' && /^\/(block|tx|address|note|pool|holders)(\/|$)/.test(path));
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
      // A transaction identifier and an address are both thirty two bytes, so
      // anything the site has not read falls through to the address page. It
      // used to go there without a word, and somebody looking up their own
      // transaction was told, in effect, that it was an address holding
      // nothing. The page is still shown, because an address nobody has paid
      // is not in the index either; what is no longer left out is that this
      // was a guess made off part of a chain.
      const guessed = answer.kind === 'address' && answer.coverage && answer.coverage.whole === false;
      searchInput.value = '';
      go(answer.target);
      if (guessed) {
        searchNote.textContent = t('search.guessed');
        searchNote.hidden = false;
      }
    } else {
      // Nothing matched, which is a statement about the chain only once the
      // whole chain has been read. During every first pass and every rebuild
      // a transaction the index had not reached was denied here.
      const coverage = answer.coverage;
      const partial = coverage && coverage.whole === false;
      if (partial && (coverage.through === null || coverage.through === undefined)) {
        searchNote.textContent = t('error.notReadAny', { blocks: count(coverage.behind) });
      } else if (partial) {
        searchNote.textContent = t('error.notRead', { through: count(coverage.through), blocks: count(coverage.behind) });
      } else {
        searchNote.textContent = t('search.nothing');
      }
      searchNote.hidden = false;
    }
  } catch (error) {
    searchNote.textContent = t('error.unreachable');
    searchNote.hidden = false;
  }
});

/* ---------- what is wrong, when something is ---------- */

/*
  How far the index may trail the chain before the page says so.

  It reads what the node has added every half second, so one block behind is
  ordinary and eight is not: at a block a minute that is somebody's afternoon.
*/
const BEHIND_ENOUGH = 8;

/*
  The one sentence about why the numbers beside it may not be what they look
  like, or nothing at all.

  The wallet has had this for every one of these states and this site had it
  for none. From the outside they all look exactly like something that is
  working: a height, a supply, a list of blocks, and no complaint. Two of them
  mean the height stopped moving some time ago and will not start again on its
  own, and one means every balance on the site is about part of the chain
  rather than about the chain.

  In order of what it costs a reader to be wrong about.

  It read six of the twelve states the node reports. A node whose disk had
  filled switched itself off, had no peers left, and was shown under the
  sentence for a node that is merely alone and will catch up when somebody
  reaches it; a disk that would not read back, a build too old for its chain,
  a node nobody could show the chain to and one whose disk was growing past
  its budget all looked healthy. The order below is the wallet's, which puts
  the clock first among the causes because it produces the symptoms of the
  others.
*/
function trouble(status) {
  const node = status.node || {};
  const index = status.index || {};
  const onDisk = (unwritten) =>
    unwritten.writtenThrough === null || unwritten.writtenThrough === undefined
      ? t('warn.disk.empty')
      : t('warn.disk.holds', { height: count(unwritten.writtenThrough) });

  if (node.outdated) {
    return t('warn.outdated', {
      height: count(node.outdated.height),
      required: count(node.outdated.required),
      known: count(node.outdated.known),
    });
  }
  if (node.stranded) {
    return t('warn.stranded', {
      anchor: count(node.stranded.anchor),
      settlesAt: count(node.stranded.settlesAt),
    });
  }
  // The third way a node stops itself, beside the two above. It has no peers
  // either, so every line below it would be false about it.
  if (node.unwritten && node.unwritten.withinReach === false) {
    return t('warn.unwritten.stopped', {
      reached: count(node.unwritten.reached),
      kept: onDisk(node.unwritten),
      blocks: count(node.unwritten.blocks),
    });
  }
  if (node.probation) {
    return t('warn.probation', {
      checked: count(node.probation.checked),
      owed: count(node.probation.owed),
    });
  }
  if (node.clockBehind) {
    const behind = node.clockBehind;
    const said = {
      gap: duration(Math.max(0, Number(behind.seconds) - Number(behind.drift))),
      blocks: count(behind.blocks),
      peers: count(behind.peers),
    };
    return behind.ownFirstBlock ? t('warn.clockBehind.certain', said) : t('warn.clockBehind.likely', said);
  }
  if (node.unwritten) {
    return t('warn.unwritten.behind', {
      reached: count(node.unwritten.reached),
      kept: onDisk(node.unwritten),
      blocks: count(node.unwritten.blocks),
    });
  }
  if (node.unread) {
    return t('warn.unread', { height: count(node.unread.height) });
  }
  if (node.unjudged) {
    return t('warn.unjudged', {
      blocks: count(node.unjudged.blocks),
      peers: count(node.unjudged.peers),
      version: count(node.unjudged.version),
      known: count(node.unjudged.known),
    });
  }
  if (node.unweighable) {
    return t('warn.unweighable', { showings: count(node.unweighable.showings), peers: count(node.unweighable.peers) });
  }
  if (node.filling) {
    const filling = node.filling;
    const said = {
      from: count(filling.from),
      through: count(Math.max(0, Number(filling.through) - 1)),
      tip: count(Math.max(0, Number(filling.reaches) - 1)),
      bytes: bytes(filling.bytes),
      keep: bytes(filling.keep),
    };
    return filling.overTheKeep ? t('warn.filling.over', said) : t('warn.filling.within', said);
  }
  if (node.joining && node.joining !== 'no' && node.joining !== 'done') {
    return t('warn.joining');
  }
  if (node.outOfReach > 0) {
    return t('warn.outOfReach', { blocks: count(node.outOfReach) });
  }
  // A disk that gave back something other than what was written to it. The
  // chain is not in doubt and the mending is exact, which is why this is worth
  // a line rather than a silence: every answer on this site comes off that
  // disk, and nothing anywhere reported the one number that says it is failing.
  if (node.mended > 0) {
    return plural('warn.mended', node.mended);
  }
  // Only once there is a chain to have read. A node that holds no chain at
  // all has not fallen behind one; it has not been given one, and the lines
  // above and below say so.
  if (status.tip && !index.blocks) {
    return t('warn.indexEmpty', { blocks: count(index.behind) });
  }
  if (index.fromTheStart === false) {
    return t('warn.indexPartial', { from: count(index.from) });
  }
  if (index.behind > BEHIND_ENOUGH) {
    return t('warn.indexBehind', { blocks: count(index.behind) });
  }
  if (!status.peers) return t('warn.alone');

  /*
    The comparison `supply.counted` was added for and which nothing made.
    Two counts of the same money worked out from different things: the ledger
    from what each block was allowed to pay, the index from the notes
    themselves. They agree or one of them is wrong, and nobody could tell
    which while only one of the two was ever shown.
  */
  if (index.behind === 0 && status.supply.issued !== status.supply.counted) {
    return t('warn.supply', {
      issued: cairn(status.supply.issued),
      counted: cairn(status.supply.counted),
    });
  }
  return null;
}

/* ---------- the ticker ---------- */

const ticker = document.getElementById('ticker');
const footNode = document.getElementById('foot-node');
const notice = document.getElementById('notice');

/*
  Whether a read of the status is out, and how many in a row have failed.

  One at a time: on a site answering slowly, a fixed interval with nothing in
  flight checked queued another request every five seconds from every open
  tab, into a server with sixty four connections for everybody.

  And a failure is said. Every one used to be caught and dropped, so the
  height, the footer and the banner went on showing the last answer for as
  long as the tab stayed open, and a site that was down looked like a chain
  that was quiet.
*/
let ticking = false;
let misses = 0;
let answeredAt = 0;

/* How many failed reads in a row before the page says its figures are old. */
const MISSES_ENOUGH = 2;

async function refreshTicker() {
  if (ticking) return;
  ticking = true;
  try {
    await readStatus();
  } finally {
    ticking = false;
  }
}

async function readStatus() {
  let status;
  try {
    status = await api('status');
  } catch (error) {
    misses += 1;
    if (misses >= MISSES_ENOUGH) {
      clear(notice);
      notice.append(
        el('p', {
          text: answeredAt
            ? t('error.stale', { ago: duration(Math.round((Date.now() - answeredAt) / 1000)) })
            : t('error.unreachable'),
        })
      );
      notice.hidden = false;
      ticker.classList.add('stale');
    }
    return;
  }
  misses = 0;
  answeredAt = Date.now();
  ticker.classList.remove('stale');
  state.status = status;

  const said = trouble(status);
  clear(notice);
  if (said) notice.append(el('p', { text: said }));
  notice.hidden = !said;

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

  // Against the tip, which is the comparison this line existed without. A
  // count of blocks read means nothing on its own: the whole of what it says
  // is whether it is the same number as the chain's.
  footNode.textContent = t('foot.node', {
    network: status.network.name,
    blocks: count(status.indexed),
    height: count(status.tip ? status.tip.height + 1 : 0),
    genesis: shorten(status.network.genesis || '-', 12, 8),
  });

  await refreshChart(status.tip ? status.tip.height : null);
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
  for (const node of document.querySelectorAll('[data-t-label]')) {
    const value = t(node.getAttribute('data-t-label'));
    if (typeof value === 'string') node.setAttribute('aria-label', value);
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

/*
  The panel that asks how much a reader already knows.

  It is a dialog, and it was one only in its markup: focus stayed on the page
  behind it and Escape did nothing, so a keyboard or a screen reader met a
  modal it could neither find nor leave.
*/
function showWelcome() {
  welcome.hidden = false;
  const first = welcome.querySelector('[data-choose]');
  if (first) first.focus();
}

function closeWelcome(level) {
  applyLevel(level, true);
  welcome.hidden = true;
  translateStatic();
  render();
}

for (const button of document.querySelectorAll('[data-choose]')) {
  button.addEventListener('click', () => closeWelcome(button.getAttribute('data-choose')));
}

welcome.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeWelcome(state.level);
});

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
  if (!level) showWelcome();

  await render();
  await refreshTicker();
  state.timers.push(window.setInterval(refreshTicker, TICKER_PERIOD));
  state.timers.push(window.setInterval(tickLive, 1000));
}

start();

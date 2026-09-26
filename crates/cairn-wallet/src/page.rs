//! The page the wallet serves, built into the binary.
//!
//! One file, no fetching from anywhere. A wallet that pulled a stylesheet or a
//! script off the network would be a wallet whose appearance, and whose
//! behaviour, someone else gets to change.
//!
//! Slate and lichen, which is the chain's own palette: one living colour, and
//! it means the same thing here as everywhere else. Green for what a node
//! holds itself, blue for what it has let go of and keeps only as hashes. A
//! note that has fallen is blue on this page for exactly the reason it is blue
//! in the design document.

/// The whole of it: markup, style and the small amount of script it takes to
/// ask the wallet what it holds.
pub(crate) const HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Cairn wallet</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="page">

  <header>
    <h1>Cairn wallet</h1>
    <div class="chain">
      <span>network <b id="network">…</b></span>
      <span>height <b id="height">…</b></span>
      <span>peers <b id="peers">…</b></span>
      <span id="joining-wrap" hidden>joining <b id="joining"></b></span>
    </div>
  </header>

  <div class="alarm" id="warning" hidden></div>

  <section class="balance">
    <p class="label">Yours, and verified here</p>
    <div class="amount"><span id="spendable">…</span><span class="unit">CAIRN</span></div>
    <p class="note-line" id="held-line">Reading the chain.</p>
    <div class="stranded" id="waiting" hidden></div>
    <div class="stranded" id="not-carried" hidden></div>
    <div class="stranded" id="ripening" hidden></div>
    <div class="stranded" id="stranded" hidden></div>
<div class="stranded" id="unaccounted" hidden></div>
    <div class="stranded" id="undone" hidden></div>
  </section>

  <div class="grid">
    <section class="card">
      <h2>Receive</h2>
      <div class="address">
        <code class="mono" id="address">…</code>
        <button class="quiet" id="copy" type="button">Copy</button>
      </div>
      <p class="note-line">Anyone paying you needs these 64 characters and
        nothing else.</p>
    </section>

    <section class="card">
      <h2>Send</h2>
      <form id="send">
        <label>To
          <input class="mono" name="to" id="to" autocomplete="off"
                 spellcheck="false" placeholder="64 hexadecimal characters">
        </label>
        <div class="row">
          <label>Amount
            <input name="amount" id="amount" autocomplete="off"
                   inputmode="decimal" placeholder="the least the network carries">
          </label>
          <label>Fee
            <input name="fee" id="fee" autocomplete="off"
                   inputmode="decimal" placeholder="0.00">
          </label>
        </div>
        <p class="note-line" id="quote">Leave the fee blank for the least the
          network will carry, and a little over it in case a note of it falls
          out of the hot set before a block carries it.</p>
        <button id="go" type="submit">Send</button>
        <p class="said" id="said"></p>
      </form>
    </section>
  </div>

  <section class="card notes">
    <h2>What happened</h2>
    <div class="scroll">
      <table>
        <thead>
          <tr><th class="where">Way</th><th>Amount</th><th>Block</th></tr>
        </thead>
        <tbody id="moves"></tbody>
      </table>
    </div>
    <p class="note-line" id="moves-line">Reading the chain.</p>
  </section>

  <section class="card notes">
    <h2>Where it sits</h2>
    <div class="scroll">
      <table>
        <thead>
          <tr><th class="where">Where</th><th>Amount</th><th>From</th></tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <p class="note-line" id="notes-line"></p>
  </section>

  <footer>
    This page is served by the wallet on this machine and by nothing else. The
    key stays in its file and in the program that read it: nothing here has
    ever held it, and nothing here can sign. Closing the wallet closes the
    page.
  </footer>
</div>

<script src="/wallet.js"></script>
</body>
</html>
"#;

/// The style, served on its own because the policy this server sends
/// forbids a page from carrying its own, which is the right default and
/// worth keeping rather than loosening for one page.
pub(crate) const CSS: &str = r#"  :root{
    --ground:#12161A; --panel:#171C21; --sunk:#1B2127;
    --ink:#E4E8E2; --ink-2:#9BA5A0; --ink-3:#6C7873;
    --rule:#242B31; --rule-firm:#333C43;
    --held:#AAC04B; --held-soft:#1E2416;
    --fallen:#7FA3BC; --fallen-soft:#161E24;
    --warn:#D2A05A;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:var(--ground); color:var(--ink);
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    font-size:16px; line-height:1.55; -webkit-font-smoothing:antialiased;
  }
  .page{max-width:56rem;margin:0 auto;padding:0 clamp(1rem,4vw,2rem) 5rem}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

  header{padding:clamp(2rem,5vw,3.5rem) 0 1.5rem;display:flex;flex-wrap:wrap;
    align-items:baseline;gap:.6rem 1.2rem}
  h1{font-size:1.4rem;font-weight:600;letter-spacing:-.02em;margin:0}
  .chain{display:flex;flex-wrap:wrap;gap:.4rem .9rem;margin-left:auto;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:.72rem;letter-spacing:.04em;color:var(--ink-3)}
  .chain b{color:var(--ink-2);font-weight:500}

  .balance{border:1px solid var(--rule-firm);border-radius:5px;
    background:var(--panel);padding:1.6rem 1.7rem}
  .label{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:.66rem;letter-spacing:.16em;text-transform:uppercase;
    color:var(--ink-3);margin:0 0 .5rem}
  .amount{font-size:clamp(2rem,6vw,2.9rem);font-weight:600;letter-spacing:-.03em;
    line-height:1.1;font-variant-numeric:tabular-nums}
  .amount .unit{font-size:.42em;font-weight:500;color:var(--ink-2);
    letter-spacing:.04em;margin-left:.5rem}
  .note-line{margin:.55rem 0 0;font-size:.87rem;color:var(--ink-2)}

  .stranded{margin-top:1.1rem;border-left:3px solid var(--warn);
    background:#211A10;padding:.85rem 1rem;border-radius:0 4px 4px 0;
    font-size:.88rem;color:var(--ink-2)}
  .stranded b{color:var(--ink);font-weight:600}

  /* Louder than the boxes inside the balance, because what it says is that
     the balance is not this wallet's own answer. */
  .alarm{margin-top:1rem;border:1px solid #C4746A;border-left:3px solid #C4746A;
    background:#251A1A;padding:.9rem 1.05rem;border-radius:4px;
    font-size:.88rem;line-height:1.55;color:var(--ink-2)}
  .alarm b{color:var(--ink);font-weight:600}
  .said button{margin-top:.6rem;font-size:.8rem;padding:.45rem .8rem;
    background:var(--warn)}

  .grid{display:grid;gap:1rem;margin-top:1rem}
  @media (min-width:50rem){.grid{grid-template-columns:1fr 1fr}}
  .card{border:1px solid var(--rule);border-radius:5px;background:var(--panel);
    padding:1.25rem 1.35rem}
  .card h2{margin:0 0 .9rem;font-size:.66rem;font-weight:500;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3)}

  .address{display:flex;gap:.6rem;align-items:flex-start}
  .address code{flex:1 1 auto;word-break:break-all;font-size:.78rem;
    line-height:1.6;color:var(--ink);background:var(--sunk);
    border:1px solid var(--rule);border-radius:4px;padding:.6rem .7rem}
  button{font:inherit;font-size:.84rem;color:var(--ground);
    background:var(--held);border:0;border-radius:4px;padding:.55rem 1rem;
    cursor:pointer;font-weight:600;white-space:nowrap}
  button:hover{filter:brightness(1.08)}
  button:disabled{background:var(--rule-firm);color:var(--ink-3);cursor:default;
    filter:none}
  button.quiet{background:transparent;color:var(--ink-2);
    border:1px solid var(--rule-firm);font-weight:500}
  button.quiet:hover{color:var(--ink);border-color:var(--ink-3);filter:none}
  :focus-visible{outline:2px solid var(--held);outline-offset:2px}

  form{display:grid;gap:.8rem}
  label{display:grid;gap:.3rem;font-size:.8rem;color:var(--ink-2)}
  input{font:inherit;font-size:.86rem;color:var(--ink);background:var(--sunk);
    border:1px solid var(--rule-firm);border-radius:4px;padding:.55rem .7rem;
    width:100%}
  input:focus{border-color:var(--held);outline:none}
  input.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:.78rem}
  .row{display:grid;gap:.8rem;grid-template-columns:1fr 1fr}
  .said{margin:0;font-size:.86rem;line-height:1.5;padding:.75rem .85rem;
    border-radius:4px;display:none}
  .said.bad{display:block;background:#251A1A;border-left:3px solid #C4746A;
    color:var(--ink-2)}
  .said.good{display:block;background:var(--held-soft);
    border-left:3px solid var(--held);color:var(--ink-2)}
  .said b{color:var(--ink)}
  .said code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:.76rem;word-break:break-all;color:var(--ink)}

  .notes{margin-top:1rem}
  table{width:100%;border-collapse:collapse;font-size:.84rem}
  th{text-align:left;font-weight:500;font-size:.66rem;letter-spacing:.14em;
    text-transform:uppercase;color:var(--ink-3);padding:0 0 .5rem;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  td{padding:.5rem 0;border-top:1px solid var(--rule);vertical-align:top}
  td.value{font-variant-numeric:tabular-nums;white-space:nowrap}
  td.where{width:1%;white-space:nowrap;padding-right:1rem}
  .tag{display:inline-block;font-size:.64rem;letter-spacing:.1em;
    text-transform:uppercase;padding:.15rem .45rem;border-radius:3px;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .tag.held{background:var(--held-soft);color:var(--held)}
  .tag.fallen{background:var(--fallen-soft);color:var(--fallen)}
  .tag.sent{background:#241A14;color:var(--warn)}
  .tag.received,.tag.mined{background:var(--held-soft);color:var(--held)}
  td.when{color:var(--ink-3);font-size:.72rem;white-space:nowrap;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  td.src{color:var(--ink-3);font-size:.72rem;word-break:break-all;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

  footer{margin-top:2rem;font-size:.8rem;color:var(--ink-3);line-height:1.6}
  .scroll{overflow-x:auto}
"#;

/// The script, for the same reason.
///
/// Hashed twice, because it writes a block number as `"#" + height` and one
/// hash would end the string there.
pub(crate) const JS: &str = r##""use strict";
// The secret that came in the address. Kept in memory and put back on every
// request; the wallet answers nothing without it.
const KEY = new URLSearchParams(location.search).get("k") || "";

const $ = (id) => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value; };

// A line of words, put in as text and never as markup, for anything the
// wallet says that is not a number.
const line = (words) => {
  const div = document.createElement("div");
  div.textContent = words;
  return div;
};
const bold = (words) => {
  const b = document.createElement("b");
  b.textContent = words;
  return b;
};

// The first and last eight characters of an address, which is what a person
// compares by eye.
const ends = (address) => address.slice(0, 8) + "…" + address.slice(-8);

// When the wallet last answered, so a page whose wallet has stopped can say
// how old its figures are.
let answeredAt = null;

// A poll that got no answer. The figures stay, because they are the last ones
// there were, and the box above them says how old they are. Returning without
// a word left a balance and a height from a wallet that had exited, or been
// restarted with a new address, looking exactly like current ones.
function unanswered(why) {
  const warning = $("warning");
  warning.hidden = false;
  warning.textContent = why + (answeredAt === null
    ? " Nothing below has been read from it yet."
    : " Not answering since " + answeredAt.toLocaleTimeString() +
      "; the figures below are from then.");
}

async function refresh() {
  let state;
  try {
    const answer = await fetch("/api/state?k=" + encodeURIComponent(KEY));
    if (answer.status === 403) {
      unanswered("The address of this page has changed: open the one the wallet printed.");
      return;
    }
    if (!answer.ok) {
      unanswered("The wallet answered with an error.");
      return;
    }
    state = await answer.json();
  } catch (_) {
    unanswered("The wallet is not answering. Is it still running?");
    return;
  }
  answeredAt = new Date();

  text("network", state.network);
  text("height", state.height === null ? "…" : state.height);
  text("peers", state.peers);
  text("address", state.address);
  text("spendable", state.spendable.replace(" CAIRN", ""));

  const joining = state.joining !== "no" && state.joining !== "done";
  $("joining-wrap").hidden = !joining;
  if (joining) { text("joining", state.joining); }

  // The node can be in three states where a height and a balance mean nothing,
  // and all three look from here like a wallet that is working.
  const warning = $("warning");
  warning.hidden = state.warning === null;
  if (state.warning !== null) { warning.textContent = state.warning; }

  // A payment handed over is not a payment made. Until a block carries it the
  // balance has not moved and the notes it holds cannot be spent again, and a
  // person pressing Send twice because nothing happened is the whole reason
  // this line is here.
  const waiting = $("waiting");
  waiting.hidden = state.payments.length === 0 && state.paymentsUnkept === null;
  waiting.replaceChildren();
  if (state.paymentsUnkept !== null) { waiting.append(line(state.paymentsUnkept)); }
  if (state.payments.length > 0) {
    const total = state.payments.map((p) => p.amount).join(", ");
    const head = document.createElement("div");
    head.innerHTML = "<b>" + state.payments.length +
      (state.payments.length === 1 ? " payment is" : " payments are") +
      " waiting for a block</b>: " + total + ". Nothing has been paid yet, and " +
      "only a block confirms a payment. A block takes a few minutes; the " +
      "balance moves when one carries it. Do not send one again while it is " +
      "listed here.";
    waiting.append(head);
    // One the wallet's node does not hold says why, and until when its notes
    // stay held.
    for (const p of state.payments) {
      if (p.why === null) { continue; }
      waiting.append(line(p.amount + " is not held by this wallet's node: " + p.why + "." +
        (p.heldUntil === null ? "" : " Its notes stay held until block " + p.heldUntil + ".")));
    }
  }

  // A payment the wallet stopped waiting on without a block carrying it. The
  // box above used to empty and the balance go back up, which is exactly
  // what a carried payment looks like, and nobody was told it was not coming.
  const notCarried = $("not-carried");
  notCarried.hidden = state.notCarried.length === 0;
  notCarried.replaceChildren();
  if (state.notCarried.length > 0) {
    const head = document.createElement("div");
    head.innerHTML = "<b>Not carried by any block</b>, so nobody was paid by " +
      (state.notCarried.length === 1 ? "it" : "them") + ". The money is back in " +
      "the balance above; if one should still be paid, send it again.";
    notCarried.append(head);
    for (const p of state.notCarried) {
      notCarried.append(line(p.amount + ", stopped waiting on at block " + p.at + ": " + p.why + "."));
    }
  }

  // Money that moved and then did not, because the chain the wallet had read
  // turned out not to be the one that won.
  const undone = $("undone");
  undone.hidden = state.undone.length === 0;
  if (state.undone.length > 0) {
    const held = new Set(state.payments.map((p) => p.id));
    const lines = state.undone.map((m) =>
      m.way + " " + m.amount + " at block " + m.height +
      (held.has(m.id) ? ", waiting for a block again" : ""));
    // Said before the closing sentence, because the closing sentence is what
    // makes the list read as complete: what it says became of the money is
    // about the ones named, and somebody whose payment is not named takes it
    // to mean theirs went through.
    const rest = state.undone_held > state.undone.length
      ? " Showing the newest " + state.undone.length + " of " +
        state.undone_held + "; the rest are not listed here."
      : "";
    undone.innerHTML = "<b>The chain changed and took these back.</b> They " +
      "were in this wallet's account of itself and the chain no longer " +
      "carries them: " + lines.join("; ") + "." + rest + " " + state.undoneNote;
  }

  const ripening = $("ripening");
  const ripeningZero = state.ripening.startsWith("0.00000000");
  ripening.hidden = ripeningZero;
  if (!ripeningZero) {
    ripening.textContent = state.ripening + " is in block rewards that " +
      "cannot be spent yet" +
      (state.ripeAt === null ? ". " : ", the first at block " + state.ripeAt + ". ") +
      "A reward is the one kind of money whose existence depends on its " +
      "block surviving, so the rules hold it still until nothing can undo it.";
  }

  const stranded = $("stranded");
  stranded.hidden = state.strandedNote === null;
  if (state.strandedNote !== null) {
    const zero = state.stranded.startsWith("0.00000000");
    stranded.innerHTML = (zero ? "" : "<b>" + state.stranded + "</b> is in " +
      "notes that cannot move yet. ") + state.strandedNote;
  }

  const unaccounted = $("unaccounted");
  unaccounted.hidden = state.unaccountedNote === null;
  if (state.unaccountedNote !== null) {
    unaccounted.textContent = state.unaccountedNote;
  }

  const rows = $("rows");
  rows.replaceChildren();
  for (const note of state.notes) {
    const row = document.createElement("tr");
    const where = document.createElement("td");
    where.className = "where";
    const tag = document.createElement("span");
    tag.className = "tag " + (note.cold ? "fallen" : "held");
    tag.textContent = note.cold ? "fallen" : "held";
    where.append(tag);
    const value = document.createElement("td");
    value.className = "value";
    value.textContent = note.value;
    const src = document.createElement("td");
    src.className = "src";
    src.textContent = note.source.slice(0, 16) + "… #" + note.index;
    row.append(where, value, src);
    rows.append(row);
  }

  const moves = $("moves");
  moves.replaceChildren();
  for (const movement of state.movements) {
    const row = document.createElement("tr");
    const way = document.createElement("td");
    way.className = "where";
    const tag = document.createElement("span");
    tag.className = "tag " + movement.way;
    tag.textContent = movement.way;
    way.append(tag);
    const value = document.createElement("td");
    value.className = "value";
    value.textContent = (movement.way === "sent" ? "\u2212 " : "+ ") + movement.amount;
    const when = document.createElement("td");
    when.className = "when";
    when.textContent = "#" + movement.height + " · " +
      new Date(movement.at * 1000).toLocaleString();
    row.append(way, value, when);
    moves.append(row);
  }
  const said = [];
  if (state.movements.length === 0) {
    said.push(state.history_from === null
      ? "Nothing yet."
      : "Nothing since block " + state.history_from + ", which is as far back as this wallet read.");
  } else if (state.history_from > 0) {
    said.push("As far back as block " + state.history_from + ": this wallet did not read what came before.");
  }
  // A gap in the middle, which nothing about the list gives away: the blocks
  // below it were read and are here, and the ones inside it look from here
  // like a stretch in which nothing happened.
  if (state.history_missed_below !== null) {
    said.push("Could not read every block up to " + state.history_missed_below +
      ": the node had let go of them. Anything that happened to this key in the " +
      "ones it missed is not listed. What can be spent is counted from the chain, " +
      "not from this list; notes this wallet lost track of there are named apart.");
  }
  if (state.movements_held > state.movements.length) {
    said.push("Showing the newest " + state.movements.length + " of " + state.movements_held + ".");
  }
  // A list that stops short of the chain and does not say so is a list that
  // says something untrue about somebody's money.
  if (state.history_behind > 0) {
    said.push("Still reading: " + state.history_behind +
      (state.history_behind === 1 ? " block" : " blocks") +
      " of the chain are not in this list yet.");
  }
  text("moves-line", said.join(" "));

  // Three states, not two. A wallet with no note a spend can reach for is not
  // the same as a wallet with nothing in it: a reward too young to move, a
  // payment already holding every note, and a note whose proof is out of reach
  // all leave this count at nought. Reading them as an empty wallet printed
  // "Nothing here yet" directly above the line naming the amount.
  const held = state.held;
  const fallen = state.fallen;
  // Nothing at all is said in the wallet's own words, which name the account
  // file when the account begins above the first block. The page said to
  // check the height, which no height answers for somebody restored from the
  // key alone.
  text("held-line", !state.anything
    ? state.nothingHere
    : held === 0
    ? "Nothing here can be spent right now."
    : held + (held === 1 ? " note" : " notes") + ", " + fallen + " of them fallen to the cold set.");
  text("notes-line", state.notes.length < held
    ? "Showing the first " + state.notes.length + " of " + held + "."
    : "");
}

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("address").textContent);
    $("copy").textContent = "Copied";
    setTimeout(() => { $("copy").textContent = "Copy"; }, 1500);
  } catch (_) {
    // A browser that refuses the clipboard leaves the address selectable,
    // which is what it was before there was a button.
    getSelection().selectAllChildren($("address"));
  }
});

const typed = () => new URLSearchParams({
  k: KEY,
  to: $("to").value.trim(),
  amount: $("amount").value.trim(),
  fee: $("fee").value.trim(),
});

const post = (path, body) => fetch(path, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: body.toString(),
}).then((answer) => answer.json());

// What carrying it costs, said before it is paid rather than after. The fee
// box takes a number nothing else on this page ever showed back, and one
// keystroke is the difference between a fee of 0.00005 and a fee of 5.
let quoting = 0;
async function quote() {
  const mine = ++quoting;
  const blank = "Leave the fee blank for the least the network will carry, and a " +
    "little over it in case a note of it falls out of the hot set before a block carries it.";
  if ($("to").value.trim().length !== 64 || $("amount").value.trim() === "") {
    text("quote", blank);
    return;
  }
  let result;
  try { result = await post("/api/quote", typed()); } catch (_) { return; }
  if (mine !== quoting) { return; }
  if (!result.quoted) { text("quote", blank); return; }
  text("quote", "Sending " + result.amount + " to " + ends(result.to) + " and paying " +
    result.fee + " to carry it, " + result.total + " in all. The network asks " +
    result.floor + "." + (result.toItself
      ? " That is this wallet's own address: nothing leaves it but the fee."
      : ""));
}

for (const box of ["to", "amount", "fee"]) {
  $(box).addEventListener("input", quote);
}

async function spend(anyway) {
  const said = $("said");
  const go = $("go");
  said.className = "said";
  go.disabled = true;
  go.textContent = "Sending…";

  const body = typed();
  if (anyway) { body.set("anyway", "1"); }

  try {
    const result = await post("/api/send", body);
    if (result.sent) {
      // A transfer nobody was offered is not good news wearing a green box.
      // And one that was offered is a socket write and no more: no message in
      // the protocol answers a transfer, so this says what was measured and
      // that only a block confirms it. It said the payment was handed over.
      said.className = result.handed_on ? "said good" : "said bad";
      said.replaceChildren();
      const code = document.createElement("code");
      code.textContent = result.id;
      if (result.handed_on) {
        said.append(bold("Written to " + result.offered +
            (result.offered === 1 ? " peer" : " peers") + "; only a block confirms it."),
          " ", bold(result.amount), " to be paid to ", bold(ends(result.to)), ", ",
          bold(result.fee), " to carry it. Whether a peer kept it, nothing in the network " +
          "says. It is listed above as waiting for a block, which takes a few minutes, " +
          "and nobody has been paid yet.");
      } else {
        // Kept rather than taken back: this wallet offers it to every peer it
        // reaches, now and the next time it opens. It used to say the money
        // was still here, beside a box showing the same payment waiting with
        // its notes held, and nothing ever offered it to anyone.
        said.append(bold("No peer has been offered it yet."), " This wallet reached " +
          "nobody to give it to. It is kept, and offered to every peer this wallet " +
          "reaches while it is open and the next time it opens; until then nobody has " +
          "it and nobody has been paid. Its notes stay held for it, so do not send it " +
          "again: it is listed above as waiting.");
      }
      said.append(document.createElement("br"), code);
      $("to").value = ""; $("amount").value = ""; $("fee").value = "";
      quote();
    } else if (result.steep) {
      // The one refusal a person is allowed to overrule, because paying over
      // the odds to be carried sooner is a thing people mean to do.
      said.className = "said bad";
      said.textContent = result.error;
      const again = document.createElement("button");
      again.type = "button";
      again.textContent = "Pay that fee, I mean it";
      again.addEventListener("click", () => spend(true));
      said.append(document.createElement("br"), again);
    } else {
      said.className = "said bad";
      said.textContent = result.error;
    }
  } catch (_) {
    // Not "it did not go": the answer is what was lost, and the payment may
    // have been handed over before it was. A payment that was is listed as
    // waiting, and the wallet refuses the same one again while it is.
    said.className = "said bad";
    said.textContent = "The wallet stopped answering before it said what became of this " +
      "payment. Is it still running? Look at the payments waiting above before sending " +
      "it again.";
  }
  go.disabled = false;
  go.textContent = "Send";
  refresh();
}

$("send").addEventListener("submit", (event) => {
  event.preventDefault();
  spend(false);
});

refresh();
setInterval(refresh, 2000);
"##;

#[cfg(test)]
mod tests {
    use super::JS;

    /// The script's `refresh`, from its first line to the next function.
    fn refresh() -> &'static str {
        let start = JS.find("async function refresh()").unwrap_or(0);
        let rest = JS.get(start..).unwrap_or("");
        let end = rest
            .get(1..)
            .and_then(|after| {
                after
                    .find("\nasync function ")
                    .or_else(|| after.find("\n$("))
            })
            .map_or(rest.len(), |at| at.saturating_add(1));
        rest.get(..end).unwrap_or(rest)
    }

    /// A poll the wallet does not answer is said on the page, with how old
    /// the figures under it are, and not passed over.
    ///
    /// `refresh` returned on a failed poll without a word, so a tab whose
    /// wallet had exited, or been started again on a new address, went on
    /// showing the last balance and height as if they were current. Nothing
    /// read the script, so that passed.
    #[test]
    fn a_wallet_that_stops_answering_is_said_on_the_page() {
        let refresh = refresh();
        assert!(
            !refresh.contains("{ return; }"),
            "a poll that got no answer returns without writing anything to the page"
        );
        assert!(
            JS.contains("Not answering since"),
            "the page does not say how old its figures are once the wallet stops answering"
        );
        assert!(
            refresh.contains("403"),
            "a page whose address the wallet no longer answers is not told to open the new one"
        );
    }

    /// A page showing a wallet that holds nothing says what the command line
    /// says: where the account begins, and that below it only the account
    /// file can find money that fell, rather than sending its owner to look
    /// at the network.
    ///
    /// The command line was taught this and the page was not: it said "check
    /// the height above" to somebody restored from the key alone, whose
    /// missing money no height will ever show. Nothing read the page's
    /// sentence, so a page that pointed at the wrong cause passed.
    #[test]
    fn an_empty_wallet_is_told_on_the_page_what_the_command_line_tells_it() {
        assert!(
            !JS.contains("check the height above"),
            "the page sends somebody whose account begins late to look at the height"
        );
        assert!(
            JS.contains("state.nothingHere"),
            "the page does not say what the wallet says about holding nothing"
        );
        assert!(
            JS.contains("which is as far back as this wallet read."),
            "the page says where its list begins in other words than the command line"
        );
    }

    /// What the page says once a payment is sent is what was measured, and
    /// names who is being paid, before and after.
    ///
    /// It said "Handed over" for a socket write that no peer answers, and the
    /// sentences read before and after pressing Send named an amount and a
    /// fee and nobody, while a page elsewhere in the same browser can put its
    /// own key on the clipboard the person pastes from.
    #[test]
    fn a_sent_payment_is_said_as_what_was_measured_and_to_whom() {
        assert!(
            !JS.contains("Handed over"),
            "the page still says a payment was handed over"
        );
        assert!(JS.contains("only a block confirms it"));
        assert_eq!(
            JS.matches("ends(result.to)").count(),
            2,
            "the recipient is not said back both in the quote and once it is sent"
        );
        assert!(
            JS.contains("result.toItself"),
            "a payment to this wallet's own address is not said to be one"
        );
    }
}

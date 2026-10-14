'use strict';

// callouts.js — ONE consistent annotation style for every tour image.
//
// injectCalloutsInPage(rects) runs IN THE PAGE (passed to page.evaluate). It receives an array of
// pre-computed { n, label, rect:{x,y,width,height} } objects (viewport coordinates, resolved
// driver-side via locator.boundingBox()) and appends a single position:fixed, full-viewport <svg>
// overlay to document.body. It resolves NO selectors itself — Playwright locators are driver-side
// handles not usable inside the page, so passing rects removes that ambiguity.
//
// Locked style (design A.4): amber #ff9900 numbered pills, #16191f number text + 1.5px #16191f
// leader lines, white label chips with 1px #879596 border, 8px radius, 13px system-ui #16191f text,
// subtle rgba(0,0,0,0.12) drop shadow. Numbered 1..N top-to-bottom (caller orders the array).
//
// This function body is serialized and executed in the browser, so it must be self-contained and
// use only browser globals (document, window). Exported both as a function (for page.evaluate) and
// as a convenience helper injectCallouts(page, rects) for the driver side.

function injectCalloutsInPage(rects) {
  var SVGNS = 'http://www.w3.org/2000/svg';
  var vw = window.innerWidth;
  var vh = window.innerHeight;

  // Remove any previous overlay so re-runs are idempotent.
  var prev = document.getElementById('__capture_callouts__');
  if (prev) prev.remove();

  var svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('id', '__capture_callouts__');
  svg.setAttribute('width', String(vw));
  svg.setAttribute('height', String(vh));
  svg.setAttribute('viewBox', '0 0 ' + vw + ' ' + vh);
  // Tiny CSS reset so chips do not inherit Cloudscape fonts/line-height.
  svg.style.cssText =
    'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;' +
    'pointer-events:none;margin:0;padding:0;';

  // Drop-shadow filter for pills and chips.
  var defs = document.createElementNS(SVGNS, 'defs');
  defs.innerHTML =
    '<filter id="__co_shadow__" x="-20%" y="-20%" width="140%" height="140%">' +
    '<feDropShadow dx="0" dy="1" stdDeviation="1.5" flood-color="rgba(0,0,0,0.12)"/></filter>';
  svg.appendChild(defs);

  var AMBER = '#ff9900';
  var INK = '#16191f';
  var BORDER = '#879596';
  var R = 15; // pill radius
  var CHIP_H = 26;
  var CHIP_PAD = 10;
  var CHAR_W = 7; // approx advance for 13px system-ui

  // Track occupied chip rectangles so later callouts nudge to avoid overlap.
  var placed = [];
  function overlaps(a, b) {
    return !(a.x + a.w < b.x || b.x + b.w < a.x || a.y + a.h < b.y || b.y + b.h < a.y);
  }

  rects.forEach(function (c) {
    var rect = c.rect;
    // Target edge: point the leader at the left-middle of the target.
    var tx = rect.x;
    var ty = rect.y + Math.min(rect.height / 2, 18);

    // Decide pill side. For targets near the top edge (e.g. top-nav), drop the pill BELOW the
    // target so the chip does not collide with the browser/app chrome. Otherwise place it to the
    // left when there is room, else to the right.
    var pillCx, pillCy;
    var nearTop = rect.y < 70;
    if (nearTop) {
      tx = rect.x + rect.width / 2;
      ty = rect.y + rect.height;
      pillCx = Math.min(vw - R - 2, Math.max(R + 2, rect.x + rect.width + R + 10));
      pillCy = ty + R + 10;
    } else if (tx > R * 2 + 180) {
      pillCx = Math.max(R + 2, tx - 150);
      pillCy = ty;
    } else {
      pillCx = Math.min(vw - R - 2, tx + rect.width + R + 20);
      pillCy = Math.max(R + 2, ty);
    }

    // Leader line pill -> target edge.
    var line = document.createElementNS(SVGNS, 'line');
    line.setAttribute('x1', String(pillCx));
    line.setAttribute('y1', String(pillCy));
    line.setAttribute('x2', String(tx));
    line.setAttribute('y2', String(ty));
    line.setAttribute('stroke', INK);
    line.setAttribute('stroke-width', '1.5');
    svg.appendChild(line);

    // Small marker dot on the target edge.
    var dot = document.createElementNS(SVGNS, 'circle');
    dot.setAttribute('cx', String(tx));
    dot.setAttribute('cy', String(ty));
    dot.setAttribute('r', '3');
    dot.setAttribute('fill', INK);
    svg.appendChild(dot);

    // Label chip to the left of the pill (or above it near the edge).
    var text = String(c.label);
    var chipW = CHIP_PAD * 2 + text.length * CHAR_W;
    var chipX, chipY;
    if (nearTop) {
      // Chip to the RIGHT of the pill for top-row callouts.
      chipX = Math.min(vw - chipW - 2, pillCx + R + 6);
      chipY = pillCy - CHIP_H / 2;
    } else {
      chipX = pillCx - R - 6 - chipW;
      chipY = pillCy - CHIP_H / 2;
      if (chipX < 2) {
        // Not enough room to the left: place chip below the pill.
        chipX = Math.max(2, Math.min(vw - chipW - 2, pillCx - chipW / 2));
        chipY = pillCy + R + 6;
      }
    }

    // Nudge vertically to avoid overlapping an already-placed chip.
    var guard = 0;
    while (guard < 12 && placed.some(function (p) { return overlaps({ x: chipX, y: chipY, w: chipW, h: CHIP_H }, p); })) {
      chipY += CHIP_H + 6;
      guard++;
    }
    placed.push({ x: chipX, y: chipY, w: chipW, h: CHIP_H });

    var chip = document.createElementNS(SVGNS, 'rect');
    chip.setAttribute('x', String(chipX));
    chip.setAttribute('y', String(chipY));
    chip.setAttribute('width', String(chipW));
    chip.setAttribute('height', String(CHIP_H));
    chip.setAttribute('rx', '8');
    chip.setAttribute('ry', '8');
    chip.setAttribute('fill', '#ffffff');
    chip.setAttribute('stroke', BORDER);
    chip.setAttribute('stroke-width', '1');
    chip.setAttribute('filter', 'url(#__co_shadow__)');
    svg.appendChild(chip);

    var label = document.createElementNS(SVGNS, 'text');
    label.setAttribute('x', String(chipX + CHIP_PAD));
    label.setAttribute('y', String(chipY + CHIP_H / 2 + 4));
    label.setAttribute('font-family', 'system-ui, -apple-system, Segoe UI, Roboto, sans-serif');
    label.setAttribute('font-size', '13');
    label.setAttribute('fill', INK);
    label.textContent = text;
    svg.appendChild(label);

    // Numbered amber pill on top of the chip's inner edge.
    var pill = document.createElementNS(SVGNS, 'circle');
    pill.setAttribute('cx', String(pillCx));
    pill.setAttribute('cy', String(pillCy));
    pill.setAttribute('r', String(R));
    pill.setAttribute('fill', AMBER);
    pill.setAttribute('filter', 'url(#__co_shadow__)');
    svg.appendChild(pill);

    var num = document.createElementNS(SVGNS, 'text');
    num.setAttribute('x', String(pillCx));
    num.setAttribute('y', String(pillCy + 5));
    num.setAttribute('text-anchor', 'middle');
    num.setAttribute('font-family', 'system-ui, -apple-system, Segoe UI, Roboto, sans-serif');
    num.setAttribute('font-size', '15');
    num.setAttribute('font-weight', '700');
    num.setAttribute('fill', INK);
    num.textContent = String(c.n);
    svg.appendChild(num);
  });

  document.body.appendChild(svg);
  return true;
}

// Driver-side convenience: inject the overlay from an array already shaped as { n, label, rect }.
async function injectCallouts(page, rects) {
  await page.evaluate(injectCalloutsInPage, rects);
}

module.exports = { injectCallouts, injectCalloutsInPage };

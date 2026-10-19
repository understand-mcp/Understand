"""Render a code map as one self-contained HTML file.

The file is opened in a browser, not read as text, so the renderer is a
canvas with a camera rather than a static SVG: a repository map routinely
holds thousands of nodes, and an SVG with one DOM element per node becomes
unusable around two thousand of them. The three constraints are unchanged
from the SVG version and still hold:

* no network access - everything is in the file;
* no ``innerHTML`` - repository-derived strings are only ever written with
  ``textContent``, so a file containing ``<img onerror=...>`` renders as
  that literal text instead of becoming an element;
* the embedded JSON escapes ``<``, ``>`` and ``&``, so a repository string
  containing ``</script>`` cannot break out of the data block.

Positions arrive pre-computed in the model. Layout runs in Python, not in
the browser, which is what makes two renders of the same scan byte
identical and the output diffable in a pull request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import ResourceLimitExceeded

__all__ = ["MAX_MAP_BYTES", "render_map_html", "write_map_html"]

MAX_MAP_BYTES = 80 * 1024 * 1024


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #0d1117;
    --panel: #131a23;
    --line: #26303d;
    --text: #d7dee8;
    --muted: #8b98a9;
    --accent: #4aa8ff;
    --critical: #ff4d4f;
    --high: #ff9f43;
    --medium: #ffd93d;
    --low: #4aa8ff;
    --info: #7d8896;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font: 13px/1.5 ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  header {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
    flex: 0 0 auto;
  }
  header h1 { font-size: 14px; margin: 0; font-weight: 600; white-space: nowrap; }
  header .sub { color: var(--muted); font-size: 12px; white-space: nowrap; }
  header input[type=search] {
    flex: 1 1 auto;
    min-width: 120px;
    background: #0b1017;
    border: 1px solid var(--line);
    color: var(--text);
    border-radius: 6px;
    padding: 6px 10px;
    font: inherit;
  }
  main { flex: 1 1 auto; display: flex; min-height: 0; }
  #stage { position: relative; flex: 1 1 auto; min-width: 0; }
  #map { display: block; width: 100%; height: 100%; cursor: grab; touch-action: none; }
  #map.dragging { cursor: grabbing; }
  #controls {
    position: absolute; right: 12px; bottom: 12px;
    display: flex; flex-direction: column; gap: 4px;
  }
  #controls button {
    width: 30px; height: 30px; border-radius: 6px;
    background: var(--panel); color: var(--text);
    border: 1px solid var(--line); cursor: pointer; font: inherit;
  }
  #controls button:hover { border-color: var(--accent); }
  #minimap {
    position: absolute; right: 12px; top: 12px;
    border: 1px solid var(--line); border-radius: 6px;
    background: #0b1017; cursor: pointer;
  }
  /* A minimap over a six-node map covers the map it is meant to locate.
     It earns its space only once there are enough nodes to be lost in. */
  #minimap[hidden] { display: none; }
  #panel {
    flex: 0 0 340px; border-left: 1px solid var(--line);
    background: var(--panel); padding: 12px 14px;
    overflow: auto; min-width: 0;
  }
  #panel h2 { font-size: 13px; margin: 0 0 4px; overflow-wrap: anywhere; }
  #panel h3 { font-size: 12px; margin: 14px 0 6px; color: var(--muted);
              text-transform: uppercase; letter-spacing: .05em; }
  #panel .kv { color: var(--muted); }
  #panel ul { margin: 4px 0; padding-left: 16px; }
  #panel li { margin: 2px 0; overflow-wrap: anywhere; }
  #panel code { color: var(--accent); }
  /* Detail needs room. A finding explanation is several paragraphs plus a code
     block; at 340px it wrapped into an unreadable column, so the panel grows
     when a node with detail is selected and shrinks back when nothing is. */
  #panel.wide { flex-basis: 460px; }
  #panel pre {
    background: #0b1017; border: 1px solid var(--line); border-radius: 6px;
    padding: 8px 10px; margin: 6px 0; overflow-x: auto;
    font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    white-space: pre; tab-size: 2;
  }
  #panel pre.wrap { white-space: pre-wrap; overflow-wrap: anywhere; }
  #panel .finding {
    border: 1px solid var(--line); border-left-width: 3px;
    border-radius: 6px; padding: 8px 10px; margin: 8px 0; background: #0d131b;
  }
  #panel .finding.critical { border-left-color: var(--critical); }
  #panel .finding.high { border-left-color: var(--high); }
  #panel .finding.medium { border-left-color: var(--medium); }
  #panel .finding.low { border-left-color: var(--low); }
  #panel .finding.info { border-left-color: var(--info); }
  #panel .finding .head { display: flex; gap: 8px; flex-wrap: wrap; align-items: baseline; }
  #panel .finding .sev { font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
  #panel .finding .sev.critical { color: var(--critical); }
  #panel .finding .sev.high { color: var(--high); }
  #panel .finding .sev.medium { color: var(--medium); }
  #panel .finding .sev.low { color: var(--low); }
  #panel .finding .sev.info { color: var(--info); }
  #panel .finding .title { font-weight: 600; overflow-wrap: anywhere; }
  #panel .finding p { margin: 6px 0; overflow-wrap: anywhere; }
  #panel .finding .field { margin: 6px 0; }
  #panel .finding .field .label {
    color: var(--muted); text-transform: uppercase; letter-spacing: .05em;
    font-size: 10px; display: block; margin-bottom: 2px;
  }
  #panel .finding .unproven { color: var(--medium); }
  /* A data-flow chain is an ordered argument: source, hops, sink. Numbering it
     is what turns a list of strings into something a reader can follow. */
  #panel ul.swatches { list-style: none; margin: 4px 0; padding: 0; }
    #panel ul.swatches li { display: flex; align-items: center; gap: 8px; }
    #panel .swatch {
      width: 16px; height: 12px; border-radius: 3px; border-style: solid;
      background: #1a222d; display: inline-block;
    }
    #panel .chain { margin: 4px 0; padding-left: 0; list-style: none; counter-reset: hop; }
  #panel .chain li {
    counter-increment: hop; position: relative; padding-left: 22px; margin: 3px 0;
  }
  #panel .chain li::before {
    content: counter(hop); position: absolute; left: 0; top: 0;
    width: 16px; height: 16px; border-radius: 50%; text-align: center;
    font-size: 10px; line-height: 16px; background: var(--line); color: var(--text);
  }
  #panel .section-toggle {
    background: none; border: none; color: var(--accent); cursor: pointer;
    font: inherit; padding: 0; text-align: left; width: 100%;
  }
  #status {
    flex: 0 0 auto; border-top: 1px solid var(--line);
    background: var(--panel); padding: 6px 14px;
    color: var(--muted); font-size: 12px;
    display: flex; gap: 16px; flex-wrap: wrap;
  }
  #status .warn { color: var(--high); }
  .hint { color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>__TITLE__</h1>
  <span class="sub" id="subtitle"></span>
  <input type="search" id="filter" placeholder="filter nodes by name or path (press / to focus)">
</header>
<main>
  <div id="stage">
    <canvas id="map"></canvas>
    <canvas id="minimap" width="180" height="130"></canvas>
    <div id="controls">
      <button id="zin" title="zoom in">+</button>
      <button id="zout" title="zoom out">&minus;</button>
      <button id="zfit" title="fit to contents">&#9633;</button>
    </div>
  </div>
  <aside id="panel"></aside>
</main>
<div id="status"></div>
<script id="map-data" type="application/json">__DATA__</script>
<script>
(function () {
  "use strict";
  var MODEL = JSON.parse(document.getElementById("map-data").textContent);
  var NODES = MODEL.nodes || [];
  var EDGES = MODEL.edges || [];
  var LEGEND = MODEL.legend || {};
  var STATS = MODEL.stats || {};
  var HONESTY = MODEL.honesty || {};

  var LABEL_MIN_PX = 8;      // below this rendered size a label is unreadable
  var HIDE_EDGES_ON_MOVE_NODES = 5000;
  var HIDE_EDGES_ON_MOVE_EDGES = 10000;
  // Edge budget by zoom. Drawing every edge of a 3,000-module repository at
  // fit-to-view produces a solid wall that hides the diagram underneath it.
  // The subset is a stable prefix of a priority order, so the picture never
  // flickers as the camera moves, and the status bar says how many were left
  // out rather than implying the picture is complete.
  var EDGE_BUDGET_MIN = 3000;
  // The budget grows with the square of the camera scale, not linearly. A linear
  // curve already allowed ~3,500 antialiased curves to be on screen at 36%
  // zoom, and rasterising them cost several hundred milliseconds per frame
  // while the camera moved. Zoomed out nobody can tell a bezier from a line,
  // so the budget has to stay small until the picture is legible enough to be
  // worth the strokes.
  var EDGE_BUDGET_PER_ZOOM = 6000;
  // Below this scale an edge is drawn as a straight segment. A cubic bezier is
  // roughly four times the rasterisation work of a line for a curve that is a
  // few pixels long at this magnification.
  var STRAIGHT_EDGE_SCALE = 0.4;
  // Absolute ceiling on edges drawn while the camera is moving. See budgetFor.
  var INTERACT_EDGE_CAP = 1500;
  var KIND_PRIORITY = {
    imports: 0, depends_on: 1, implements: 2, inherits: 3, tests: 4,
    configures: 5, influences: 6, registers: 7, handles_event: 8,
    opens_resource: 9, closes_resource: 10, sends_data_to: 11,
    authorizes: 12, validates: 13, transforms: 14, writes: 15, reads: 16,
    starts_task: 17, awaits_task: 18, calls: 19
  };
  var ZOOM_STEP = 0.15;
  var MIN_SCALE = 0.02;
  var MAX_SCALE = 8;
  var PAD = 40;

  var SEVERITY_FILL = {
    critical: "#ff4d4f", high: "#ff9f43", medium: "#ffd93d",
    low: "#4aa8ff", info: "#7d8896"
  };
  // The border is deliberately not the fill. Two severities that share a
  // border colour cannot be told apart at a glance, and that was the whole
  // point of colouring a node at all.
  var SEVERITY_BORDER = {
    critical: "#ff1f21", high: "#ff7a45", medium: "#ffc53d",
    low: "#9ad1ff", info: "#aab3bf"
  };
  // Thickness carries the same ranking, so the order survives a screenshot
  // taken by someone who cannot see the hues.
  var SEVERITY_BORDER_PX = {
    critical: 3, high: 2.25, medium: 1.75, low: 1.25, info: 1
  };
  var SEVERITY_TEXT = {
    critical: "#ffffff", high: "#1a1000", medium: "#1a1600",
    low: "#00101f", info: "#0b1017"
  };
  var NODE_STROKE = {
    module: "#7d8896", class: "#4aa8ff", function: "#8fb573",
    method: "#b08bd4", unknown: "#8b98a9", directory: "#3a4653"
  };
  var KIND_COLOR = {
    calls: "#8fb573", imports: "#4aa8ff", depends_on: "#4aa8ff",
    implements: "#b08bd4", inherits: "#b08bd4", reads: "#ffd93d",
    writes: "#ff9f43", transforms: "#7ec8b4", validates: "#7ec8b4",
    authorizes: "#ff9f43", sends_data_to: "#ff6fae", registers: "#c98a5e",
    handles_event: "#c98a5e", starts_task: "#5ec8d4", awaits_task: "#5ec8d4",
    opens_resource: "#9aa7b5", closes_resource: "#9aa7b5",
    tests: "#5f7fa8", influences: "#c9a25e", configures: "#c9a25e"
  };

  var canvas = document.getElementById("map");
  var ctx = canvas.getContext("2d");
  var mini = document.getElementById("minimap");
  var mctx = mini.getContext("2d");
  var panel = document.getElementById("panel");
  var statusEl = document.getElementById("status");
  var stage = document.getElementById("stage");

  // ---------------------------------------------------------------- DOM helpers
  // Every string that comes from the repository reaches the page through
  // textContent. There is no innerHTML anywhere in this file, so a file whose
  // name contains markup is displayed rather than executed.
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---------------------------------------------------------------- camera
  var cam = { scale: 1, tx: 0, ty: 0 };
  var viewW = 1, viewH = 1, dpr = 1;

  function bounds() {
    if (!NODES.length) return { x: 0, y: 0, w: 1, h: 1 };
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (var i = 0; i < NODES.length; i++) {
      var n = NODES[i];
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x + n.w > maxX) maxX = n.x + n.w;
      if (n.y + n.h > maxY) maxY = n.y + n.h;
    }
    return { x: minX, y: minY, w: Math.max(1, maxX - minX), h: Math.max(1, maxY - minY) };
  }
  var B = bounds();

  function fit() {
    if (!viewW || !viewH) return;
    var s = Math.min((viewW - PAD * 2) / B.w, (viewH - PAD * 2) / B.h);
    cam.scale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, s));
    cam.tx = (viewW - B.w * cam.scale) / 2 - B.x * cam.scale;
    cam.ty = (viewH - B.h * cam.scale) / 2 - B.y * cam.scale;
    markLabels();
    requestDraw();
  }

  // Keep the point under the cursor pinned while the scale changes. The
  // cursor has to be converted from page coordinates into canvas-local ones
  // on both axes before this is meaningful.
  // Restores full detail once the zoom gesture goes quiet. Without it the map
  // stays at the coarse budget until the next input event.
  var settleQueued = false;
  function scheduleSettle() {
    if (settleQueued) return;
    settleQueued = true;
    setTimeout(function () {
      settleQueued = false;
      if (interacting()) { scheduleSettle(); return; }
      // Begin the staged restore rather than jumping straight to full detail.
      beginRestore();
    }, 140);
  }

  function zoomAt(canvasX, canvasY, factor) {
    var next = cam.scale * factor;
    if (next < MIN_SCALE) next = MIN_SCALE;
    if (next > MAX_SCALE) next = MAX_SCALE;
    if (next === cam.scale) return;
    var ratio = next / cam.scale;
    cam.tx = canvasX - ratio * (canvasX - cam.tx);
    cam.ty = canvasY - ratio * (canvasY - cam.ty);
    cam.scale = next;
    markLabels();
    requestDraw();
  }

  // Canvas origin in page coordinates, cached rather than measured per event.
  // getBoundingClientRect() forces a synchronous style recalc and layout, and
  // the browser can only answer it by recomputing if something invalidated
  // layout since the last frame. Calling it on every wheel event while the
  // status bar is rewriting DOM each frame turns two reads per event into two
  // full layouts per event, which is what made zoom feel frozen. The canvas
  // only moves when the window scrolls or resizes, so the origin is refreshed
  // in those handlers and nowhere else.
  var rectLeft = 0, rectTop = 0, rectW = 0, rectH = 0;
  function measureRect() {
    var rect = canvas.getBoundingClientRect();
    rectLeft = rect.left; rectTop = rect.top;
    rectW = rect.width; rectH = rect.height;
  }
  function rectWidth() { return rectW; }
  function rectHeight() { return rectH; }
  function toCanvasX(pageX) { return pageX - rectLeft; }
  function toCanvasY(pageY) { return pageY - rectTop; }

  // ---------------------------------------------------------------- LOD state
  // The label threshold is compared against a rendered size, so it flips when
  // the camera crosses it. Flipping the flag from inside the draw loop would
  // make it oscillate around the threshold, so it is only updated on zoom.
  var showLabels = false;
  var visCount = NODES.length;
  var showEdgeLabels = false;
  function markLabels() {
    // A module node is roughly 200 world pixels wide, so labels only become
    // legible once about a third of that survives the camera. Below that the
    // text is an unreadable smear, which is worse than no text at all.
    showLabels = cam.scale >= 0.14;
    showEdgeLabels = cam.scale >= 0.6;
  }

  // ---------------------------------------------------------------- spatial index
  // Uniform grid over node boxes. Culling and hit testing both walk it, which
  // is what keeps a zoomed-in view from touching every node on every frame.
  var GRID = null;
  function buildGrid() {
    var cell = Math.max(64, Math.sqrt((B.w * B.h) / Math.max(1, NODES.length)) * 2);
    var cols = Math.max(1, Math.ceil(B.w / cell) + 1);
    var rows = Math.max(1, Math.ceil(B.h / cell) + 1);
    var buckets = new Array(cols * rows);
    for (var i = 0; i < NODES.length; i++) {
      var n = NODES[i];
      var c0 = Math.max(0, Math.floor((n.x - B.x) / cell));
      var c1 = Math.min(cols - 1, Math.floor((n.x + n.w - B.x) / cell));
      var r0 = Math.max(0, Math.floor((n.y - B.y) / cell));
      var r1 = Math.min(rows - 1, Math.floor((n.y + n.h - B.y) / cell));
      for (var r = r0; r <= r1; r++) {
        for (var c = c0; c <= c1; c++) {
          var key = r * cols + c;
          (buckets[key] || (buckets[key] = [])).push(n);
        }
      }
    }
    GRID = { cell: cell, cols: cols, rows: rows, buckets: buckets };
  }

  function visibleNodes() {
    // The visible count is recorded here rather than in the draw loop: this is
    // the only place that knows it, and a caller that forgets to copy it back
    // leaves the label budget spending itself on a count from whenever the
    // map was last filtered.
    if (!GRID) { visCount = NODES.length; return NODES; }
    var x0 = (0 - cam.tx) / cam.scale - PAD;
    var y0 = (0 - cam.ty) / cam.scale - PAD;
    var x1 = (viewW - cam.tx) / cam.scale + PAD;
    var y1 = (viewH - cam.ty) / cam.scale + PAD;
    var c0 = Math.max(0, Math.floor((x0 - B.x) / GRID.cell));
    var c1 = Math.min(GRID.cols - 1, Math.floor((x1 - B.x) / GRID.cell));
    var r0 = Math.max(0, Math.floor((y0 - B.y) / GRID.cell));
    var r1 = Math.min(GRID.rows - 1, Math.floor((y1 - B.y) / GRID.cell));
    if (c0 > c1 || r0 > r1) { visCount = 0; return []; }
    var out = [], seen = {};
    for (var r = r0; r <= r1; r++) {
      for (var c = c0; c <= c1; c++) {
        var bucket = GRID.buckets[r * GRID.cols + c];
        if (!bucket) continue;
        for (var i = 0; i < bucket.length; i++) {
          var n = bucket[i];
          if (seen[n.id]) continue;
          seen[n.id] = 1;
          if (n.x + n.w < x0 || n.x > x1 || n.y + n.h < y0 || n.y > y1) continue;
          out.push(n);
        }
      }
    }
    visCount = out.length;
    return out;
  }

  // Node degree, computed once. It orders the labels, so the most connected
  // nodes keep their names when the label budget bites.
  (function computeDegrees() {
    var d = {};
    for (var i = 0; i < NODES.length; i++) d[NODES[i].id] = 0;
    for (var j = 0; j < EDGES.length; j++) {
      var e = EDGES[j];
      if (d[e.src] !== undefined) d[e.src] += (e.count || 1);
      if (d[e.dst] !== undefined) d[e.dst] += (e.count || 1);
    }
    for (var k = 0; k < NODES.length; k++) NODES[k].degree = d[NODES[k].id] || 0;
  })();

  var byId = {};
  for (var bi = 0; bi < NODES.length; bi++) byId[NODES[bi].id] = NODES[bi];

  var KIND_PRIORITY = {
    imports: 0, depends_on: 1, implements: 2, inherits: 3, tests: 4,
    configures: 5, influences: 6, registers: 7, handles_event: 8,
    opens_resource: 9, closes_resource: 10, sends_data_to: 11,
    authorizes: 12, validates: 13, transforms: 14, writes: 15, reads: 16,
    starts_task: 17, awaits_task: 18, calls: 19
  };

  // Priority order: structural relations first, collapsed calls last, and
  // within a kind the edges joining the most-connected nodes win. Computed
  // once per filter change so the budgeted subset is the same on every frame
  // and never flickers as the camera moves.
  function rankEdges(list) {
    var degree = {};
    var i, e;
    for (i = 0; i < list.length; i++) {
      e = list[i];
      degree[e.src] = (degree[e.src] || 0) + (e.count || 1);
      degree[e.dst] = (degree[e.dst] || 0) + (e.count || 1);
    }
    var ranked = [];
    for (i = 0; i < list.length; i++) {
      e = list[i];
      ranked.push({
        edge: e,
        kind: KIND_PRIORITY[e.kind] === undefined ? 99 : KIND_PRIORITY[e.kind],
        weight: (degree[e.src] || 0) + (degree[e.dst] || 0)
      });
    }
    ranked.sort(function (a, b) {
      if (a.kind !== b.kind) return a.kind - b.kind;
      if (a.weight !== b.weight) return b.weight - a.weight;
      return a.edge.src < b.edge.src ? -1 : a.edge.src > b.edge.src ? 1 : 0;
    });
    return ranked;
  }

  var drawnEdgeCount = EDGES.length;
  var drawnNodeCount = 0;
  function budgetFor(scale) {
    // While the camera is actually moving — a drag, or a zoom gesture that has
    // not settled yet — the map shows a coarser picture rather than a late
    // one. Full detail is restored as soon as the user stops. A map that keeps
    // up with the pointer is worth more than one that is briefly prettier.
    //
    // The cap has to be absolute, not a fraction of the zoom budget. The zoom
    // budget grows with scale squared, so by 800% it exceeds the total edge
    // count on its own; multiplying it by 0.2 still left every edge being
    // drawn while dragging, which measured as a p95 of 121ms per frame. A
    // fixed ceiling bounds the worst case at any zoom.
    var n = Math.round(EDGE_BUDGET_MIN + EDGE_BUDGET_PER_ZOOM * scale * scale);
    if (interacting()) n = Math.min(n, INTERACT_EDGE_CAP);
    // Hardware-independent quality. perf.quality is 1 on a machine that keeps
    // up and falls toward PERF_MIN_QUALITY on one that does not, so the same
    // map file stays usable on a GPU workstation and on a machine with only a
    // software rasteriser without either having to be told which it is.
    if (perf.quality < 1) n = Math.round(n * perf.quality);
    // And the restore ladder caps it while detail is coming back.
    var ceiling = restoreCeiling();
    if (ceiling !== null) n = Math.round(n * ceiling);
    return Math.max(0, Math.min(rankedVisible.length, n));
  }

  // A zoom gesture has no pointerup to mark its end, so it is timed: the flag
  // clears once the wheel has been quiet long enough to mean the user stopped.
  var zoomUntil = 0;
  function interacting() { return dragging || performance.now() < zoomUntil; }

  // ---------------------------------------------------------------- performance
  // The map cannot know what it is running on. A workstation with a discrete
  // GPU, a laptop with a shared one, and a VM with a software rasteriser all
  // execute the same Canvas2D commands at very different speeds. Every proxy
  // for "how fast is this machine" that a web page can read — the GPU vendor
  // string, WebGL renderer strings, user-agent sniffing, deviceMemory — is a
  // guess, and it is wrong on somebody's machine. The one question that can be
  // answered honestly is "how long did the last frame take on the hardware in
  // front of me", so that is the only question the renderer asks.
  //
  // `quality` is a multiplier on everything expensive: the edge budget and the
  // label budget. It settles near 1 on hardware that keeps up and falls toward
  // PERF_MIN_QUALITY on hardware that does not, with no configuration and no
  // branch on the user's platform.
  var PERF_TARGET_MS = 20;
  var PERF_MIN_QUALITY = 0.15;
  var perf = { quality: 1, slow: 0, fast: 0, last: 0 };
  // Frames drawn while nobody is touching the map must not drive the
  // controller. A slow frame while the camera is still is a responsiveness
  // problem worth fixing; a slow frame while the map is sitting at rest is
  // just a big picture, and degrading the map for standing still would make it
  // permanently worse for no reason.
  var adaptUntil = 0;
  function adaptNow() { return interacting() || restoreStage >= 0 || performance.now() < adaptUntil; }

  // Detail comes back in stages rather than in one frame. Restoring every edge,
  // every label and every curve at the instant the camera stopped is what left
  // an isolated 130-200ms stall: the picture jumped straight from "coarse but
  // moving" back to "everything at once". Raising the ceiling one step at a
  // time, and letting each step's measured cost decide whether the next step is
  // safe, turns that stall into a few ordinary frames on any hardware.
  var RESTORE_STEPS = [0.35, 0.6, 0.85, 1.0];
  var restoreStage = -1; // -1 means "not restoring"

  function restoreCeiling() {
    if (restoreStage < 0) return null;
    return RESTORE_STEPS[Math.min(restoreStage, RESTORE_STEPS.length - 1)];
  }

  function beginRestore() {
    if (restoreStage >= 0) return;
    restoreStage = 0;
    adaptUntil = performance.now() + 1200;
    requestDraw();
  }

  function advanceRestore(expensive) {
    if (restoreStage < 0) return;
    if (expensive) { restoreStage = 0; return; } // step back rather than push on
    restoreStage++;
    if (restoreStage >= RESTORE_STEPS.length) { restoreStage = -1; return; }
    requestDraw();
  }

  // Called with the measured duration of the frame that just finished.
  function measureFrame(ms) {
    if (!(ms >= 0) || ms > 2000) return false;
    perf.last = ms;
    if (!adaptNow()) return false;

    var expensive = ms > PERF_TARGET_MS * 1.4;
    if (expensive) { perf.slow++; perf.fast = 0; }
    else if (ms < PERF_TARGET_MS * 0.55) { perf.fast++; perf.slow = 0; }
    else { perf.slow = 0; perf.fast = 0; }

    if (expensive && perf.quality > PERF_MIN_QUALITY) {
      // Back off proportionally to how far over budget the frame was, but never
      // all the way in one step. A single slow frame is usually a one-off, and
      // dropping straight to the floor makes the detail level flicker.
      var ratio = Math.min(0.5, ms / (PERF_TARGET_MS * 4));
      perf.quality = Math.max(PERF_MIN_QUALITY, perf.quality * (1 - ratio));
    } else if (perf.fast >= 3 && perf.quality < 1) {
      // Climb only after several consecutive cheap frames so the level does not
      // oscillate around the boundary.
      perf.quality = Math.min(1, perf.quality + 0.12);
      perf.fast = 0;
    }
    advanceRestore(expensive);
    return expensive;
  }

  // Walks the spatial grid, not the whole node list. The previous version
  // scanned all NODES on every call, which on a 2,000-symbol map was 2,000 box
  // tests per click and it also returned the *last* overlapping node rather
  // than the smallest match, so clicking a wide module selected a small node
  // sitting on top of it.
  function hitTest(px, py) {
    var wx = (px - cam.tx) / cam.scale;
    var wy = (py - cam.ty) / cam.scale;
    var found = null, foundArea = Infinity;
    var cells = gridCells(wx, wy);
    for (var i = 0; i < cells.length; i++) {
      var bucket = cells[i];
      if (!bucket) continue;
      for (var j = 0; j < bucket.length; j++) {
        var n = bucket[j];
        if (wx < n.x || wx > n.x + n.w || wy < n.y || wy > n.y + n.h) continue;
        // A small node drawn on top of a large one wins; without this the
        // wider box always won because it was tested last.
        var area = n.w * n.h;
        if (area < foundArea) { foundArea = area; found = n; }
      }
    }
    if (found) return found;
    // Missed every box: fall back to a proximity search so a click near a thin
    // node still selects something sensible.
    var best = null, bestD = 18 / cam.scale;
    var vis = visibleNodes();
    for (var k = 0; k < vis.length; k++) {
      var m = vis[k];
      var cx = Math.max(m.x, Math.min(wx, m.x + m.w));
      var cy = Math.max(m.y, Math.min(wy, m.y + m.h));
      var d = Math.hypot(wx - cx, wy - cy);
      if (d < bestD) { bestD = d; best = m; }
    }
    return best;
  }

  // The grid buckets overlapping one world point.
  function gridCells(wx, wy) {
    if (!GRID) return [NODES];
    var c = Math.floor((wx - B.x) / GRID.cell);
    var r = Math.floor((wy - B.y) / GRID.cell);
    if (c < 0 || r < 0 || c >= GRID.cols || r >= GRID.rows) return [];
    var bucket = GRID.buckets[r * GRID.cols + c];
    return bucket ? [bucket] : [];
  }

  // ---------------------------------------------------------------- filter
  var query = "";
  function filtered() {
    if (!query) return NODES;
    var q = query.toLowerCase();
    var out = [];
    for (var i = 0; i < NODES.length; i++) {
      var n = NODES[i];
      if ((n.name || "").toLowerCase().indexOf(q) >= 0 ||
          (n.id || "").toLowerCase().indexOf(q) >= 0) out.push(n);
    }
    return out;
  }
  var active = NODES.slice();

  function applyFilter() {
    active = filtered();
    var keep = {};
    for (var i = 0; i < active.length; i++) keep[active[i].id] = 1;
    visibleEdges = [];
    for (var j = 0; j < EDGES.length; j++) {
      var e = EDGES[j];
      if (keep[e.src] && keep[e.dst]) visibleEdges.push(e);
    }
    rankedVisible = rankEdges(visibleEdges);
    renderStatus();
    requestDraw();
  }
  var visibleEdges = EDGES.slice();
  var rankedVisible = [];

  // ---------------------------------------------------------------- drawing
  var dragging = false;
  var panStart = null;   // saved, not accumulated: incremental updates drift
  var drawQueued = false;

  function resize() {
    measureRect();
    dpr = window.devicePixelRatio || 1;
    viewW = Math.max(1, rectWidth());
    viewH = Math.max(1, rectHeight());
    canvas.width = Math.round(viewW * dpr);
    canvas.height = Math.round(viewH * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function requestDraw() {
    // Every frame requested while the camera is moving, or while detail is
    // being restored, extends the window in which the quality controller may
    // act. A slow frame while nobody is touching the map is not a
    // responsiveness problem, and the map must not degrade itself for standing
    // still.
    if (interacting() || restoreStage >= 0) adaptUntil = performance.now() + 700;
    if (drawQueued) return;
    drawQueued = true;
    window.requestAnimationFrame(function () { drawQueued = false; draw(); });
  }

  function roundRect(g, x, y, w, h, r) {
    g.beginPath();
    if (g.roundRect) { g.roundRect(x, y, w, h, r); return; }
    g.moveTo(x + r, y);
    g.arcTo(x + w, y, x + w, y + h, r);
    g.arcTo(x + w, y + h, x, y + h, r);
    g.arcTo(x, y + h, x, y, r);
    g.arcTo(x, y, x + w, y, r);
    g.closePath();
  }

  // A diamond is the one glyph a data-flow map needs that no other view does:
  // it marks a node as the origin of a value rather than a place in the code.
  // It has to be a real diamond and not a square with a border, because the
  // shape is the only thing distinguishing it once the colour scale is in use
  // for severity.
  function diamondPath(g, x, y, w, h) {
    var cx = x + w / 2, cy = y + h / 2, rx = w / 2, ry = h / 2;
    g.beginPath();
    g.moveTo(cx, cy - ry);
    g.lineTo(cx + rx, cy);
    g.lineTo(cx, cy + ry);
    g.lineTo(cx - rx, cy);
    g.closePath();
  }

  var LABEL_BUDGET = 400;
  // Below this many nodes in the viewport every visible node is named. A label
  // budget handed out by GLOBAL degree rank starves the nodes the reader is
  // actually looking at: zoomed into a corner of a 2,000-node map, forty nodes
  // are on screen while the four hundred most connected ones hold the labels,
  // most of them elsewhere in the drawing. The cost of naming what is already
  // on screen is bounded by the size of the screen, so below this count the
  // rank stops mattering and the reader gets what they asked for.
  // Measured: a frame with 277 visible nodes drew in 7ms, so naming all of
  // them is not expensive at this map's scale. The limit only has to sit
  // below the point where the text becomes an unreadable smear.
  var LABEL_ALL_BELOW = 600;
  // Nodes are not budgeted by the label budget. During a gesture this map
  // keeps the best-connected 60% of nodes and never fewer than 1,200, so a
  // 2,000-node map keeps every node it has room to draw and only a genuinely
  // enormous one thins out.
  var MOVE_NODE_KEEP = 0.6;
  var NODE_KEEP_MIN = 1200;
  // Label order is fixed once, by degree, so the same nodes keep their labels
  // as the camera moves instead of the set flickering with the viewport.
  (function rankLabels() {
    var order = NODES.slice().sort(function (a, b) {
      var da = (a.degree || 0), db = (b.degree || 0);
      if (da !== db) return db - da;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    for (var i = 0; i < order.length; i++) order[i].labelRank = i;
  })();

  function draw() {
    var startedAt = performance.now();
    // One bad frame must not be able to wedge the map. An exception thrown
    // between save() and restore() leaves the context's transform stack
    // corrupted and the canvas half-painted, and because requestDraw() has
    // already cleared its queued flag the next frame starts from an even
    // worse state. Nothing here is load-bearing enough to justify a wedged
    // canvas, so the frame is abandoned rather than allowed to cascade.
    try {
      drawFrame();
    } catch (err) {
      ctx.restore();
      if (window.console && console.error) console.error("map frame failed", err);
    }
    // The frame's own duration is the only honest signal available about the
    // hardware, so it is what drives the quality controller and the restore
    // ladder.
    measureFrame(performance.now() - startedAt);
    var spent = performance.now() - startedAt;
    mapStats.draws++;
    mapStats.lastDrawMs = spent;
    if (spent > PERF_TARGET_MS * 1.4) mapStats.slow++;
  }

  // Counters so the controller can be measured rather than assumed, and so the
  // status bar can state what the last frame actually cost instead of implying
  // the picture is free.
  var mapStats = { draws: 0, slow: 0, lastDrawMs: 0 };
  (function publishStats() {
    window.__understandMap = {
      perf: perf,
      stats: mapStats,
      state: function () {
        return {
          draws: mapStats.draws, slow: mapStats.slow, lastDrawMs: mapStats.lastDrawMs,
          quality: perf.quality, restoreStage: restoreStage, interacting: interacting(),
        visCount: visCount, scale: cam.scale
        };
      }
    };
  })();

  function drawFrame() {
    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, viewW, viewH);
    ctx.translate(cam.tx, cam.ty);
    ctx.scale(cam.scale, cam.scale);

    var vis = visibleNodes();
    // Membership test against the on-screen set. A Map is used rather than a
    // plain object because the previous object form rebuilt a 2,000-key hash
    // every frame and coerces every key through string conversion.
    var ids = new Set();
    for (var i = 0; i < vis.length; i++) ids.add(vis[i].id);

    // When the view holds a lot of geometry, edges are the first thing that
    // costs frames, so they are dropped for the duration of a drag.
    var dropEdges = dragging &&
      (NODES.length > HIDE_EDGES_ON_MOVE_NODES || EDGES.length > HIDE_EDGES_ON_MOVE_EDGES);

    var budget = budgetFor(cam.scale);
    drawnEdgeCount = 0;
    if (!dropEdges) {
      // Edges are bucketed by stroke style first and one path is issued per
      // bucket. Setting strokeStyle and setLineDash per edge was the single
      // largest per-frame cost: a dashed stroke is markedly more expensive
      // than a solid one, and the property changes forced the rasteriser to
      // re-prepare its stroke state thousands of times a frame.
      var buckets = new Map();
      // rankedVisible is bounded by the filter while the budget is derived from
      // the whole map, so the loop is clamped on the array that is actually
      // indexed. budgetFor() also clamps, but a mismatch between the two would
      // be an undefined read inside the animation frame, and an exception
      // thrown here leaves the canvas half-painted with ctx.save() unbalanced.
      var limit = Math.min(budget, rankedVisible.length);
      for (var e = 0; e < limit; e++) {
        var entry = rankedVisible[e];
        if (!entry) continue;
        var edge = entry.edge;
        var a = byId[edge.src], b = byId[edge.dst];
        if (!a || !b) continue;
        if (!ids.has(edge.src) && !ids.has(edge.dst)) continue;
        var key = edge.kind + "|" + edge.origin;
        var bucket = buckets.get(key);
        if (!bucket) {
          bucket = {
            color: KIND_COLOR[edge.kind] || "#8b98a9",
            origin: edge.origin,
            kind: edge.kind,
            paths: [],
            drawn: 0
          };
          buckets.set(key, bucket);
        }
        var ends = anchorEnds(a, b);
        bucket.paths.push(ends.x0, ends.y0, ends.x1, ends.y1, edge.count);
        bucket.drawn++;
        drawnEdgeCount++;
      }
      buckets.forEach(function (bucket) {
        strokeBucket(bucket);
      });
    }
    ctx.globalAlpha = 1;

    // Text state is frame-wide. Setting it per node forced the browser to redo
    // font matching and text alignment for every one of two thousand nodes.
    if (showLabels) {
      ctx.font = "12px ui-sans-serif, system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
    }
    drawnNodeCount = 0;
    for (var j = 0; j < vis.length; j++) { drawNode(vis[j]); drawnNodeCount++; }

    ctx.restore();
    drawMini();
    renderStatus();
  }

  // Where an edge leaves one box and enters the other.
  //
  // The previous version always left the bottom-centre and entered the
  // top-centre. That is right for a straight vertical hop and wrong for
  // everything else: on a long horizontal edge the two anchors are far apart
  // in x, the curve degenerates into a near-vertical wiggle, and it crosses
  // the neighbouring edges it was supposed to separate. Choosing the side from
  // the relative position is the cheap version of what Cytoscape calls port
  // selection, and it is what makes the curves readable.
  function anchorEnds(a, b) {
    var ax = a.x + a.w / 2, ay = a.y + a.h / 2;
    var bx = b.x + b.w / 2, by = b.y + b.h / 2;
    var dx = bx - ax, dy = by - ay;
    if (Math.abs(dy) >= Math.abs(dx)) {
      // Mostly vertical: use the top and bottom faces.
      return dy >= 0
        ? { x0: ax, y0: a.y + a.h, x1: bx, y1: b.y }
        : { x0: ax, y0: a.y, x1: bx, y1: b.y + b.h };
    }
    // Mostly horizontal: use the left and right faces, which is what keeps a
    // same-layer dependency from diving through the rows above and below it.
    return dx >= 0
      ? { x0: a.x + a.w, y0: ay, x1: b.x, y1: by }
      : { x0: a.x, y0: ay, x1: b.x + b.w, y1: by };
  }

  function dashFor(origin, scale) {
    return origin === "inferred" ? [6 / scale, 4 / scale] :
           origin === "unresolved" ? [2 / scale, 4 / scale] : [];
  }

  // One beginPath for every edge sharing a style, then a single stroke. Arrow
  // heads go in their own path per bucket for the same reason: one fill call
  // instead of one per edge.
  function strokeBucket(bucket) {
    var s = cam.scale;
    var alpha = Math.min(0.85, 0.18 + 0.7 * Math.min(1, s * 2.5));
    var p = bucket.paths;
    ctx.globalAlpha = alpha;
    ctx.strokeStyle = bucket.color;
    ctx.lineWidth = 1 / s;
    ctx.setLineDash(dashFor(bucket.origin, s));
    var straight = s < STRAIGHT_EDGE_SCALE;
    ctx.beginPath();
    for (var i = 0; i < p.length; i += 5) {
      var x0 = p[i], y0 = p[i + 1], x1 = p[i + 2], y1 = p[i + 3];
      ctx.moveTo(x0, y0);
      if (straight) { ctx.lineTo(x1, y1); continue; }
      // Smart curve: the control points bow away from the straight line in
      // proportion to the offset between the endpoints. An aligned pair gets
      // no bow at all (a straight line), a diagonal one bows toward its own
      // average and stops overlapping the edges of its neighbours.
      var dx = x1 - x0, dy = y1 - y0;
      if (Math.abs(dy) >= Math.abs(dx)) {
        var bow = dx * 0.4;
        var mid = (y0 + y1) / 2;
        ctx.bezierCurveTo(x0 + bow, mid, x1 + bow, mid, x1, y1);
      } else {
        var bowY = dy * 0.4;
        var midX = (x0 + x1) / 2;
        ctx.bezierCurveTo(midX, y0 + bowY, midX, y1 + bowY, x1, y1);
      }
    }
    ctx.stroke();
    ctx.setLineDash([]);

    // Arrow heads are skipped while zoomed out: below this scale a head is
    // under a pixel, costs a second path per edge, and contributes nothing
    // readable. The status bar already reports how many edges are shown.
    if (s > STRAIGHT_EDGE_SCALE) {
      var size = 6 / s;
      ctx.fillStyle = bucket.color;
      ctx.beginPath();
      for (var k = 0; k < p.length; k += 5) {
        var hx = p[k + 2], hy = p[k + 3];
        ctx.moveTo(hx, hy);
        ctx.lineTo(hx - size / 2, hy - size);
        ctx.lineTo(hx + size / 2, hy - size);
        ctx.closePath();
      }
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    if (showEdgeLabels) {
      ctx.fillStyle = bucket.color;
      ctx.font = (10 / s) + "px ui-sans-serif, system-ui, sans-serif";
      ctx.textAlign = "center";
      // The label names the *relation*, not the confidence of the inference
      // that found it. The previous version printed "inferred x3", which told
      // the reader how sure the engine was but not what the line means. The
      // origin stays available in the side panel and the legend.
      var text = (bucket.kind || bucket.origin) + (p[4] > 1 ? " x" + p[4] : "");
      for (var t = 0; t < p.length; t += 5) {
        if (p[t + 4] <= 1) continue;
        ctx.fillText(text,
          (p[t] + p[t + 2]) / 2, (p[t + 1] + p[t + 3]) / 2);
      }
    }
  }

  function drawNode(n) {
    // Nodes are budgeted while the camera is moving for the same reason edges
    // are: drawing two thousand rounded rectangles costs more than the frame
    // allows. The budget is a floor-guarded fraction of the map, not the
    // label budget -- reusing LABEL_BUDGET (400) here removed 1,600 of 2,000
    // nodes the instant a drag started, and a reader pressing the mouse saw
    // the map empty itself. Half the map, and never fewer than 1,200 nodes,
    // survives a gesture; past that the edges are the honest thing to drop.
    if (interacting() && n.labelRank !== undefined &&
        labelBudget() > 0 && NODES.length > MOVE_NODE_KEEP * 2 &&
        n.labelRank >= Math.max(NODE_KEEP_MIN, Math.floor(NODES.length * MOVE_NODE_KEEP))) return;
    var sev = n.finding_severity;
    var fill = sev && SEVERITY_FILL[sev] ? SEVERITY_FILL[sev] : "#1a222d";
    var text = sev && SEVERITY_TEXT[sev] ? SEVERITY_TEXT[sev] : "#d7dee8";
    // A placeholder is the name of something the code calls that the analyzer
    // could not bind to a definition. It is drawn hollow so it never reads as
    // a function that has a body.
    var ghost = n.shape === "placeholder";
    // A severity border has to be a *different* colour from the fill. The
    // previous line set the stroke to the fill, which made the outline
    // invisible: a node flagged critical looked identical to a node flagged
    // high once both were drawn. The border also thickens with severity, so
    // the ranking is readable without the legend or a hover.
    var stroke = ghost ? "#5b6472"
      : (sev ? SEVERITY_BORDER[sev] || fill : (NODE_STROKE[n.kind] || "#8b98a9"));
    var borderPx = (sev ? SEVERITY_BORDER_PX[sev] || 1 : 1) / cam.scale;
    // The floor is one SCREEN pixel, not one world pixel. A larger floor is
    // tempting -- it made a fit-to-view map look solid -- and it is a lie:
    // at 8% zoom a floor of three pixels forces every node to 37 world pixels,
    // and 2,000 nodes that size overlap into unbroken bands. The reader sees a
    // smear with no way to tell a dense region from a solid one, and cannot
    // tell which of the merged nodes a click would select. One pixel keeps the
    // map honest at a glance and the zoom is what makes a node readable.
    var minPx = 1 / cam.scale;
    var w = Math.max(n.w, minPx);
    var h = Math.max(n.h, minPx);
    var r = n.shape === "circle" ? h / 2 : n.shape === "pill" ? h / 2 : 5;

    if (n.shape === "diamond") { diamondPath(ctx, n.x, n.y, w, h); }
    else { roundRect(ctx, n.x, n.y, w, h, r); }
    ctx.fillStyle = ghost ? "#11161d" : fill;
    ctx.fill();
    ctx.strokeStyle = stroke;
    ctx.lineWidth = borderPx;
    // setLineDash is only touched for a node that is actually in a cycle or is
    // a placeholder; the previous version called it for every node twice, which
    // is 4,000 state changes a frame on a 2,000-node map.
    if (n.in_cycle || ghost) {
      ctx.setLineDash(ghost ? [2 / cam.scale, 3 / cam.scale] : [3 / cam.scale, 3 / cam.scale]);
      ctx.stroke();
      ctx.setLineDash([]);
    } else {
      ctx.stroke();
    }

    // Labels are the first thing dropped when zoomed out. The distinction
    // between an inferred and a solid edge is not lost because the legend and
    // the side panel state it in words. ctx.font, textAlign and textBaseline
    // are set once per frame in draw(); assigning a font per node makes the
    // browser redo font matching two thousand times a frame.
    if (!showLabels || interacting() || n.labelRank === undefined) return;
    // The budget is spent on what is visible, not on what is globally busiest.
    if (visCount > LABEL_ALL_BELOW && n.labelRank >= labelBudget()) return;
    ctx.fillStyle = text;
    ctx.fillText(n.name, n.x + n.w / 2, n.y + n.h / 2);
  }

  // ---------------------------------------------------------------- minimap
  var miniView = { x: 0, y: 0, w: 1, h: 1 };
var MINI_MIN_NODES = 40;
  // The node rectangles never change, so they are rasterised once into an
  // offscreen canvas and blitted thereafter. Redrawing every rectangle every
  // frame was pure waste: the only part of the minimap that actually moves is
  // the viewport rectangle.
  var miniBase = document.createElement("canvas");
  var miniBaseDrawn = false;
  var lastMiniKey = "";
  function drawMini() {
    // Hidden rather than drawn: below this size the map already fits on screen,
    // so the overlay only hides the thing it is meant to help with.
    if (NODES.length < MINI_MIN_NODES) { mini.hidden = true; return; }
    mini.hidden = false;
    // The node layer is a cached bitmap and the viewport rectangle is the only
    // thing that moves, so the whole overlay is skipped unless one of those
    // two actually changed. This ran on every frame of every pan and zoom for
    // the sake of one stroked rectangle.
    var mw = mini.width, mh = mini.height;
    var ms = Math.min((mw - 8) / B.w, (mh - 8) / B.h);
    var mox = (mw - B.w * ms) / 2, moy = (mh - B.h * ms) / 2;
    var vx = (-cam.tx / cam.scale - B.x) * ms + mox;
    var vy = (-cam.ty / cam.scale - B.y) * ms + moy;
    var vw = (viewW / cam.scale) * ms, vh = (viewH / cam.scale) * ms;
    var rectKey = mw + "|" + mh + "|" + (vx | 0) + "|" + (vy | 0) + "|" + (vw | 0) + "|" + (vh | 0) + "|" + miniBaseDrawn;
    if (rectKey === lastMiniKey) return;
    lastMiniKey = rectKey;
    var s = ms, ox = mox, oy = moy;

    if (miniBase.width !== mw || miniBase.height !== mh) {
      miniBase.width = mw; miniBase.height = mh;
      miniBaseDrawn = false;
    }
    // miniBaseDrawn is set below, so rectKey above could not see it flip. Any
    // frame that rasterises the base therefore draws once more and settles.
    if (!miniBaseDrawn) {
      var bx = miniBase.getContext("2d");
      bx.clearRect(0, 0, mw, mh);
      bx.fillStyle = "#2a3441";
      for (var k = 0; k < NODES.length; k++) {
        var node = NODES[k];
        bx.fillRect(ox + (node.x - B.x) * s, oy + (node.y - B.y) * s,
                    Math.max(1, node.w * s), Math.max(1, node.h * s));
      }
      miniBaseDrawn = true;
    }
    mctx.clearRect(0, 0, mw, mh);
    mctx.drawImage(miniBase, 0, 0);
    miniView = {
      x: (-cam.tx / cam.scale - B.x) * s + ox,
      y: (-cam.ty / cam.scale - B.y) * s + oy,
      w: (viewW / cam.scale) * s,
      h: (viewH / cam.scale) * s,
      s: s, ox: ox, oy: oy
    };
    mctx.strokeStyle = "#4aa8ff";
    mctx.lineWidth = 1;
    mctx.strokeRect(miniView.x, miniView.y, miniView.w, miniView.h);
  }

  function miniJump(event) {
    var rect = mini.getBoundingClientRect();
    var mx = event.clientX - rect.left, my = event.clientY - rect.top;
    var wx = (mx - miniView.ox) / miniView.s + B.x;
    var wy = (my - miniView.oy) / miniView.s + B.y;
    cam.tx = viewW / 2 - wx * cam.scale;
    cam.ty = viewH / 2 - wy * cam.scale;
    markLabels();
    requestDraw();
  }

  // ---------------------------------------------------------------- panel
  // The panel answers one question: what is this thing and why does it matter?
  // A list of ids, kinds and severities answers none of it, so the node's own
  // source is shown first, then every attached finding with the reasoning the
  // analyzer recorded, then the relations as context. Everything is built from
  // textContent; a repository is untrusted input and a finding summary is
  // attacker-influenced prose, so it must never become markup.
  function renderPanel(node) {
    clear(panel);
    panel.className = node ? "wide" : "";
    if (!node) {
      panel.appendChild(el("h2", null, "Nothing selected"));
      panel.appendChild(el("p", "hint",
        "Click a node to see its code and its findings. Drag to pan, scroll to zoom."));
      var legend = el("div");
      legend.appendChild(el("h3", null, "Relations in this map"));
      var ul = el("ul");
      var byKind = STATS.edges_by_kind || {};
      var kinds = LEGEND.kinds || Object.keys(byKind).sort();
      for (var i = 0; i < kinds.length; i++) {
        var li = el("li");
        li.appendChild(el("span", null, kinds[i] + " "));
        li.appendChild(el("span", "kv", "(" + (byKind[kinds[i]] || 0) + ")"));
        ul.appendChild(li);
      }
      legend.appendChild(ul);
      legend.appendChild(el("h3", null, "Line style"));
      legend.appendChild(el("p", "kv",
        "solid = proven from syntax or types; dashed = inferred by name and " +
        "shape; dotted = the target was not resolved."));
      // On a data-flow map the node shape carries the argument, not the
      // colour: a diamond is where the value enters and a square is where it
      // is used. A glyph with no legend is a glyph the reader has to guess at.
      // An empty object is still truthy in JavaScript, so the length is the
      // test — otherwise every other view grows an empty heading.
      var flowShapes = (LEGEND && LEGEND.flow_shapes) || null;
      if (flowShapes && Object.keys(flowShapes).length) {
        var present = {};
        for (var f = 0; f < NODES.length; f++) {
          if (NODES[f].flow_role) present[NODES[f].flow_role] = true;
        }
        legend.appendChild(el("h3", null, "Node shape"));
        var shapeUl = el("ul");
        var labels = { source: "diamond", sink: "square", caller: "pill",
                       via: "circle", step: "circle", symbol: "circle" };
        for (var key in flowShapes) {
          if (!Object.prototype.hasOwnProperty.call(present, key)) continue;
          var sli = el("li");
          sli.appendChild(el("span", null, (labels[key] || "shape") + " "));
          sli.appendChild(el("span", "kv", flowShapes[key]));
          shapeUl.appendChild(sli);
        }
        legend.appendChild(shapeUl);
      }
      var ghosts = STATS.placeholder_nodes || 0;
      if (ghosts) {
        legend.appendChild(el("h3", null, "Hollow, dashed node"));
        legend.appendChild(el("p", "kv", ghosts + " node(s) on this map are the " +
          "name of something the code calls that the analyzer could not bind to a " +
          "definition in this repository -- standard library, a third-party " +
          "dependency, or a name chosen at run time. They are drawn hollow and " +
          "dashed because the call is real and the definition is not here. Click " +
          "one for the specific reason."));
      }
      // The border is the ranking, so it gets its own key. A red outline that
      // nobody has been told about is indistinguishable from a rendering
      // artefact, and the reader is left guessing which of two red-ish nodes
      // is worse.
      var sevCount = {};
      for (var s = 0; s < NODES.length; s++) {
        if (NODES[s].finding_severity) sevCount[NODES[s].finding_severity] = true;
      }
      var sevKeys = Object.keys(sevCount);
      if (sevKeys.length) {
        legend.appendChild(el("h3", null, "Severity border"));
        var sevOrder = ["critical", "high", "medium", "low", "info"];
        var sevUl = el("ul", "swatches");
        for (var sv = 0; sv < sevOrder.length; sv++) {
          var name = sevOrder[sv];
          if (!sevCount[name]) continue;
          var svLi = el("li");
          var sw = el("span", "swatch");
          sw.style.borderColor = SEVERITY_BORDER[name];
          sw.style.borderWidth = SEVERITY_BORDER_PX[name] + "px";
          svLi.appendChild(sw);
          svLi.appendChild(el("span", null, name));
          sevUl.appendChild(svLi);
        }
        legend.appendChild(sevUl);
        legend.appendChild(el("p", "kv",
          "A node is outlined in the worst severity of any finding on it, and " +
          "the outline thickens with the severity so the order survives a " +
          "black-and-white screenshot."));
      }
      panel.appendChild(legend);
      return;
    }
    panel.appendChild(el("h2", null, node.name));
    var kv = el("div", "kv");
    kv.appendChild(el("div", null, node.kind + (node.exported ? " (exported)" : "")));
    kv.appendChild(el("div", null, node.id));
    if (node.file) {
      kv.appendChild(el("div", null,
        node.file + (node.start_line ? ":" + node.start_line : "")));
    }
    if (node.finding_count) {
      kv.appendChild(el("div", null,
        node.finding_count + " finding(s), worst " + node.finding_severity));
    }
    if (node.collapsed) kv.appendChild(el("div", null, node.collapsed + " symbols collapsed here"));
    if (node.in_cycle) kv.appendChild(el("div", null, "part of a dependency cycle"));
    if (node.depth_from_root !== undefined && node.depth_from_root !== null) {
      kv.appendChild(el("div", null, node.depth_from_root + " hop(s) from the root"));
    }
    panel.appendChild(kv);

    // 1. What the code is.
    panel.appendChild(el("h3", null, "Code"));
    // Three different reasons, never one. A node with no file is not the same
    // as a repository that has moved, and telling a reader the source is
    // unavailable when the map simply has nothing to show for this node is a
    // false statement about the analysis. The no-file case is the common one in
    // a call graph and it means something specific: the analyzer saw this name
    // being called and could not bind it to a definition, so there is no code
    // to show because there is no definition to point at.
    var sourceText;
    var sourceNote = null;
    if (node.source_available) {
      sourceText = node.source;
    } else if (!node.file) {
      sourceText = null;
      sourceNote = node.placeholder_reason ||
        ("No code is attached to this node because there is none. This is the " +
         "name of something the analysed code calls that the analyzer could not " +
         "bind to a definition in this repository: it is most likely part of " +
         "the standard library, a third-party dependency, or a name resolved " +
         "dynamically at run time. Drawn hollow and dashed to mark it as a " +
         "name rather than a place.");
    } else {
      sourceText = STATS.source_reason ||
        ("The source of " + node.file + " could not be read when this map was built.");
    }
    if (sourceNote) {
      panel.appendChild(el("p", "kv", sourceNote));
    } else {
      var pre = el("pre", node.source_available ? "" : "wrap", sourceText);
      if (node.source_available && node.body_lines < (node.end_line - node.start_line + 1)) {
        pre.appendChild(document.createTextNode(
          "\\n… " + (node.end_line - node.start_line + 1 - node.body_lines) + " more line(s)"));
      }
      panel.appendChild(pre);
    }

    // 2. Why it matters.
    var details = node.finding_detail || [];
    panel.appendChild(el("h3", null, "Findings (" + node.finding_detail_total + ")"));
    if (!details.length) {
      // Distinguish "the scan found nothing here" from "the map did not carry
      // it". The second is a limit of this file, and saying nothing about it
      // would read as a clean result.
      var withheld = STATS.findings_withheld || 0;
      panel.appendChild(el("p", "kv",
        withheld
          ? "this map carries no finding for this symbol. " + withheld +
            " finding(s) were dropped to keep the map readable, and " +
            (node.finding_count || 0) +
            " land on files that contain it; run `understand finding show` with any id"
          : (node.finding_count
            ? "no finding is attached to this symbol; " + node.finding_count +
              " land on files that contain it"
            : "the scan reported no finding on this symbol")));
    } else {
      var shown = Math.min(details.length, PANEL_FINDING_CAP);
      for (var f = 0; f < shown; f++) appendFinding(details[f]);
      if (details.length > PANEL_FINDING_CAP) {
        panel.appendChild(el("p", "kv",
          "showing " + PANEL_FINDING_CAP + " of " + details.length +
          " findings; run `understand finding show <id>` for any of them"));
      }
    }

    // 3. Context.
    var outgoing = [], incoming = [];
    for (var j = 0; j < visibleEdges.length; j++) {
      var e = visibleEdges[j];
      if (e.src === node.id) outgoing.push(e);
      if (e.dst === node.id) incoming.push(e);
    }
    appendEdgeList("Outgoing", outgoing);
    appendEdgeList("Incoming", incoming);
  }

  // One finding, in full. The order is the analyzer's own order of argument:
  // what it is, why it is dangerous, what an attacker would have to do, what
  // this analysis could NOT prove, and what to change. The "not proven" block
  // is not an afterthought: without it a low-confidence hint reads as a
  // demonstrated vulnerability, which is the one failure mode this tool exists
  // to avoid.
  function appendFinding(d) {
    var box = el("div", "finding " + (d.severity || "info"));
    var head = el("div", "head");
    head.appendChild(el("span", "sev " + (d.severity || "info"), d.severity || "?"));
    head.appendChild(el("span", "title", d.title || d.rule_id || "finding"));
    box.appendChild(head);
    box.appendChild(el("div", "kv",
      (d.rule_id || "") + "  ·  " + (d.category || "") + "  ·  " +
      (d.language || "") + (d.finding_id ? "  ·  " + d.finding_id : "")));
    box.appendChild(el("div", "kv",
      "confidence " + (d.confidence || "unknown") + "  ·  verification " +
      (d.verification_status || "unknown")));

    if (d.summary) box.appendChild(el("p", null, d.summary));
    if (d.technical_explanation) appendField(box, "What is happening", d.technical_explanation);
    if (d.impact) appendField(box, "Impact", d.impact);

    if (d.data_flows && d.data_flows.length) {
      for (var i = 0; i < d.data_flows.length; i++) {
        var flow = d.data_flows[i];
        var hops = Array.isArray(flow) ? flow : [flow];
        appendField(box, "Path " + (i + 1) + " of " + d.data_flows.length, null);
        var chain = el("ol", "chain");
        for (var h = 0; h < hops.length; h++) {
          chain.appendChild(el("li", null, String(hops[h])));
        }
        box.appendChild(chain);
      }
    }
    if (d.call_chains && d.call_chains.length) {
      for (var c = 0; c < d.call_chains.length; c++) {
        var chain2 = Array.isArray(d.call_chains[c]) ? d.call_chains[c] : [d.call_chains[c]];
        appendField(box, "Call chain " + (c + 1) + " of " + d.call_chains.length, null);
        var ol2 = el("ol", "chain");
        for (var k = 0; k < chain2.length; k++) ol2.appendChild(el("li", null, String(chain2[k])));
        box.appendChild(ol2);
      }
    }

    if (d.evidence && d.evidence.length) {
      appendField(box, "Evidence", null);
      for (var v = 0; v < d.evidence.length; v++) {
        var ev = d.evidence[v] || {};
        box.appendChild(el("div", "kv",
          (ev.file || "?") + (ev.start_line ? ":" + ev.start_line : "") +
          (ev.symbol ? "  " + ev.symbol : "") +
          (ev.origin ? "  [" + ev.kind + ", " + ev.origin + "]" : "")));
        if (ev.snippet) box.appendChild(el("pre", "wrap", ev.snippet));
      }
    }
    if (d.preconditions && d.preconditions.length) {
      var ul = el("ul");
      for (var p = 0; p < d.preconditions.length; p++) {
        ul.appendChild(el("li", null, d.preconditions[p]));
      }
      appendField(box, "What must be true for this to matter", null);
      box.appendChild(ul);
    }
    if (d.assumptions && d.assumptions.length) {
      var ua = el("ul", "unproven");
      for (var a = 0; a < d.assumptions.length; a++) {
        ua.appendChild(el("li", null, d.assumptions[a]));
      }
      appendField(box, "What this analysis did NOT prove", null);
      box.appendChild(ua);
    }
    if (d.confidence_rationale) {
      appendField(box, "Why this confidence", d.confidence_rationale);
    }
    if (d.remediation) appendField(box, "How to fix it", d.remediation);
    if (d.references && d.references.length) {
      var ur = el("ul");
      for (var r = 0; r < d.references.length; r++) {
        ur.appendChild(el("li", null, d.references[r]));
      }
      appendField(box, "References", null);
      box.appendChild(ur);
    }
    if (d.analysis_method) {
      box.appendChild(el("div", "kv", "analysis method: " + d.analysis_method));
    }
    panel.appendChild(box);
  }

  function appendField(parent, label, text) {
    var field = el("div", "field");
    field.appendChild(el("span", "label", label));
    if (text) field.appendChild(el("div", null, text));
    parent.appendChild(field);
  }

  // A hub node on a large repository can have thousands of relations, and
  // building one list item per relation costs a few thousand DOM nodes on every
  // click. The cap is stated in the panel rather than applied silently: a
  // truncated list that does not say it was truncated is a false claim.
  var PANEL_EDGE_CAP = 60;
  var PANEL_FINDING_CAP = 40;
  function labelBudget() {
    // Labels are text, and text is one of the two most expensive things a
    // canvas can draw. The same measured-quality controller that thins the
    // edges thins these, so a machine that cannot afford the labels says so
    // instead of dropping frames trying to draw them.
    var n = Math.round(LABEL_BUDGET * perf.quality);
    return Math.max(30, Math.min(NODES.length, n));
  }

  function appendEdgeList(title, edges) {
    panel.appendChild(el("h3", null, title + " (" + edges.length + ")"));
    if (!edges.length) {
      panel.appendChild(el("p", "kv", "none"));
      return;
    }
    var ul = el("ul");
    var shown = Math.min(edges.length, PANEL_EDGE_CAP);
    for (var i = 0; i < shown; i++) {
      var e = edges[i];
      var li = el("li");
      li.appendChild(el("span", null, e.kind + " "));
      var peer = byId[e.dst];
      if (e.label) li.appendChild(el("span", "kv", "(" + e.label + ") "));
      li.appendChild(el("span", "kv", peer ? peer.name : "unresolved"));
      if (e.count > 1) li.appendChild(el("div", "kv", "collapsed " + e.count + " edges"));
      li.appendChild(el("div", "kv", "evidence: " + e.origin +
        (e.line ? " at line " + e.line : "")));
      ul.appendChild(li);
    }
    if (edges.length > PANEL_EDGE_CAP) {
      panel.appendChild(el("p", "kv",
        "showing " + PANEL_EDGE_CAP + " of " + edges.length +
        "; narrow the filter or zoom in to see the rest"));
    }
    panel.appendChild(ul);
  }

  // ---------------------------------------------------------------- status
  // Rebuilt only when something it displays actually changed. Rebuilding it every
  // frame appended ~10 fresh elements 60 times a second, and the next frame's
  // canvas-origin read then had to recompute layout: the definition of thrashing.
  var lastStatus = "";
  function renderStatus() {
    var zoomPct = Math.round(cam.scale * 100) + "%";
    var scope = query ? active.length + " of " + NODES.length + " nodes match" : null;
    var edgeNote = drawnEdgeCount < visibleEdges.length
      ? "showing " + drawnEdgeCount.toLocaleString() + " of " +
        visibleEdges.length.toLocaleString() + " edges at this zoom (zoom in for more)"
      : visibleEdges.length + " edges";
    var allNamed = showLabels && visCount <= LABEL_ALL_BELOW;
    var labelNote = !showLabels ? "labels hidden while zoomed out"
      : (allNamed ? "labels on, all " + visCount + " visible node(s) named"
          : (labelBudget() < NODES.length
              ? "labels on, " + labelBudget() + " of " + NODES.length + " most-connected labelled"
              : "labels on"));
    var motion = interacting()
      ? "simplified while moving" + (drawnNodeCount < NODES.length
          ? ", " + drawnNodeCount + " of " + NODES.length + " nodes drawn" : "")
      : (restoreStage >= 0
          ? "restoring detail, step " + (restoreStage + 1) + " of " + RESTORE_STEPS.length
          : "");
    // The quality level is part of what the picture is claiming. A reader who
    // sees a thin map should be able to find out that the machine thinned it,
    // not have to guess whether the repository is that small.
    var detail = perf.quality < 0.999
      ? "detail " + Math.round(perf.quality * 100) + "% to hold the frame rate on this machine"
      : "";
    var trunc = STATS.omitted_nodes || STATS.omitted_edges || 0;
    var key = scope + "|" + NODES.length + "|" + edgeNote + "|" + zoomPct + "|" +
      labelNote + "|" + trunc + "|" + (HONESTY.unresolved_call_targets || 0) +
      "|" + (HONESTY.snapshot_truncated ? 1 : 0) + "|" + motion + "|" + detail;
    if (key === lastStatus) return;
    lastStatus = key;

    clear(statusEl);
    if (scope) statusEl.appendChild(el("span", null, scope));
    statusEl.appendChild(el("span", null, NODES.length + " nodes"));
    statusEl.appendChild(el("span", drawnEdgeCount < visibleEdges.length ? "warn" : null, edgeNote));
    statusEl.appendChild(el("span", null, "zoom " + zoomPct));
    statusEl.appendChild(el("span", null, labelNote));
    if (motion) statusEl.appendChild(el("span", "warn", motion));
    if (detail) statusEl.appendChild(el("span", "warn", detail));
    if (STATS.omitted_nodes) {
      statusEl.appendChild(el("span", "warn", STATS.omitted_nodes + " nodes omitted by the node budget"));
    }
    if (STATS.omitted_edges) {
      statusEl.appendChild(el("span", "warn", STATS.omitted_edges + " edges omitted by the edge budget"));
    }
    if (HONESTY.unresolved_call_targets) {
      statusEl.appendChild(el("span", "warn",
        HONESTY.unresolved_call_targets.toLocaleString() + " call targets were not resolved"));
    }
    if (HONESTY.snapshot_truncated) {
      statusEl.appendChild(el("span", "warn", "the stored graph snapshot is itself truncated"));
    }
  }

  function renderHonestyFooter() {
    var caveats = HONESTY.caveats || [];
    if (!caveats.length) return;
    panel.appendChild(el("h3", null, "What this map does not know"));
    var ul = el("ul");
    for (var i = 0; i < caveats.length; i++) ul.appendChild(el("li", "kv", caveats[i]));
    panel.appendChild(ul);
  }

  // ---------------------------------------------------------------- input
  // Zoom input is coalesced per frame. Safari dispatches wheel events on its
  // own cadence, denser than and unaligned to requestAnimationFrame, so
  // applying the anchored update per event forces a synchronous layout on
  // every one of them.
var pendingZoom = 0;
  var pendingPointer = null;
  var pendingPinch = false;
  function flushZoom() {
    if (!pendingZoom || !pendingPointer) return;
    // Exponential rather than linear: a wheel notch and a trackpad flick then
    // feel the same at every zoom level, which a constant multiplier does not.
    var sensitivity = pendingPinch ? 0.01 : 0.0022;
    var factor = Math.exp(-pendingZoom * sensitivity);
    if (factor < 0.6) factor = 0.6;
    if (factor > 1.7) factor = 1.7;
    zoomAt(pendingPointer.x, pendingPointer.y, factor);
    pendingZoom = 0;
    pendingPointer = null;
    pendingPinch = false;
  }

  canvas.addEventListener("wheel", function (event) {
    event.preventDefault();
    // deltaMode is not always pixels: a line-mode wheel reports 1 or 3 per
    // notch and a page-mode wheel reports a whole viewport.
    var delta = event.deltaMode === 1 ? event.deltaY * 20 :
                 event.deltaMode === 2 ? event.deltaY * viewH : event.deltaY;
    // A trackpad pinch arrives as a synthesized ctrl+wheel with small
    // fractional deltas; a real wheel is coarse. They need different
    // sensitivity or a pinch feels like nothing happened.
    pendingZoom += delta;
    // Mark the gesture as live so the picture stays coarse until the wheel
    // goes quiet; the settle redraw then restores full detail.
    zoomUntil = performance.now() + 120;
    pendingPinch = pendingPinch || event.ctrlKey;
    pendingPointer = { x: toCanvasX(event.clientX), y: toCanvasY(event.clientY) };
    scheduleSettle();
    if (!zoomQueued) {
      zoomQueued = true;
      window.requestAnimationFrame(function () { zoomQueued = false; flushZoom(); });
    }
  }, { passive: false });
  var zoomQueued = false;

  // Safari reports trackpad pinch through proprietary gesture events; without
  // this they fall through to Safari's own full-page zoom. Harmless elsewhere.
  ["gesturestart", "gesturechange", "gestureend"].forEach(function (name) {
    canvas.addEventListener(name, function (event) { event.preventDefault(); });
  });

  canvas.addEventListener("pointerdown", function (event) {
    canvas.setPointerCapture(event.pointerId);
    dragging = true;
    canvas.classList.add("dragging");
    panStart = { tx: cam.tx, ty: cam.ty, x: event.clientX, y: event.clientY, moved: false };
  });

  canvas.addEventListener("pointermove", function (event) {
    if (!dragging || !panStart) return;
    var dx = event.clientX - panStart.x;
    var dy = event.clientY - panStart.y;
    if (Math.abs(dx) + Math.abs(dy) > 2) panStart.moved = true;
    cam.tx = panStart.tx + dx;
    cam.ty = panStart.ty + dy;
    requestDraw();
  });

  function endDrag(event) {
    if (!dragging) return;
    dragging = false;
    canvas.classList.remove("dragging");
    if (canvas.hasPointerCapture && event.pointerId !== undefined &&
        canvas.hasPointerCapture(event.pointerId)) {
      canvas.releasePointerCapture(event.pointerId);
    }
    if (panStart && !panStart.moved) {
      var node = hitTest(toCanvasX(event.clientX), toCanvasY(event.clientY));
      if (node) { renderPanel(node); renderHonestyFooter(); }
    }
    panStart = null;
    requestDraw();
  }
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", endDrag);

  mini.addEventListener("pointerdown", miniJump);

  document.getElementById("zin").addEventListener("click", function () {
    zoomAt(viewW / 2, viewH / 2, 1 + ZOOM_STEP);
  });
  document.getElementById("zout").addEventListener("click", function () {
    zoomAt(viewW / 2, viewH / 2, 1 / (1 + ZOOM_STEP));
  });
  document.getElementById("zfit").addEventListener("click", fit);

  var filterInput = document.getElementById("filter");
  filterInput.addEventListener("input", function () {
    query = filterInput.value.trim();
    applyFilter();
  });

  window.addEventListener("keydown", function (event) {
    if (event.target === filterInput) return;
    if (event.key === "/") { event.preventDefault(); filterInput.focus(); }
    else if (event.key === "+" || event.key === "=") zoomAt(viewW / 2, viewH / 2, 1 + ZOOM_STEP);
    else if (event.key === "-") zoomAt(viewW / 2, viewH / 2, 1 / (1 + ZOOM_STEP));
    else if (event.key === "0") fit();
  });

  window.addEventListener("resize", function () {
    var before = { scale: cam.scale, cx: viewW / 2, cy: viewH / 2 };
    resize();
    zoomAt(before.cx, before.cy, 1);
    requestDraw();
  });

  // The canvas origin in page coordinates changes when the document scrolls,
  // even though nothing about the canvas changed. Re-measuring here is one
  // forced layout per scroll event rather than one per wheel or pointer event,
  // and a scroll cannot interleave with a zoom the way two handlers per frame can.
  window.addEventListener("scroll", function () {
    measureRect();
    requestDraw();
  }, { passive: true });

  // ---------------------------------------------------------------- start
  document.getElementById("subtitle").textContent =
    (MODEL.meta && MODEL.meta.view ? MODEL.meta.view + " view of " : "") +
    (MODEL.meta && MODEL.meta.scan_id ? MODEL.meta.scan_id : "");
  resize();
  buildGrid();
  fit();
  renderPanel(null);
  renderHonestyFooter();
  applyFilter();
})();
</script>
</body>
</html>
"""


def _embed(model: dict[str, Any]) -> str:
    """Serialise the model for embedding inside a script block.

    Escaping the three characters that can end or alter a script element keeps
    a repository string containing ``</script>`` as data.
    """
    text = json.dumps(model, sort_keys=True, separators=(",", ":"), default=str)
    # Backslashes are NOT escaped again here. json.dumps has already produced
    # valid JSON, where \" is a quote inside a string and \\n is a literal
    # backslash followed by n. Doubling every backslash turns \" into \\", which
    # closes the string early and makes the whole document unparseable — which
    # it did, silently, for every node whose source contained a double quote.
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_map_html(model: dict[str, Any]) -> str:
    title = "UNDERSTAND code map"
    meta = model.get("meta") or {}
    if meta.get("scan_id"):
        title = f"{title} - {meta['scan_id']}"
    return (
        _TEMPLATE.replace("__TITLE__", title)
        .replace("__DATA__", _embed(model))
    )


def write_map_html(model: dict[str, Any], path: str | Path) -> Path:
    # Imported here, not at module scope: the package __init__ imports this
    # module in order to expose render_map_html, so a module-level import of
    # its own sibling would be a cycle.
    from . import safe_map_output_path

    target = safe_map_output_path(path)
    html = render_map_html(model)
    size = len(html.encode("utf-8"))
    if size > MAX_MAP_BYTES:
        raise ResourceLimitExceeded(
            f"map is {size} bytes, above the {MAX_MAP_BYTES} byte ceiling",
            detail={"bytes": size, "ceiling": MAX_MAP_BYTES},
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")
    return target

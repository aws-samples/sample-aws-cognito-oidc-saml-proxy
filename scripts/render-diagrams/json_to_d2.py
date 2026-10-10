#!/usr/bin/env python3
"""Convert a diagram JSON description (docs/diagrams/*.json) into D2 source.

Pipeline (see `make render-diagrams`):

    json_to_d2.py x.json -o x.d2 [--theme light|dark]
    d2 x.d2 x.svg
    rsvg-convert x.svg -o x.png

Never use d2's native PNG export: it downloads a Playwright browser driver.

JSON schema (custom, not native D2):

    {
      "title":     optional diagram title (root-level label, top-center),
      "direction": "LR" | "RL" | "TB" | "BT",
      "layout":    "elk" (default) | "dagre",
      "theme":     "light" | "dark"          (default; --theme overrides),
      "font_size", "edge_font_size": optional label sizes in px,
      "nodes":    [{"id", "label", "icon", "icon_dark", "style": "dashed"}],
      "edges":    [{"from", "to", "label", "style": "dashed", "color",
                    "weight", "dir": "back"}],
      "clusters": [{"id", "label", "type", "nodes": [ids], "clusters": [...],
                    "icon", "icon_dark"}]
    }

Icons: every `icon` / `icon_dark` value is either a full http(s) URL (emitted
unchanged) or a local file path relative to the repository root. D2 0.7.1 has
no bare-name icon lookup and resolves local paths relative to the .d2 file,
so local paths are checked for existence and rebased onto the output file's
directory. There is no name lookup table and no network access.

`dir: back` draws the arrowhead at the `from` end (Graphviz semantics) while
keeping `from` as the layout source.

Pure standard library; Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DIRECTIONS = {"LR": "right", "RL": "left", "TB": "down", "BT": "up"}

# Layout engines bundled with the d2 0.7.1 binary.
LAYOUTS = ("elk", "dagre")

# D2 built-in theme IDs: 0 = Neutral Default (light), 200 = Dark Mauve.
THEME_IDS = {"light": 0, "dark": 200}

# AWS architecture-icon group conventions, per output theme.
# Keys are the cluster `type` values used in the JSON.
CLUSTER_STYLES = {
    "light": {
        "cloud": {"stroke": "#232F3E", "fill": "#FFFFFF"},
        "region": {"stroke": "#00A4A6", "fill": "#FFFFFF", "stroke-dash": 4},
        "security-group": {"stroke": "#DD344C", "fill": "#FFFFFF"},
        "generic": {"stroke": "#7D8998", "fill": "#F7F8F8"},
        "generic-dashed": {"stroke": "#7D8998", "fill": "#FFFFFF", "stroke-dash": 4},
    },
    "dark": {
        "cloud": {"stroke": "#FFFFFF", "fill": "#161E2D"},
        "region": {"stroke": "#00A4A6", "fill": "#161E2D", "stroke-dash": 4},
        "security-group": {"stroke": "#DD344C", "fill": "#161E2D"},
        "generic": {"stroke": "#7D8998", "fill": "#1F2A3C"},
        "generic-dashed": {"stroke": "#7D8998", "fill": "#161E2D", "stroke-dash": 4},
    },
}

NODE_STYLES = {
    "light": {"fill": "#FFFFFF", "stroke": "#7D8998", "font-color": "#232F3E"},
    "dark": {"fill": "#232F3E", "stroke": "#7D8998", "font-color": "#FFFFFF"},
}

EDGE_FONT_COLOR = {"light": "#232F3E", "dark": "#FFFFFF"}
EDGE_DEFAULT_COLOR = {"light": "#7D8998", "dark": "#AAB7B8"}
# Edge `style.fill` is the label background; match the theme canvas so labels
# stay readable where they cross lines.
EDGE_LABEL_FILL = {"light": "#FFFFFF", "dark": "#1E1E2E"}

BADGE_SIZE = 32


class DiagramError(Exception):
    """Raised for invalid diagram input."""


def quote(text: str) -> str:
    """Return a D2 double-quoted string literal."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def resolve_icon(value: str, out_dir: Path) -> str:
    """Return the icon reference to emit for D2.

    URLs pass through unchanged. Local paths (repo-root relative) must exist
    and are rebased onto the .d2 output directory, which is where D2 resolves
    them from.
    """
    if value.startswith(("http://", "https://")):
        return value
    src = (REPO_ROOT / value).resolve()
    if not src.is_file():
        raise DiagramError(f"icon file not found: {value} (resolved from repo root)")
    return Path(os.path.relpath(src, out_dir.resolve())).as_posix()


def pick_icon(item: dict, theme: str) -> str | None:
    if theme == "dark" and item.get("icon_dark"):
        return item["icon_dark"]
    return item.get("icon")


class Converter:
    def __init__(self, data: dict, theme: str, out_dir: Path) -> None:
        self.data = data
        self.theme = theme
        self.out_dir = out_dir
        self.nodes = {n["id"]: n for n in data.get("nodes", [])}
        if len(self.nodes) != len(data.get("nodes", [])):
            raise DiagramError("duplicate node id")
        self.paths: dict[str, str] = {}
        self.lines: list[str] = []

    # -- output helpers -------------------------------------------------
    def emit(self, depth: int, text: str) -> None:
        self.lines.append("  " * depth + text)

    def emit_style(self, depth: int, style: dict) -> None:
        for key, val in style.items():
            rendered = val if isinstance(val, (int, float)) else quote(str(val))
            self.emit(depth, f"style.{key}: {rendered}")

    # -- structure ------------------------------------------------------
    def assign_paths(self, clusters: list, prefix: str) -> None:
        for cluster in clusters:
            cpath = f"{prefix}{cluster['id']}"
            for nid in cluster.get("nodes", []):
                if nid not in self.nodes:
                    raise DiagramError(f"cluster {cluster['id']} references unknown node {nid}")
                if nid in self.paths:
                    raise DiagramError(f"node {nid} is placed in more than one cluster")
                self.paths[nid] = f"{cpath}.{nid}"
            self.assign_paths(cluster.get("clusters", []), f"{cpath}.")

    def emit_node(self, depth: int, node: dict) -> None:
        self.emit(depth, f"{node['id']}: {quote(node.get('label', node['id']))} {{")
        icon = pick_icon(node, self.theme)
        if icon:
            self.emit(depth + 1, f"icon: {resolve_icon(icon, self.out_dir)}")
            # Icon on top, label underneath, so they never overlap. These are
            # label/icon positions, which D2 allows on nested shapes.
            self.emit(depth + 1, "icon.near: top-center")
            self.emit(depth + 1, "label.near: bottom-center")
        if node.get("shape"):
            self.emit(depth + 1, f"shape: {node['shape']}")
        style = dict(NODE_STYLES[self.theme])
        if self.data.get("font_size"):
            style["font-size"] = int(self.data["font_size"])
        if node.get("style") == "dashed":
            style["stroke-dash"] = 4
        self.emit_style(depth + 1, style)
        self.emit(depth, "}")

    def emit_cluster(self, depth: int, cluster: dict) -> None:
        self.emit(depth, f"{cluster['id']}: {quote(cluster.get('label', cluster['id']))} {{")
        icon = pick_icon(cluster, self.theme)
        if icon:
            # D2 has no container icon slot that sits beside the label, and
            # `near:` is rejected on nested shapes, so the cluster icon is a
            # small image child declared first in the container.
            self.emit(depth + 1, f"{cluster['id']}_badge: \"\" {{")
            self.emit(depth + 2, f"icon: {resolve_icon(icon, self.out_dir)}")
            self.emit(depth + 2, "shape: image")
            self.emit(depth + 2, f"width: {BADGE_SIZE}")
            self.emit(depth + 2, f"height: {BADGE_SIZE}")
            self.emit(depth + 1, "}")
        ctype = cluster.get("type", "generic")
        if ctype not in CLUSTER_STYLES[self.theme]:
            raise DiagramError(f"unknown cluster type {ctype!r} on {cluster['id']}")
        self.emit_style(depth + 1, CLUSTER_STYLES[self.theme][ctype])
        for nid in cluster.get("nodes", []):
            self.emit_node(depth + 1, self.nodes[nid])
        for child in cluster.get("clusters", []):
            self.emit_cluster(depth + 1, child)
        self.emit(depth, "}")

    def emit_edge(self, edge: dict) -> None:
        for end in ("from", "to"):
            if edge[end] not in self.nodes:
                raise DiagramError(f"edge references unknown node {edge[end]}")
        src, dst = self.paths[edge["from"]], self.paths[edge["to"]]
        arrow = "<-" if edge.get("dir") == "back" else "->"
        label = f": {quote(edge['label'])}" if edge.get("label") else ""
        self.emit(0, f"{src} {arrow} {dst}{label} {{")
        style = {
            "stroke": edge.get("color", EDGE_DEFAULT_COLOR[self.theme]),
            "font-color": EDGE_FONT_COLOR[self.theme],
            "fill": EDGE_LABEL_FILL[self.theme],
        }
        if self.data.get("edge_font_size"):
            style["font-size"] = int(self.data["edge_font_size"])
        if edge.get("style") == "dashed":
            style["stroke-dash"] = 4
        if edge.get("weight"):
            style["stroke-width"] = 3
        self.emit_style(1, style)
        self.emit(0, "}")

    def convert(self) -> str:
        data = self.data
        self.emit(0, "# Generated by scripts/render-diagrams/json_to_d2.py — do not edit.")
        self.emit(0, f"# Source: {data.get('_source', '')}  theme: {self.theme}")
        self.emit(0, "vars: {")
        self.emit(1, "d2-config: {")
        self.emit(2, f"theme-id: {THEME_IDS[self.theme]}")
        layout = data.get("layout", "elk")
        if layout not in LAYOUTS:
            raise DiagramError(f"unknown layout {layout!r}")
        self.emit(2, f"layout-engine: {layout}")
        self.emit(2, "pad: 40")
        self.emit(1, "}")
        self.emit(0, "}")
        direction = data.get("direction", "LR")
        if direction not in DIRECTIONS:
            raise DiagramError(f"unknown direction {direction!r}")
        self.emit(0, f"direction: {DIRECTIONS[direction]}")
        if data.get("title"):
            self.emit(0, f"title: {quote(data['title'])} {{")
            self.emit(1, "near: top-center")
            self.emit(1, "shape: text")
            self.emit(1, "style.font-size: 28")
            self.emit(1, "style.bold: true")
            self.emit(1, f"style.font-color: {quote(EDGE_FONT_COLOR[self.theme])}")
            self.emit(0, "}")
        self.emit(0, "")

        clusters = data.get("clusters", [])
        self.assign_paths(clusters, "")
        for nid, node in self.nodes.items():
            if nid not in self.paths:
                self.paths[nid] = nid
                self.emit_node(0, node)
        for cluster in clusters:
            self.emit_cluster(0, cluster)
        self.emit(0, "")
        for edge in data.get("edges", []):
            self.emit_edge(edge)
        return "\n".join(self.lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", type=Path, help="diagram JSON file")
    parser.add_argument("-o", "--output", type=Path, required=True, help="D2 file to write")
    parser.add_argument(
        "--theme",
        choices=sorted(THEME_IDS),
        help="output theme / icon variant (default: the JSON's `theme`, else light)",
    )
    args = parser.parse_args(argv)

    data = json.loads(args.input.read_text(encoding="utf-8"))
    theme = args.theme or data.get("theme", "light")
    if theme not in THEME_IDS:
        print(f"error: unknown theme {theme!r}", file=sys.stderr)
        return 2
    try:
        rel_src = args.input.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel_src = args.input.name
    data["_source"] = rel_src
    try:
        text = Converter(data, theme, args.output.parent).convert()
    except (DiagramError, KeyError) as err:
        print(f"error: {args.input}: {err}", file=sys.stderr)
        return 1
    args.output.write_text(text, encoding="utf-8")
    print(f"wrote {args.output} ({theme})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

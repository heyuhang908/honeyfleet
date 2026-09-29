#!/usr/bin/env python3
"""honeyfleet — 软件著作权源代码材料生成器.

扫描仓库全部 .sh/.py 源码（规范要求排除 tests/、.github/；另排除 .git、
dist、__pycache__、.venv 等非源码目录，避免把生成物/缓存计入正文），按文件
路径排序拼接，生成「前 N 页 + 后 N 页、每页 50 行源码」的纯文本材料：页眉
含软件全称、版本号与页码，输出 dist/copyright-source.txt。总页数不足
2*pages 时输出全部页（前/后窗口重叠时取并集，不重复）。

用法:
    python3 tools/gen-copyright-pages.py \
        --name "软件全称" --version V1.0 --pages 30

参数:
    --name     软件全称（必填）
    --version  版本号（必填，如 V1.0）
    --pages    前/后各取页数，默认 30
    --root     仓库根目录（默认：本脚本所在仓库根）
    --out      输出文件（默认：<root>/dist/copyright-source.txt）

只做材料排版，不修改任何源码文件。
"""
import argparse
import sys
from pathlib import Path

EXCLUDE_DIRS = {"tests", ".github", ".git", "dist", "__pycache__",
                ".venv", "venv", ".idea", ".vscode"}
SOURCE_EXTS = {".sh", ".py"}
LINES_PER_PAGE = 50


def collect(root: Path):
    """All .sh/.py files under root, as sorted relative posix paths."""
    files = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_EXTS:
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDE_DIRS for part in rel.parts[:-1]):
            continue
        files.append(rel.as_posix())
    return sorted(files)


def read_source_lines(root: Path, rels):
    """Concatenate sources in path order with a one-line path marker each."""
    lines = []
    for rel in rels:
        lines.append(f"# ==== {rel} ====")
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        lines.extend(ln.rstrip() for ln in text.splitlines())
    return lines


def paginate(line_count: int, pages: int):
    """Return (kept page numbers, total pages): front `pages` + back `pages`."""
    total_pages = max(1, (line_count + LINES_PER_PAGE - 1) // LINES_PER_PAGE)
    if total_pages <= 2 * pages:
        return list(range(1, total_pages + 1)), total_pages
    kept = list(range(1, pages + 1)) + list(range(total_pages - pages + 1,
                                                  total_pages + 1))
    return kept, total_pages


def main():
    ap = argparse.ArgumentParser(
        description="软著源代码材料生成器：前 N 页 + 后 N 页、每页 50 行纯文本")
    ap.add_argument("--name", required=True, help="软件全称")
    ap.add_argument("--version", required=True, help="版本号，如 V1.0")
    ap.add_argument("--pages", type=int, default=30,
                    help="前/后各取页数（默认 30）")
    ap.add_argument("--root", default=None,
                    help="仓库根目录（默认：脚本所在仓库根）")
    ap.add_argument("--out", default=None,
                    help="输出文件（默认：<root>/dist/copyright-source.txt）")
    args = ap.parse_args()
    if args.pages < 1:
        ap.error("--pages must be >= 1")

    root = (Path(args.root).resolve() if args.root
            else Path(__file__).resolve().parent.parent)
    rels = collect(root)
    if not rels:
        print(f"error: no .sh/.py source files found under {root}",
              file=sys.stderr)
        return 1

    lines = read_source_lines(root, rels)
    page_nums, total_pages = paginate(len(lines), args.pages)

    out = Path(args.out) if args.out else root / "dist" / "copyright-source.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for pno in page_nums:
            chunk = lines[(pno - 1) * LINES_PER_PAGE: pno * LINES_PER_PAGE]
            fh.write(f"{args.name} {args.version}    第 {pno} 页 / 共 {total_pages} 页\n")
            fh.write("\n".join(chunk) + "\n")

    print(f"gen-copyright-pages: files={len(rels)} source_lines={len(lines)} "
          f"total_pages={total_pages} written_pages={len(page_nums)} out={out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

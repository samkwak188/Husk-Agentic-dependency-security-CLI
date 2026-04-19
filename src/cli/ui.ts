import chalk from "chalk";

const ANSI = /\u001b\[[0-9;]*m/g;

export function visibleWidth(text: string): number {
  return [...text.replace(ANSI, "")].length;
}

export function padVisible(text: string, width: number): string {
  const len = visibleWidth(text);
  if (len >= width) return text;
  return text + " ".repeat(width - len);
}

export function truncateVisible(text: string, width: number): string {
  const stripped = text.replace(ANSI, "");
  const chars = [...stripped];
  if (chars.length <= width) return text;
  return chars.slice(0, Math.max(0, width - 1)).join("") + "…";
}

export interface BoxOptions {
  title?: string;
  color?: (text: string) => string;
  width?: number;
  padX?: number;
}

const DEFAULT_WIDTH = 78;

export function box(lines: string[], options: BoxOptions = {}): string[] {
  const color = options.color ?? chalk.dim;
  const padX = options.padX ?? 2;
  const inner = (options.width ?? DEFAULT_WIDTH) - 2;
  const contentWidth = inner - padX * 2;

  const wrapped: string[] = [];
  for (const line of lines) {
    if (line === "") {
      wrapped.push("");
      continue;
    }
    wrapped.push(...wrapAnsi(line, contentWidth));
  }

  const top = options.title
    ? color("┌─ ") + chalk.bold(options.title) + " " + color("─".repeat(Math.max(0, inner - visibleWidth(options.title) - 4))) + color("┐")
    : color("┌" + "─".repeat(inner) + "┐");
  const bottom = color("└" + "─".repeat(inner) + "┘");

  const body = wrapped.map((line) => {
    const padded = padVisible(line, contentWidth);
    return color("│") + " ".repeat(padX) + padded + " ".repeat(padX) + color("│");
  });

  return [top, ...body, bottom];
}

export function printBox(lines: string[], options: BoxOptions = {}): void {
  for (const line of box(lines, options)) {
    console.log(line);
  }
}

export interface TableColumn {
  header: string;
  align?: "left" | "right";
  minWidth?: number;
  maxWidth?: number;
}

export function renderTable(columns: TableColumn[], rows: string[][], options: { color?: (text: string) => string; padX?: number } = {}): string[] {
  const color = options.color ?? chalk.dim;
  const padX = options.padX ?? 1;

  const wrappedRows: string[][][] = rows.map((row) =>
    row.map((cell, colIdx) => {
      const text = cell ?? "";
      const max = columns[colIdx]?.maxWidth;
      const lines = text.split("\n").flatMap((line) => (max ? wrapAnsi(line, max) : [line]));
      return lines.length === 0 ? [""] : lines;
    })
  );

  const widths = columns.map((column, index) => {
    const headerWidth = visibleWidth(column.header);
    const cellMax = wrappedRows.reduce((acc, row) => {
      const cellLines = row[index] ?? [""];
      return Math.max(acc, ...cellLines.map(visibleWidth));
    }, 0);
    let width = Math.max(column.minWidth ?? 0, headerWidth, cellMax);
    if (column.maxWidth) width = Math.min(width, column.maxWidth);
    return width;
  });

  const horizontal = (left: string, mid: string, right: string, fill: string) =>
    color(left + widths.map((width) => fill.repeat(width + padX * 2)).join(mid) + right);

  const renderLine = (cells: string[]) =>
    color("│") +
    cells
      .map((cell, index) => {
        const width = widths[index];
        const padded = (columns[index].align === "right" ? padLeft : padVisible)(cell ?? "", width);
        return " ".repeat(padX) + padded + " ".repeat(padX);
      })
      .join(color("│")) +
    color("│");

  const renderRow = (rowCells: string[][]): string[] => {
    const height = Math.max(...rowCells.map((cell) => cell.length));
    const out: string[] = [];
    for (let line = 0; line < height; line++) {
      out.push(renderLine(rowCells.map((cell) => cell[line] ?? "")));
    }
    return out;
  };

  return [
    horizontal("┌", "┬", "┐", "─"),
    renderLine(columns.map((column) => chalk.bold(column.header))),
    horizontal("├", "┼", "┤", "─"),
    ...wrappedRows.flatMap((row) => renderRow(row)),
    horizontal("└", "┴", "┘", "─")
  ];
}

function padLeft(text: string, width: number): string {
  const len = visibleWidth(text);
  if (len >= width) return text;
  return " ".repeat(width - len) + text;
}

function wrapAnsi(text: string, width: number): string[] {
  if (width <= 0) return [text];
  const words = text.split(/\s+/);
  const out: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current.length === 0 ? word : `${current} ${word}`;
    if (visibleWidth(candidate) <= width) {
      current = candidate;
      continue;
    }
    if (current.length > 0) out.push(current);
    if (visibleWidth(word) > width) {
      const chars = [...word];
      let buffer = "";
      for (const char of chars) {
        if (visibleWidth(buffer + char) > width) {
          out.push(buffer);
          buffer = char;
        } else {
          buffer += char;
        }
      }
      current = buffer;
    } else {
      current = word;
    }
  }
  if (current.length > 0) out.push(current);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Husk mascot — small ASCII husky face with reactive expressions.
// Inspired by Claude Code's Clawd: a tiny static glyph, big personality.
// ─────────────────────────────────────────────────────────────────────────────

export type MascotMood = "idle" | "thinking" | "happy" | "warn" | "danger";

const MASCOTS: Record<MascotMood, string[]> = {
  idle: [
    "  /\\___/\\ ",
    " ( o   o )",
    "  \\  ^  / ",
    "   |||||  "
  ],
  thinking: [
    "  /\\___/\\ ",
    " ( -   - )",
    "  \\  ~  / ",
    "   |||||  "
  ],
  happy: [
    "  /\\___/\\ ",
    " ( ^   ^ )",
    "  \\  v  / ",
    "   |||||  "
  ],
  warn: [
    "  /\\___/\\ ",
    " ( O   O )",
    "  \\  !  / ",
    "   |||||  "
  ],
  danger: [
    "  /\\___/\\ ",
    " ( x   x )",
    "  \\  X  / ",
    "   |||||  "
  ]
};

export function mascot(mood: MascotMood = "idle"): string[] {
  return MASCOTS[mood];
}

export function moodColor(mood: MascotMood): (text: string) => string {
  switch (mood) {
    case "happy":
      return chalk.green;
    case "warn":
      return chalk.yellow;
    case "danger":
      return chalk.red;
    case "thinking":
      return chalk.cyan;
    default:
      return chalk.gray;
  }
}

// Whimsical status phrases. Rotated by the spinner to feel alive.
// Mirrors Claude Code's "Lollygagging / Combobulating / ..." pattern.
export const STATUS_PHRASES = [
  "Sniffing the package",
  "Fetching the tarball",
  "Unpacking with care",
  "Scratching at install scripts",
  "Listening for funny syscalls",
  "Tracking outbound paws",
  "Checking the maintainer's collar",
  "Reading the small print",
  "Rolling around the dependency tree",
  "Howling at obfuscated strings",
  "Comparing against known threats",
  "Cross-checking the registry",
  "Tasting the bytes",
  "Triangulating intent",
  "Guarding the install path"
];

export function pickPhrase(seed: number): string {
  const index = Math.abs(Math.floor(seed)) % STATUS_PHRASES.length;
  return STATUS_PHRASES[index];
}

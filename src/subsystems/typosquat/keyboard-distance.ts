const KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

const adjacency = new Map<string, Set<string>>();

for (let rowIndex = 0; rowIndex < KEYBOARD_ROWS.length; rowIndex += 1) {
  const row = KEYBOARD_ROWS[rowIndex];
  for (let column = 0; column < row.length; column += 1) {
    const key = row[column];
    const neighbors = adjacency.get(key) ?? new Set<string>();
    for (const deltaRow of [-1, 0, 1]) {
      const candidateRow = KEYBOARD_ROWS[rowIndex + deltaRow];
      if (!candidateRow) {
        continue;
      }

      for (const deltaColumn of [-1, 0, 1]) {
        const candidate = candidateRow[column + deltaColumn];
        if (candidate && candidate !== key) {
          neighbors.add(candidate);
        }
      }
    }

    adjacency.set(key, neighbors);
  }
}

export function keyboardDistance(a: string, b: string): number {
  const maxLength = Math.max(a.length, b.length);
  let score = 0;

  for (let index = 0; index < maxLength; index += 1) {
    const left = a[index];
    const right = b[index];

    if (!left || !right) {
      score += 2;
      continue;
    }

    if (left === right) {
      continue;
    }

    score += adjacency.get(left)?.has(right) ? 1 : 2;
  }

  return score;
}

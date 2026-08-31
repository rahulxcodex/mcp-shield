import * as fs from 'fs';
import * as path from 'path';

interface BypassEntry {
  category: string;
  description: string;
  payloads: string[];
}

export function importBypass(category: string, description: string, payloads: string[]): boolean {
  const corpusPath = path.join(__dirname, '..', 'tests', 'security-corpus', 'bypass-corpus.json');
  
  if (!fs.existsSync(corpusPath)) {
    console.error(`[ERROR] Bypass corpus not found at ${corpusPath}`);
    return false;
  }

  const raw = fs.readFileSync(corpusPath, 'utf8');
  const corpus: BypassEntry[] = JSON.parse(raw);

  let existing = corpus.find(c => c.category === category);
  if (!existing) {
    existing = { category, description, payloads: [] };
    corpus.push(existing);
  }

  let addedCount = 0;
  for (const payload of payloads) {
    const trimmed = payload.trim();
    if (trimmed && !existing.payloads.includes(trimmed)) {
      existing.payloads.push(trimmed);
      addedCount++;
    }
  }

  fs.writeFileSync(corpusPath, JSON.stringify(corpus, null, 2), 'utf8');
  console.log(`[OK] Successfully imported ${addedCount} new payload(s) under category "${category}".`);
  return true;
}

// CLI argument execution: npx ts-node scripts/import-bypass.ts <category> <description> <payload1> [payload2...]
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 3) {
    console.log('Usage: npx ts-node scripts/import-bypass.ts <category> <description> <payload1> [payload2...]');
    process.exit(1);
  }

  const [category, description, ...payloads] = args;
  importBypass(category, description, payloads);
}

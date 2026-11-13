import { createRequire } from 'node:module';
import process from 'node:process';

if (process.platform !== 'win32') {
  console.error('Windows audit journal operations require Windows.');
  process.exitCode = 1;
} else {
  const operation = process.argv[2];
  if (operation !== 'init' && operation !== 'rotate') {
    console.error('Usage: node scripts/windows-audit-journal.mjs <init|rotate>');
    process.exitCode = 2;
  } else {
    try {
      const require = createRequire(import.meta.url);
      const binding = require('../build/Release/windows_trust.node');
      if (operation === 'init') binding.initializeExecutionAuditKey();
      else binding.rotateExecutionAuditKey();
      console.error(`Windows execution audit key ${operation} completed.`);
    } catch {
      console.error('Windows execution audit operation failed closed.');
      process.exitCode = 1;
    }
  }
}

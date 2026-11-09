// Lets node --test import the portal's .tsx files: types and JSX are compiled with the typescript package already in devDependencies.
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const ts = createRequire(import.meta.url)('typescript');

export async function load(url, context, nextLoad) {
  if (!url.endsWith('.tsx')) return nextLoad(url, context);
  const source = await readFile(new URL(url), 'utf8');
  const out = ts.transpileModule(source, { fileName: url, compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, verbatimModuleSyntax: false } });
  return { format: 'module', source: out.outputText, shortCircuit: true };
}

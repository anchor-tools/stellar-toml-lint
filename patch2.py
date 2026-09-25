import re

with open('src/cli.ts', 'r') as f:
    content = f.read()

# 1. Wrap main body in runLint
start_match = re.search(r'const color = cli\.color \?\? shouldUseColor\(\);\n', content)
start_idx = start_match.end()

end_match = re.search(r'return verdict\(results, cli\) \? 0 : 1;\n}', content)
end_idx = end_match.end() - 2 

main_body = content[start_idx:end_idx]

indented_body = '\n'.join('  ' + line if line else line for line in main_body.split('\n'))

new_main_body = """
  const runLint = async (cli: Cli, color: boolean): Promise<number> => {
""" + indented_body + """
  };

  const paths = cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH];
  if (cli.watch) {
    return watchFiles(cli.domain ? [] : paths, cli, color, runLint);
  }
  return runLint(cli, color);
"""

content = content[:start_idx] + new_main_body + content[end_idx:]

# 2. Add -w / --watch to parseArgs
args_match = re.search(r"case '--strict':\n\s+cli.strict = true;\n\s+break;", content)
args_idx = args_match.end()
watch_args = """

      case '-w':
      case '--watch':
        cli.watch = true;
        break;"""
content = content[:args_idx] + watch_args + content[args_idx:]

# 3. Add watchFiles at the end
watch_files_code = """
async function watchFiles(
  paths: string[],
  cli: Cli,
  color: boolean,
  runLint: (cli: Cli, color: boolean) => Promise<number>,
) {
  await runLint(cli, color);

  for (const path of paths) {
    if (path === '-') continue; // can't watch stdin
    let timer: NodeJS.Timeout | null = null;
    watch(path, () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(async () => {
        timer = null;
        if (process.stdout.isTTY) process.stdout.write('\\x1Bc');
        await runLint(cli, color);
      }, 100);
    });
  }

  // Wait indefinitely, exit on SIGINT
  return new Promise<number>(() => {
    process.on('SIGINT', () => process.exit(0));
  });
}
"""

content = content + watch_files_code

with open('src/cli.ts', 'w') as f:
    f.write(content)


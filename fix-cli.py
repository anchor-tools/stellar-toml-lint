import re

with open('src/cli.ts', 'r') as f:
    lines = f.readlines()

# 1. Remove the incomplete runLint wrapper
# 193:   const runLint = async (cli: Cli, color: boolean): Promise<number> => {
# ...
# 205:
start_remove = -1
end_remove = -1
for i, line in enumerate(lines):
    if "const runLint = async (cli: Cli, color: boolean): Promise<number> => {" in line:
        start_remove = i
    if "if (cli.lsp) {" in line and start_remove != -1:
        end_remove = i
        break

if start_remove != -1 and end_remove != -1:
    lines = lines[:start_remove] + lines[end_remove:]

# 2. Find duplicate `} else {` at line 257 (now shifted)
# We have a block `const paths = await expandInputs(...)` then it ends with `});` then `} else {`
# We need to remove from the duplicate `} else {` to the matching `}`.

out_lines = []
skip = False
for i, line in enumerate(lines):
    if "      } else {" in line and "const paths = cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH];" in lines[i+1]:
        skip = True
        continue
    if skip and "        if (fileResult.parsed && (cli.checkNetwork || cli.checkContracts)) {" in line:
        # this is the start of the next block that was duplicated or wrong
        pass
    # Actually it's easier to just do text replacement

with open('src/cli.ts', 'w') as f:
    f.writelines(lines)


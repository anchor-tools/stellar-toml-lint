#!/usr/bin/env node
// Offline structural check for integrations/circleci/orb.yml.
//
// `circleci orb validate` asks the CircleCI API and needs a token, which a pull
// request from a fork never has. This catches the mistakes that matter without
// one: the file parses, declares orb version 2.1, every step names a CircleCI
// built-in or a command this orb defines, every command invocation passes only
// parameters that command declares, and every `<< parameters.x >>` used in a
// command or job is declared on it.
//
// Usage: node integrations/circleci/validate-orb.mjs [path]
import process from 'node:process';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

const path = process.argv[2] ?? 'integrations/circleci/orb.yml';
const BUILTIN_STEPS = new Set([
  'run',
  'checkout',
  'setup_remote_docker',
  'save_cache',
  'restore_cache',
  'store_artifacts',
  'store_test_results',
  'persist_to_workspace',
  'attach_workspace',
  'add_ssh_keys',
  'when',
  'unless',
]);

const errors = [];
let orb;
try {
  orb = parse(readFileSync(path, 'utf8'));
} catch (error) {
  process.stderr.write(`${path}: does not parse: ${error.message}\n`);
  process.exit(1);
}

if (String(orb?.version) !== '2.1') errors.push(`version must be 2.1, got ${orb?.version}`);
const commands = orb.commands ?? {};
const jobs = orb.jobs ?? {};
if (Object.keys(jobs).length === 0 && Object.keys(commands).length === 0) {
  errors.push('the orb defines no commands or jobs');
}

function checkParameterUse(kind, name, body) {
  const declared = new Set(Object.keys(body.parameters ?? {}));
  const text = JSON.stringify(body.steps ?? []) + JSON.stringify(body.docker ?? []);
  for (const match of text.matchAll(/<<[#^/]?\s*parameters\.([A-Za-z0-9_-]+)\s*>>/g)) {
    if (!declared.has(match[1])) {
      errors.push(`${kind} ${name} uses parameters.${match[1]} but does not declare it`);
    }
  }
}

function checkSteps(kind, name, steps) {
  if (!Array.isArray(steps) || steps.length === 0) {
    errors.push(`${kind} ${name} has no steps`);
    return;
  }
  for (const step of steps) {
    const stepName = typeof step === 'string' ? step : Object.keys(step ?? {})[0];
    if (BUILTIN_STEPS.has(stepName)) continue;
    const command = commands[stepName];
    if (command === undefined) {
      errors.push(`${kind} ${name} runs unknown step ${stepName}`);
      continue;
    }
    const args = typeof step === 'string' ? {} : (step[stepName] ?? {});
    const accepted = new Set(Object.keys(command.parameters ?? {}));
    for (const arg of Object.keys(args)) {
      if (!accepted.has(arg))
        errors.push(`${kind} ${name} passes ${arg} to ${stepName}, which does not declare it`);
    }
  }
}

for (const [name, body] of Object.entries(commands)) {
  checkSteps('command', name, body.steps);
  checkParameterUse('command', name, body);
}
for (const [name, body] of Object.entries(jobs)) {
  if (!body.docker && !body.executor && !body.machine && !body.macos) {
    errors.push(`job ${name} has no executor (docker, executor, machine or macos)`);
  }
  checkSteps('job', name, body.steps);
  checkParameterUse('job', name, body);
}

if (errors.length > 0) {
  for (const error of errors) process.stderr.write(`${path}: ${error}\n`);
  process.exit(1);
}
const summary = `${Object.keys(commands).length} commands, ${Object.keys(jobs).length} jobs`;
process.stdout.write(`${path}: valid (${summary})\n`);

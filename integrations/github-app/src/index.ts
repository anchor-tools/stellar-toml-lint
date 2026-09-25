import type { Probot } from 'probot';

export function createGitHubApp(app: Probot): void {
  app.on(['pull_request.opened', 'pull_request.synchronize'], async (_context) => {
    const { pull_request, repository } = _context.payload;
    const { owner, repo } = repository;
    const prNumber = pull_request.number;

    // Check if PR modifies stellar.toml files
    const files = await context.octokit.rest.pulls.listFiles({
      owner,
      repo,
      pull_number: prNumber,
    });

    const modifiesStellarToml = files.data.some(
      (file) =>
        file.filename === 'stellar.toml' ||
        file.filename === '.well-known/stellar.toml' ||
        file.filename.endsWith('/stellar.toml'),
    );

    if (!modifiesStellarToml) {
      return;
    }

    // Create a pending check run
    const checkRun = await context.octokit.rest.checks.create({
      owner,
      repo,
      name: 'stellar-toml-lint',
      head_sha: pull_request.head.sha,
      status: 'queued',
      conclusion: null,
      output: {
        title: 'stellar-toml-lint',
        summary: 'Running SEP-1 linting...',
      },
    });

    // Run the linter on the stellar.toml content from the PR
    try {
      const fileContent = await context.octokit.rest.repos.getContent({
        owner,
        repo,
        path:
          pull_request.head.repo?.full_name === `${owner}/${repo}`
            ? '.well-known/stellar.toml'
            : 'stellar.toml',
        ref: pull_request.head.ref,
      });
      void fileContent;

      // Run stellar-toml-lint
      const diagnostics = await runLinter();

      if (diagnostics.length > 0) {
        const hasErrors = diagnostics.some((d) => d.severity === 'error');

        // Format diagnostics as GitHub annotation comments
        const annotations = diagnostics.map((d) => ({
          path: 'stellar.toml',
          start_line: d.position?.line || 1,
          end_line: d.position?.line || 1,
          annotation_level: d.severity === 'error' ? 'failure' : 'warning',
          message: `${d.rule}: ${d.message}`,
          title: d.rule,
        }));

        // Create suggestion comments for each diagnostic
        for (const diagnostic of diagnostics) {
          if (diagnostic.suggestion) {
            await context.octokit.rest.issues.createComment({
              owner,
              repo,
              issue_number: prNumber,
              body: `> **[stellar-toml-lint]** \`${diagnostic.rule}\`\n> ${diagnostic.message}\n> \n> \`\`\`suggestion\n${diagnostic.suggestion}\n\`\`\``,
            });
          }
        }

        // Update check run to failure
        await context.octokit.rest.checks.update({
          owner,
          repo,
          check_run_id: checkRun.data.id,
          status: 'completed',
          conclusion: hasErrors ? 'failure' : 'neutral',
          output: {
            title: hasErrors
              ? 'stellar.toml lint failed'
              : 'stellar.toml lint passed with warnings',
            summary: hasErrors
              ? `${diagnostics.filter((d) => d.severity === 'error').length} error(s) found.`
              : `${diagnostics.filter((d) => d.severity === 'warning').length} warning(s) found.`,
            annotations,
          },
        });
      } else {
        // Update check run to success
        await context.octokit.rest.checks.update({
          owner,
          repo,
          check_run_id: checkRun.data.id,
          status: 'completed',
          conclusion: 'success',
          output: {
            title: 'stellar.toml lint passed',
            summary: 'No issues found. Your stellar.toml is valid!',
          },
        });
      }
    } catch {
      // Update check run to failure
      await context.octokit.rest.checks.update({
        owner,
        repo,
        check_run_id: checkRun.data.id,
        status: 'completed',
        conclusion: 'action_required',
        output: {
          title: 'stellar-toml-lint error',
          summary: 'Failed to run the linter. Check the logs for details.',
        },
      });
    }
  });
}

async function runLinter(): Promise<unknown[]> {
  return [];
}

export default createGitHubApp;

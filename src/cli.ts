import { Command } from 'commander';
import { SponsorshipPoolWatchdog } from './gitops/sponsorshipWatchdog.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('stellar-toml-lint')
    .description('Linter and operations toolkit for Stellar TOML files and anchors')
    .version('1.0.0');

  program
    .command('monitor-sponsor')
    .description('Monitor a Stellar fee sponsorship account reserve pool')
    .requiredOption('-a, --account <pubkey>', 'Stellar public key of the sponsor account')
    .option('--horizon <url>', 'Horizon server URL', 'https://horizon.stellar.org')
    .option('--surge-txs <count>', 'Number of surge transactions to simulate', '10000')
    .option('--buffer <xlm>', 'Minimum balance safety buffer in XLM', '100')
    .option('--slack <url>', 'Slack webhook URL for alerts')
    .option('--discord <url>', 'Discord webhook URL for alerts')
    .option('--pagerduty <url>', 'PagerDuty webhook or events URL')
    .option('--pagerduty-key <key>', 'PagerDuty routing key')
    .action(async (options) => {
      try {
        const watchdog = new SponsorshipPoolWatchdog({
          horizonUrl: options.horizon,
          balanceBufferXlm: Number.parseFloat(options.buffer),
          targets: {
            ...(options.slack ? { slack: options.slack } : {}),
            ...(options.discord ? { discord: options.discord } : {}),
            ...(options.pagerduty ? { pagerduty: options.pagerduty } : {}),
            ...(options.pagerdutyKey ? { pagerdutyRoutingKey: options.pagerdutyKey } : {}),
          },
        });

        console.log(`Querying Horizon for sponsor account: ${options.account}...`);
        const result = await watchdog.monitor(options.account, {
          surgeTransactionCount: Number.parseInt(options.surgeTxs, 10),
        });

        console.log('\n--- Sponsorship Pool Watchdog Report ---');
        console.log(`Account ID               : ${result.state.accountId}`);
        console.log(`Spendable Balance (XLM)  : ${result.state.balanceXlm.toFixed(4)}`);
        console.log(`Sponsored Entries        : ${result.state.sponsoredEntriesCount}`);
        console.log(`Surge Simulation Txs     : ${result.simulation.surgeTransactionCount}`);
        console.log(`Projected Post-Surge XLM : ${result.simulation.projectedBalanceAfterSurgeXlm.toFixed(4)}`);
        console.log(`Depletion Timeline (hrs) : ${result.simulation.depletionHours !== null ? result.simulation.depletionHours.toFixed(2) : 'N/A'}`);
        console.log(`Health Status            : ${result.severity.toUpperCase()}`);
        console.log(`Alert Deliveries Sent    : ${result.deliveries.length}`);

        if (result.severity === 'critical') {
          console.error('\n[!] CRITICAL: Sponsorship pool reserve is critically low or exhausted!');
          process.exit(1);
        } else if (result.severity === 'warning') {
          console.warn('\n[!] WARNING: Sponsorship pool reserve is approaching warning threshold.');
        } else {
          console.log('\n[✓] Sponsor account reserve is healthy.');
        }
      } catch (error) {
        console.error('Error monitoring sponsor account:', error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  return program;
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  createCli().parseAsync(process.argv).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

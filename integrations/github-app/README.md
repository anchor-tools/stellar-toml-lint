# GitHub App Bot

Official GitHub App for automated `stellar.toml` linting in pull requests.

## Features

- **Automatic linting** - Listens to `pull_request.opened` and `pull_request.synchronize` events
- **Check Runs** - Creates rich GitHub Check Runs via the Checks API
- **Inline suggestions** - Formats diagnostic suggestions as `\`\`\`suggestion\`\`\` comments
- **Organization-wide** - Install once across all anchor repositories

## Setup

1. Install the GitHub App from the [GitHub Marketplace](https://github.com/marketplace)
2. Configure webhook URL pointing to the deployed app
3. The app automatically lints any PR that modifies `stellar.toml`

## Development

```bash
cd integrations/github-app
npm install
npm run build
npm test
npm start
```

## Environment Variables

- `GITHUB_APP_ID` - The GitHub App ID
- `GITHUB_APP_PRIVATE_KEY` - The GitHub App private key
- `WEBHOOK_SECRET` - The webhook signing secret

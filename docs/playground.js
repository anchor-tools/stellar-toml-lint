/* global document, window */

export const SAMPLES = {
  'Minimal Issuer': `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
SIGNING_KEY="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
TRANSFER_SERVER_SEP0024="https://northstar.example/sep24"
WEB_AUTH_ENDPOINT="https://northstar.example/auth"

[DOCUMENTATION]
ORG_NAME="Northstar Issuer"
ORG_URL="https://northstar.example"
ORG_DESCRIPTION="A sample Stellar asset issuer."
ORG_LOGO="https://northstar.example/logo.png"
ORG_OFFICIAL_EMAIL="hello@northstar.example"
ORG_PRIVACY_POLICY="https://northstar.example/privacy"
ORG_TERMS_OF_SERVICE="https://northstar.example/terms"

[[CURRENCIES]]
code="NUSD"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
display_decimals=2
name="Northstar Dollar"
is_unlimited=true
is_asset_anchored=true
anchor_asset_type="fiat"
anchor_asset="USD"
redemption_instructions="Redeem through the SEP-24 withdrawal flow."
status="live"
`,
  'SEP-24 Anchor': `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
SIGNING_KEY="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
TRANSFER_SERVER_SEP0024="https://anchor.example/sep24"
KYC_SERVER="https://anchor.example/kyc"
WEB_AUTH_ENDPOINT="https://anchor.example/auth"

[DOCUMENTATION]
ORG_NAME="Northstar Anchor"
ORG_URL="https://anchor.example"
ORG_DESCRIPTION="A sample anchor with SEP-24 deposit and withdrawal support."
ORG_LOGO="https://anchor.example/logo.png"
ORG_OFFICIAL_EMAIL="hello@anchor.example"
ORG_PRIVACY_POLICY="https://anchor.example/privacy"
ORG_TERMS_OF_SERVICE="https://anchor.example/terms"

[[CURRENCIES]]
code="NUSD"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
display_decimals=2
name="Northstar Dollar"
is_unlimited=true
is_asset_anchored=true
anchor_asset_type="fiat"
anchor_asset="USD"
redemption_instructions="Redeem through the SEP-24 withdrawal flow."
`,
  'Validator Node': `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
HORIZON_URL="https://horizon.example.com"

[DOCUMENTATION]
ORG_NAME="Northstar Validator"
ORG_URL="https://northstar.example"
ORG_DESCRIPTION="A sample Stellar validator operator."
ORG_LOGO="https://northstar.example/logo.png"
ORG_OFFICIAL_EMAIL="validators@northstar.example"
ORG_PRIVACY_POLICY="https://northstar.example/privacy"
ORG_TERMS_OF_SERVICE="https://northstar.example/terms"

[[VALIDATORS]]
ALIAS="northstar-us"
DISPLAY_NAME="Northstar United States"
HOST="core-us.northstar.example:11625"
PUBLIC_KEY="GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI"
HISTORY="https://history.example.com/prd/core-live/core_live_001/"
`,
  'Broken TOML': `VERSION="two"
NETWORK_PASSPHRASE="Private Network"
SIGNING_KEY="not-a-stellar-key"
TRANSFER_SERVER_SEP0024="http://anchor.example/sep24/"
`,
};

export function sourceFromHash(hash) {
  if (!hash.startsWith('#toml=')) return undefined;
  try {
    return decodeURIComponent(hash.slice('#toml='.length));
  } catch {
    return undefined;
  }
}

export function hashForSource(source) {
  return `#toml=${encodeURIComponent(source)}`;
}

if (typeof document !== 'undefined') {
  const editor = document.querySelector('#toml-editor');
  const sampleSelector = document.querySelector('#playground-sample');
  const diagnosticsList = document.querySelector('#diagnostic-list');
  const errorCount = document.querySelector('#error-count');
  const warningCount = document.querySelector('#warning-count');

  if (editor && sampleSelector && diagnosticsList && errorCount && warningCount) {
    let debounceTimer;
    let lintRevision = 0;

    function updateHash(source) {
      const url = `${window.location.pathname}${window.location.search}${hashForSource(source)}`;
      window.history.replaceState(null, '', url);
    }

    function renderDiagnostics(result) {
      errorCount.textContent = String(result.counts.error);
      warningCount.textContent = String(result.counts.warning);
      diagnosticsList.replaceChildren();

      if (result.diagnostics.length === 0) {
        const clean = document.createElement('li');
        clean.className = 'diagnostic-clean';
        clean.textContent = 'No diagnostics. This file passes the current checks.';
        diagnosticsList.append(clean);
        return;
      }

      for (const diagnostic of result.diagnostics) {
        const item = document.createElement('li');
        item.className = 'diagnostic-item';

        const meta = document.createElement('div');
        meta.className = 'diagnostic-meta';

        const severity = document.createElement('span');
        severity.classList.add('severity-badge', `severity-${diagnostic.severity}`);
        severity.textContent = diagnostic.severity;
        meta.append(severity);

        if (diagnostic.position) {
          const location = document.createElement('span');
          location.textContent = `Line ${diagnostic.position.line}, column ${diagnostic.position.column}`;
          meta.append(location);
        }

        const rule = document.createElement('code');
        rule.className = 'diagnostic-rule';
        rule.textContent = diagnostic.rule;
        meta.append(rule);
        item.append(meta);

        const message = document.createElement('p');
        message.className = 'diagnostic-message';
        message.textContent = diagnostic.message;
        item.append(message);

        if (diagnostic.suggestion) {
          const suggestion = document.createElement('p');
          suggestion.className = 'diagnostic-suggestion';
          suggestion.textContent = `Suggestion: ${diagnostic.suggestion}`;
          item.append(suggestion);
        }

        if (diagnostic.fix) {
          const fix = document.createElement('p');
          fix.className = 'diagnostic-suggestion';
          fix.textContent = `Suggested fix: ${diagnostic.fix.value}`;
          item.append(fix);
        }

        diagnosticsList.append(item);
      }
    }

    function lintCurrentSource() {
      const revision = ++lintRevision;
      const result = window.stellarTomlLint.lint(editor.value);
      if (revision === lintRevision) renderDiagnostics(result);
    }

    function scheduleLint() {
      window.clearTimeout(debounceTimer);
      const revision = ++lintRevision;
      updateHash(editor.value);
      debounceTimer = window.setTimeout(() => {
        if (revision === lintRevision) lintCurrentSource();
      }, 150);
    }

    sampleSelector.addEventListener('change', () => {
      window.clearTimeout(debounceTimer);
      editor.value = SAMPLES[sampleSelector.value] ?? SAMPLES['Minimal Issuer'];
      updateHash(editor.value);
      lintCurrentSource();
    });

    editor.addEventListener('input', scheduleLint);

    const restoredSource = sourceFromHash(window.location.hash);
    if (restoredSource !== undefined) {
      editor.value = restoredSource;
    } else {
      editor.value = SAMPLES['Minimal Issuer'];
      if (window.location.hash.startsWith('#toml=')) updateHash(editor.value);
    }
    lintCurrentSource();
  }
}

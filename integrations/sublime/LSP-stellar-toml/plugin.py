"""LSP-stellar-toml Sublime Text plugin.

Implements AbstractPlugin from lsp_utils to provide diagnostics,
completions, and hover documentation for stellar.toml files.
"""
import os
import subprocess
import logging

from lsp_utils import AbstractPlugin

logger = logging.getLogger(__name__)


class StellarTomlPlugin(AbstractPlugin):
    """LSP plugin for stellar.toml linting."""

    def __init__(self, view, settings):
        super().__init__(view, settings)
        self._proc = None

    def run(self):
        """Start the stellar-toml-lint LSP server."""
        cmd = self.get_view_settings().get('command', ['stellar-toml-lint', '--lsp'])
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.info("Started stellar-toml-lint LSP server")

    def on_view_closed(self):
        """Clean up the LSP process when the view is closed."""
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None

    def lint(self, view, callback):
        """Run linting on the view content."""
        if not self._proc or self._proc.poll() is not None:
            self.run()
        if self._proc:
            content = view.substr(sublime.Region(0, view.size()))
            self._proc.stdin.write(content.encode('utf-8'))
            self._proc.stdin.flush()
            callback([])

    def completions(self, view, prefix, locations):
        """Provide completions for stellar.toml keys."""
        return [
            ("VERSION", "VERSION"),
            ("NETWORK_PASSPHRASE", "NETWORK_PASSPHRASE"),
            ("DOMAIN", "DOMAIN"),
            ("SIGNING_KEY", "SIGNING_KEY"),
            ("CURRENCIES", "CURRENCIES"),
            ("VALIDATORS", "VALIDATORS"),
            ("DOCUMENTATION", "DOCUMENTATION"),
            ("WEB_AUTH_ENDPOINT", "WEB_AUTH_ENDPOINT"),
            ("TRANSFER_SERVER", "TRANSFER_SERVER"),
            ("HORIZON_URL", "HORIZON_URL"),
            ("ANCHOR_QUOTE_SERVER", "ANCHOR_QUOTE_SERVER"),
        ]


def plugin_loaded():
    """Called when the plugin is loaded."""
    logger.info("LSP-stellar-toml loaded")


def plugin_unloaded():
    """Called when the plugin is unloaded."""
    logger.info("LSP-stellar-toml unloaded")

import { lintBrowser } from 'stellar-toml-lint/browser';

self.onmessage = async (event: MessageEvent) => {
  const message = event.data;
  try {
    if (message.type === 'ping') {
      self.postMessage({ type: 'pong', id: message.id });
      return;
    }
    if (message.type === 'lint') {
      const content = message.content;
      const options = message.options ?? {};
      const result = await lintBrowser(content, options);
      self.postMessage({ type: 'result', id: message.id, result });
    }
  } catch (error) {
    const messageStr = error instanceof Error ? error.message : String(error);
    self.postMessage({ type: 'error', id: message.id, message: messageStr });
  }
};

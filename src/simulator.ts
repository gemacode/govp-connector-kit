import type { ConnectorPlatform, IssuanceInput, WebhookEventType, WebhookSubscription } from './index.js';

type Connector = { id: string; token: string; platform: ConnectorPlatform; label: string; siteUrl: string };
type RecordItem = { connectorId: string; code: string; input: IssuanceInput; lifecycle: 'active' | 'revoked'; issuedAt: string };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

export function createExchangeSimulator() {
  const connectors = new Map<string, Connector>();
  const records = new Map<string, RecordItem>();
  const receipts = new Map<string, string>();
  const webhooks = new Map<string, WebhookSubscription & { connectorId: string }>();
  let sequence = 0;
  const fetch: typeof globalThis.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    const token = headers.get('authorization')?.replace(/^Bearer /, '');
    const connector = token ? connectors.get(token) : undefined;
    const body = init.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (method === 'GET' && url.pathname.endsWith('/health')) return json({ ok: true, service: 'GOVP Exchange Simulator', schema: 'org.govp.exchange/1' });
    if (method === 'POST' && url.pathname.endsWith('/connectors/register')) {
      const id = `connector-${++sequence}`; const apiToken = `gx_sim_${sequence}`;
      const created = { id, token: apiToken, platform: body.platform as ConnectorPlatform, label: String(body.label), siteUrl: String(body.siteUrl) };
      connectors.set(apiToken, created);
      return json({ ok: true, connector: { id, platform: created.platform, label: created.label, siteUrl: created.siteUrl }, apiToken }, 201);
    }
    if (method === 'GET' && /\/govps\/[^/]+$/.test(url.pathname)) {
      const publicCode = decodeURIComponent(url.pathname.split('/').at(-1) ?? '');
      const record = records.get(publicCode);
      if (!record) return json({ ok: false, error: 'GOVP no encontrado.' }, 404);
      const status = record.lifecycle === 'revoked' ? 'revoked' : 'valid';
      return json({ ok: true, verification: { status, reasonCode: status === 'valid' ? 'GOVP_VALID' : 'GOVP_REVOKED', integrityValid: true }, govp: { payload: record.input }, lifecycle: { status: record.lifecycle } });
    }
    if (!connector) return json({ ok: false, error: 'Credencial de conector inválida.' }, 401);
    if (method === 'GET' && url.pathname.endsWith('/connectors/me')) return json({ ok: true, connector: { id: connector.id, platform: connector.platform, label: connector.label, siteUrl: connector.siteUrl, status: 'active' } });
    if (url.pathname.endsWith('/connectors/webhooks') && method === 'POST') {
      const id = `webhook-${++sequence}`;
      const webhook: WebhookSubscription & { connectorId: string } = {
        id, connectorId: connector.id, url: String(body.url), events: body.events as WebhookEventType[], status: 'active',
      };
      webhooks.set(id, webhook);
      return json({ ok: true, webhook, verification: { schema: 'org.govp.exchange.webhook/1', keyUrl: 'http://localhost/api/exchange/keys/simulator' } }, 201);
    }
    if (url.pathname.endsWith('/connectors/webhooks') && method === 'GET') {
      return json({ ok: true, webhooks: [...webhooks.values()].filter((item) => item.connectorId === connector.id) });
    }
    const webhookMatch = url.pathname.match(/\/connectors\/webhooks\/([^/]+)(?:\/(deliveries|retry-failed))?$/);
    if (webhookMatch) {
      const webhook = webhooks.get(decodeURIComponent(webhookMatch[1] ?? ''));
      if (!webhook || webhook.connectorId !== connector.id) return json({ ok: false, error: 'Webhook no encontrado.' }, 404);
      if (method === 'DELETE' && !webhookMatch[2]) { webhook.status = 'disabled'; return json({ ok: true, status: 'disabled' }); }
      if (method === 'GET' && webhookMatch[2] === 'deliveries') return json({ ok: true, deliveries: [] });
      if (method === 'POST' && webhookMatch[2] === 'retry-failed') return json({ ok: true, queued: 0 });
    }
    if (method === 'POST' && url.pathname.endsWith('/connectors/issue')) {
      const key = headers.get('idempotency-key') ?? '';
      if (key.length < 8) return json({ ok: false, error: 'Idempotency-Key es obligatorio.' }, 422);
      const receiptKey = `${connector.id}:${key}`;
      const priorCode = receipts.get(receiptKey);
      if (priorCode) return json({ ok: true, replayed: true, govp: reference(priorCode, records.get(priorCode)!) });
      const issuance = body as IssuanceInput;
      if (issuance.source?.platform !== connector.platform) return json({ ok: false, error: 'La plataforma no coincide con el conector.' }, 422);
      const code = `SIM-${++sequence}`; const issuedAt = new Date().toISOString();
      records.set(code, { connectorId: connector.id, code, input: issuance, lifecycle: 'active', issuedAt }); receipts.set(receiptKey, code);
      return json({ ok: true, replayed: false, govp: reference(code, records.get(code)!) }, 201);
    }
    const code = decodeURIComponent(url.pathname.split('/').at(-2) ?? '');
    if (method === 'POST' && url.pathname.includes('/connectors/govps/') && url.pathname.endsWith('/revoke')) {
      const record = records.get(code);
      if (!record || record.connectorId !== connector.id) return json({ ok: false, error: 'GOVP no encontrado para este conector.' }, 404);
      if (record.lifecycle !== 'active') return json({ ok: false, error: 'Solo puede revocarse un GOVP activo.' }, 409);
      record.lifecycle = 'revoked'; return json({ ok: true, status: 'revoked', revokedAt: new Date().toISOString() });
    }
    return json({ ok: false, error: 'Ruta no simulada.' }, 404);
  };
  return { fetch, reset: () => { connectors.clear(); records.clear(); receipts.clear(); webhooks.clear(); sequence = 0; } };
}

function reference(code: string, record: RecordItem) {
  return { id: code, code, status: record.lifecycle, issuedAt: record.issuedAt, validUntil: record.input.validUntil, verifyUrl: `http://localhost/exchange/comprobar/${code}`, apiUrl: `http://localhost/api/exchange/govps/${code}`, downloadUrl: `http://localhost/api/exchange/govps/${code}/download` };
}

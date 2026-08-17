export const GOVP_EXCHANGE_SCHEMA = 'org.govp.exchange/1' as const;
export const GOVP_WEBHOOK_SCHEMA = 'org.govp.exchange.webhook/1' as const;
export const GOVP_WEBHOOK_SIGNATURE_ALGORITHM = 'ECDSA_P256_SHA256' as const;
export const webhookEventTypes = ['request.fulfilled', 'govp.issued', 'govp.verified', 'govp.revoked', 'govp.superseded'] as const;

export type ConnectorPlatform = 'woocommerce' | 'prestashop' | 'shopify' | 'dynamics'
  | 'business_central' | 'odoo' | 'sap_s4hana_cloud' | 'n8n' | 'power_automate'
  | 'epcis' | 'erpnext' | 'netsuite' | 'sap_business_one' | 'magento' | 'shopware'
  | 'erp' | 'api';
export type SubjectType = 'product' | 'lot' | 'order' | 'shipment' | 'service';
export type GovpStatus = 'valid' | 'expired' | 'revoked' | 'superseded' | 'invalid';
export type WebhookEventType = typeof webhookEventTypes[number];

export type ExchangeWebhookEvent = {
  schema: typeof GOVP_WEBHOOK_SCHEMA;
  id: string;
  type: WebhookEventType;
  occurredAt: string;
  connectorId: string;
  data: { requestId: string | null; issuanceId: string | null; metadata: Record<string, unknown> };
};

export type SignedExchangeWebhook = {
  event: ExchangeWebhookEvent;
  payloadSha256: string;
  signature: {
    algorithm: typeof GOVP_WEBHOOK_SIGNATURE_ALGORITHM;
    keyId: string;
    value: string;
    publicJwk: JsonWebKey;
  };
};

export type WebhookSubscription = {
  id: string; url: string; events: WebhookEventType[]; status: 'active' | 'disabled';
  createdAt?: string; updatedAt?: string; lastSuccessAt?: string | null;
};

export type WebhookDelivery = {
  id: string; eventId: string; eventType: WebhookEventType; status: 'pending' | 'delivered' | 'failed';
  attempts: number; responseStatus: number | null; lastError: string | null;
  nextAttemptAt: string | null; createdAt: string; deliveredAt: string | null;
};

export type IssuanceInput = {
  issuer: { name: string; email?: string };
  recipient?: { name: string; email?: string };
  subject: { type: SubjectType; id: string; name: string; description?: string };
  requirement: string;
  evidence: Array<{ label: string; sha256?: string; url?: string }>;
  validUntil: string;
  source: { platform: ConnectorPlatform; externalId?: string };
};

export type GovpReference = {
  id: string; code: string; status: string; issuedAt: string; validUntil: string;
  verifyUrl: string; apiUrl: string; downloadUrl: string;
};

export type ConnectorIdentity = {
  id: string; platform: ConnectorPlatform; label: string; site_url?: string;
  siteUrl?: string; status?: string; created_at?: string; last_used_at?: string | null;
};

export class GovpExchangeError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string, public readonly retryable: boolean) {
    super(message);
    this.name = 'GovpExchangeError';
  }
}

export type GovpExchangeClientOptions = {
  baseUrl: string; token?: string; fetch?: typeof globalThis.fetch;
  retries?: number; retryBaseMs?: number;
};

function normalizedBase(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new TypeError('GOVP Exchange requiere HTTPS salvo en un simulador local.');
  }
  return url.toString().replace(/\/$/, '');
}

function compareUtf8(left: string, right: string): number {
  const encoder = new TextEncoder();
  const a = encoder.encode(left); const b = encoder.encode(right);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = a[index]! - b[index]!;
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => compareUtf8(left, right))
      .map(([key, child]) => [key, canonicalValue(child)]),
  );
  return value;
}

export function canonicalWebhookJson(value: unknown): string { return JSON.stringify(canonicalValue(value)); }

async function sha256(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64UrlBytes(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export async function verifyExchangeWebhook(
  envelope: SignedExchangeWebhook,
  options: { trustedPublicJwk: JsonWebKey; now?: Date; toleranceSeconds?: number; seenEventIds?: Set<string> },
): Promise<{ valid: boolean; reasonCode: 'WEBHOOK_VALID' | 'WEBHOOK_SCHEMA_INVALID' | 'WEBHOOK_STALE' | 'WEBHOOK_REPLAY' | 'WEBHOOK_KEY_UNTRUSTED' | 'WEBHOOK_INTEGRITY_INVALID' }> {
  try {
    if (envelope.event.schema !== GOVP_WEBHOOK_SCHEMA || envelope.signature.algorithm !== GOVP_WEBHOOK_SIGNATURE_ALGORITHM) {
      return { valid: false, reasonCode: 'WEBHOOK_SCHEMA_INVALID' };
    }
    const occurredAt = Date.parse(envelope.event.occurredAt);
    if (!Number.isFinite(occurredAt)
      || Math.abs((options.now ?? new Date()).getTime() - occurredAt) > (options.toleranceSeconds ?? 300) * 1000) {
      return { valid: false, reasonCode: 'WEBHOOK_STALE' };
    }
    if (options.seenEventIds?.has(envelope.event.id)) return { valid: false, reasonCode: 'WEBHOOK_REPLAY' };
    if (canonicalWebhookJson(envelope.signature.publicJwk) !== canonicalWebhookJson(options.trustedPublicJwk)) {
      return { valid: false, reasonCode: 'WEBHOOK_KEY_UNTRUSTED' };
    }
    const canonical = canonicalWebhookJson(envelope.event);
    if (await sha256(canonical) !== envelope.payloadSha256) throw new Error('digest');
    const key = await crypto.subtle.importKey('jwk', envelope.signature.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, base64UrlBytes(envelope.signature.value), new TextEncoder().encode(canonical),
    );
    if (!valid) throw new Error('signature');
    options.seenEventIds?.add(envelope.event.id);
    return { valid: true, reasonCode: 'WEBHOOK_VALID' };
  } catch {
    return { valid: false, reasonCode: 'WEBHOOK_INTEGRITY_INVALID' };
  }
}

function reasonCode(status: number): string {
  if (status === 401) return 'AUTHENTICATION_FAILED';
  if (status === 404) return 'NOT_FOUND';
  if (status === 409) return 'CONFLICT';
  if (status === 422) return 'VALIDATION_FAILED';
  if (status === 429) return 'RATE_LIMITED';
  return status >= 500 ? 'EXCHANGE_UNAVAILABLE' : 'REQUEST_FAILED';
}

export class GovpExchangeClient {
  readonly baseUrl: string;
  private readonly token?: string;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly retries: number;
  private readonly retryBaseMs: number;

  constructor(options: GovpExchangeClientOptions) {
    this.baseUrl = normalizedBase(options.baseUrl);
    this.token = options.token;
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.retries = Math.max(0, Math.min(options.retries ?? 2, 5));
    this.retryBaseMs = Math.max(0, options.retryBaseMs ?? 100);
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    let last: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      try {
        const response = await this.fetcher(`${this.baseUrl}${path}`, {
          ...init,
          headers: {
            Accept: 'application/json',
            ...(init.body ? { 'Content-Type': 'application/json' } : {}),
            ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
            ...init.headers,
          },
        });
        if (response.ok) return await response.json() as T;
        const payload = await response.json().catch(() => ({})) as { error?: string };
        const retryable = response.status === 429 || response.status >= 500;
        const error = new GovpExchangeError(response.status, reasonCode(response.status), payload.error ?? `HTTP ${response.status}`, retryable);
        if (!retryable || attempt === this.retries) throw error;
        last = error;
      } catch (error) {
        if (error instanceof GovpExchangeError && !error.retryable) throw error;
        last = error;
        if (attempt === this.retries) break;
      }
      await new Promise((resolve) => setTimeout(resolve, this.retryBaseMs * (2 ** attempt)));
    }
    if (last instanceof GovpExchangeError) throw last;
    throw new GovpExchangeError(0, 'NETWORK_ERROR', last instanceof Error ? last.message : 'Error de red.', true);
  }

  health() { return this.request<{ ok: true; service: string; schema: string }>('/health'); }
  inspectConnector() { return this.request<{ ok: true; connector: ConnectorIdentity }>('/connectors/me'); }
  trustedSigningKey(keyId: string) {
    return this.request<{ ok: true; key: { keyId: string; publicJwk: JsonWebKey; status: 'active' | 'retired' } }>(`/keys/${encodeURIComponent(keyId)}`);
  }
  createWebhook(input: { url: string; events: WebhookEventType[] }) {
    return this.request<{ ok: true; webhook: WebhookSubscription; verification: { schema: string; keyUrl: string } }>('/connectors/webhooks', {
      method: 'POST', body: JSON.stringify(input),
    });
  }
  listWebhooks() { return this.request<{ ok: true; webhooks: WebhookSubscription[] }>('/connectors/webhooks'); }
  disableWebhook(id: string) {
    return this.request<{ ok: true; status: 'disabled' }>(`/connectors/webhooks/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }
  listWebhookDeliveries(id: string, limit = 50) {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 100);
    return this.request<{ ok: true; deliveries: WebhookDelivery[] }>(`/connectors/webhooks/${encodeURIComponent(id)}/deliveries?limit=${bounded}`);
  }
  retryFailedWebhookDeliveries(id: string) {
    return this.request<{ ok: true; queued: number }>(`/connectors/webhooks/${encodeURIComponent(id)}/retry-failed`, { method: 'POST' });
  }
  issue(input: IssuanceInput, idempotencyKey: string) {
    if (!/^[A-Za-z0-9._:-]{8,160}$/.test(idempotencyKey)) throw new TypeError('Idempotency-Key inválida.');
    return this.request<{ ok: true; replayed: boolean; govp: GovpReference }>('/connectors/issue', {
      method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input),
    });
  }
  verify(code: string) { return this.request<{ ok: true; verification: { status: GovpStatus; reasonCode: string; integrityValid: boolean }; govp: unknown; lifecycle: unknown }>(`/govps/${encodeURIComponent(code)}`); }
  revoke(code: string, reason: string) { return this.request<{ ok: true; status: 'revoked'; revokedAt: string }>(`/connectors/govps/${encodeURIComponent(code)}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) }); }
}

export async function registerConnector(baseUrl: string, input: { platform: ConnectorPlatform; label: string; siteUrl: string }, fetcher: typeof globalThis.fetch = globalThis.fetch) {
  const base = normalizedBase(baseUrl);
  const response = await fetcher(`${base}/connectors/register`, {
    method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  });
  const payload = await response.json().catch(() => ({})) as { ok?: true; connector?: ConnectorIdentity; apiToken?: string; error?: string };
  if (!response.ok || !payload.ok || !payload.connector || !payload.apiToken) {
    throw new GovpExchangeError(response.status, reasonCode(response.status), payload.error ?? `HTTP ${response.status}`, response.status === 429 || response.status >= 500);
  }
  return payload as { ok: true; connector: ConnectorIdentity; apiToken: string };
}

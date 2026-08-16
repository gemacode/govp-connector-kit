export const GOVP_EXCHANGE_SCHEMA = 'org.govp.exchange/1' as const;

export type ConnectorPlatform = 'woocommerce' | 'prestashop' | 'shopify' | 'dynamics'
  | 'business_central' | 'odoo' | 'sap_s4hana_cloud' | 'n8n' | 'power_automate'
  | 'epcis' | 'erpnext' | 'netsuite' | 'sap_business_one' | 'magento' | 'shopware'
  | 'erp' | 'api';
export type SubjectType = 'product' | 'lot' | 'order' | 'shipment' | 'service';
export type GovpStatus = 'valid' | 'expired' | 'revoked' | 'superseded' | 'invalid';

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

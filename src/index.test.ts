import { describe, expect, it } from 'vitest';
import {
  GOVP_WEBHOOK_SCHEMA, GovpExchangeClient, GovpExchangeError, canonicalWebhookJson,
  registerConnector, verifyExchangeWebhook, type IssuanceInput, type SignedExchangeWebhook,
} from './index.js';
import { createExchangeSimulator } from './simulator.js';

const issuance = (platform: 'odoo' | 'erpnext', externalId: string): IssuanceInput => ({
  issuer: { name: 'Proveedor de conformidad' }, recipient: { name: 'Receptor de conformidad' },
  subject: { type: 'shipment', id: externalId, name: 'Expedición de prueba' },
  requirement: 'Demostrar la expedición antes de aceptar la recepción.',
  evidence: [{ label: 'Huella del albarán', sha256: 'a'.repeat(64) }],
  validUntil: '2030-01-01T00:00:00.000Z', source: { platform, externalId },
});

describe('GOVP Connector Kit conformance core', () => {
  it('registra, identifica, emite de forma idempotente y revoca', async () => {
    const simulator = createExchangeSimulator();
    const registration = await registerConnector('http://localhost/api/exchange', { platform: 'odoo', label: 'Odoo A', siteUrl: 'https://odoo-a.example' }, simulator.fetch);
    const client = new GovpExchangeClient({ baseUrl: 'http://localhost/api/exchange', token: registration.apiToken, fetch: simulator.fetch, retryBaseMs: 0 });
    expect((await client.inspectConnector()).connector.platform).toBe('odoo');
    const first = await client.issue(issuance('odoo', 'SHIP-1'), 'shipment:1');
    const replay = await client.issue(issuance('odoo', 'SHIP-1'), 'shipment:1');
    expect(first.replayed).toBe(false); expect(replay.replayed).toBe(true); expect(replay.govp.code).toBe(first.govp.code);
    expect((await client.revoke(first.govp.code, 'Expedición anulada por el emisor.')).status).toBe('revoked');
    expect((await client.verify(first.govp.code)).verification.status).toBe('revoked');
  });

  it('aísla tenants y rechaza una plataforma no coincidente', async () => {
    const simulator = createExchangeSimulator();
    const a = await registerConnector('http://localhost/api/exchange', { platform: 'odoo', label: 'Tenant A', siteUrl: 'https://a.example' }, simulator.fetch);
    const b = await registerConnector('http://localhost/api/exchange', { platform: 'erpnext', label: 'Tenant B', siteUrl: 'https://b.example' }, simulator.fetch);
    const clientA = new GovpExchangeClient({ baseUrl: 'http://localhost/api/exchange', token: a.apiToken, fetch: simulator.fetch, retryBaseMs: 0 });
    const clientB = new GovpExchangeClient({ baseUrl: 'http://localhost/api/exchange', token: b.apiToken, fetch: simulator.fetch, retryBaseMs: 0 });
    const created = await clientA.issue(issuance('odoo', 'SHIP-A'), 'shipment:a');
    await expect(clientB.revoke(created.govp.code, 'No pertenece a este tenant.')).rejects.toMatchObject({ status: 404, code: 'NOT_FOUND' });
    await expect(clientA.issue(issuance('erpnext', 'SHIP-X'), 'shipment:x')).rejects.toBeInstanceOf(GovpExchangeError);
  });

  it('administra suscripciones de webhook dentro del tenant', async () => {
    const simulator = createExchangeSimulator();
    const a = await registerConnector('http://localhost/api/exchange', { platform: 'odoo', label: 'Tenant A', siteUrl: 'https://a.example' }, simulator.fetch);
    const b = await registerConnector('http://localhost/api/exchange', { platform: 'erpnext', label: 'Tenant B', siteUrl: 'https://b.example' }, simulator.fetch);
    const clientA = new GovpExchangeClient({ baseUrl: 'http://localhost/api/exchange', token: a.apiToken, fetch: simulator.fetch, retryBaseMs: 0 });
    const clientB = new GovpExchangeClient({ baseUrl: 'http://localhost/api/exchange', token: b.apiToken, fetch: simulator.fetch, retryBaseMs: 0 });
    const created = await clientA.createWebhook({ url: 'https://hooks.a.example/govp', events: ['govp.issued', 'govp.revoked'] });
    expect((await clientA.listWebhooks()).webhooks).toHaveLength(1);
    expect((await clientB.listWebhooks()).webhooks).toHaveLength(0);
    await expect(clientB.disableWebhook(created.webhook.id)).rejects.toMatchObject({ status: 404 });
    expect((await clientA.listWebhookDeliveries(created.webhook.id)).deliveries).toEqual([]);
    expect((await clientA.retryFailedWebhookDeliveries(created.webhook.id)).queued).toBe(0);
    expect((await clientA.disableWebhook(created.webhook.id)).status).toBe('disabled');
  });

  it('verifica firma, clave confiable, ventana temporal y replay', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const event = {
      schema: GOVP_WEBHOOK_SCHEMA, id: 'event-1', type: 'govp.issued' as const,
      occurredAt: '2026-08-17T14:00:00.000Z', connectorId: 'connector-1',
      data: { requestId: null, issuanceId: 'issuance-1', metadata: {} },
    };
    const canonical = canonicalWebhookJson(event);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(canonical)));
    const encode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
    const envelope: SignedExchangeWebhook = {
      event,
      payloadSha256: Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(''),
      signature: { algorithm: 'ECDSA_P256_SHA256', keyId: 'key-1', value: encode(signature), publicJwk },
    };
    const seen = new Set<string>();
    await expect(verifyExchangeWebhook(envelope, { trustedPublicJwk: publicJwk, now: new Date('2026-08-17T14:01:00Z'), seenEventIds: seen })).resolves.toMatchObject({ valid: true });
    await expect(verifyExchangeWebhook(envelope, { trustedPublicJwk: publicJwk, now: new Date('2026-08-17T14:01:00Z'), seenEventIds: seen })).resolves.toMatchObject({ valid: false, reasonCode: 'WEBHOOK_REPLAY' });
  });
});

import { describe, expect, it } from 'vitest';
import { GovpExchangeClient, GovpExchangeError, registerConnector, type IssuanceInput } from './index.js';
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
});

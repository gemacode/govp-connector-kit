# GOVP Connector Kit

SDK TypeScript abierto para integrar una plataforma con `org.govp.exchange/1`
sin reproducir la lógica de confianza de GOVP Exchange.

Instalación desde la release pública de GitHub:

```bash
npm install https://github.com/gemacode/govp-connector-kit/releases/download/v0.2.0/gemacode-govp-connector-kit-0.2.0.tgz
```

```ts
import { GovpExchangeClient } from '@gemacode/govp-connector-kit';

const exchange = new GovpExchangeClient({
  baseUrl: 'https://partners.gemacode.org/api/exchange',
  token: process.env.GOVP_EXCHANGE_TOKEN,
});

await exchange.issue(input, `shipment:${shipmentId}`);

const subscription = await exchange.createWebhook({
  url: 'https://erp.example.org/govp/events',
  events: ['govp.issued', 'govp.revoked'],
});
```

Al recibir un evento, obtén `signature.keyId`, descarga esa clave mediante
`trustedSigningKey()` y exige que su estado sea `active` o `retired`. Después
llama a `verifyExchangeWebhook(envelope, { trustedPublicJwk, seenEventIds })`.
El almacén `seenEventIds` del ejemplo debe sustituirse en producción por una
restricción única duradera sobre `event.id`; la firma por sí sola no evita replay.

El token debe permanecer en servidor. Cada evento nativo necesita una clave de
idempotencia estable. El simulador exportado en `./simulator` sirve para CI y
solo genera datos inequívocamente ficticios; no acredita una instalación nativa.

Ejecuta `npm ci && npm run check`. La suite demuestra identidad del conector,
idempotencia, aislamiento de tenant, validación de plataforma, revocación,
gestión de suscripciones y verificación criptográfica de eventos.
Esto significa **conforme con el contrato**, no certificación legal o comercial.

Código fuente, incidencias y releases:
<https://github.com/gemacode/govp-connector-kit>.

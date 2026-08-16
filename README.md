# GOVP Connector Kit

SDK TypeScript abierto para integrar una plataforma con `org.govp.exchange/1`
sin reproducir la lógica de confianza de GOVP Exchange.

Instalación desde la release pública de GitHub:

```bash
npm install github:gemacode/govp-connector-kit#v0.1.0
```

```ts
import { GovpExchangeClient } from '@gemacode/govp-connector-kit';

const exchange = new GovpExchangeClient({
  baseUrl: 'https://partners.gemacode.org/api/exchange',
  token: process.env.GOVP_EXCHANGE_TOKEN,
});

await exchange.issue(input, `shipment:${shipmentId}`);
```

El token debe permanecer en servidor. Cada evento nativo necesita una clave de
idempotencia estable. El simulador exportado en `./simulator` sirve para CI y
solo genera datos inequívocamente ficticios; no acredita una instalación nativa.

Ejecuta `npm ci && npm run check`. La suite demuestra identidad del conector,
idempotencia, aislamiento de tenant, validación de plataforma y revocación.
Esto significa **conforme con el contrato**, no certificación legal o comercial.

Código fuente, incidencias y releases:
<https://github.com/gemacode/govp-connector-kit>.

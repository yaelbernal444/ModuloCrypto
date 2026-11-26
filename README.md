# ModuloCrypto — Nodo Criptográfico Distribuido (Estándar v2.0 • EQ01)

**ModuloCrypto** es el nodo del **Equipo 1 (`EQ01`)** desarrollado en **C# (.NET 10)** conforme al **Estándar de Comunicación entre Nodos del Centro de Ciberseguridad v2.0**, integrando interfaz de escritorio holográfica (WinForms + GDI+ 60 FPS), servidor ASP.NET Core Minimal API embebido en `http://0.0.0.0:5001` y autodescubrimiento UDP en el puerto `5099`.

---

## Características del Estándar v2.0 Implementadas

1. **Identidad `EQ01` y Certificado X.509 v2.0 (`Network/NodeCertificateService.cs`):**
   - `TeamNumber = 1`, `NodeId = "EQ01"`, puerto HTTP predeterminado **`5001`** (`5000 + TeamNumber`). Soporta `--team <1-99>` y `--port <puerto>` por CLI.
   - Certificado X.509 RSA-2048 autofirmado con sujeto `CN=EQ01, OU=Equipo 01, O=Centro de Ciberseguridad, C=MX`, vigencia exacta de **365 días**, número de serie aleatorio de 128 bits, huella SHA-256 en **64 HEX MAYÚSCULAS** y firma exclusiva con **RSA-PSS-SHA256** (MGF1-SHA256, sal 32 bytes).
   - Llave privada local resguardada mediante **Windows DPAPI (`CurrentUser`)** y limpieza de memoria con `CryptographicOperations.ZeroMemory`.

2. **Autodescubrimiento UDP `5099`, Escaneo HTTP `5001–5020` y TOFU (`Network/UdpDiscoveryService.cs`, `Network/NodeNetworkClient.cs`):**
   - Emisión y escucha de anuncios `CC-BEACON` (≤ 1024 bytes) en **UDP `5099`** al iniciar, cada **30 segundos**, y beacon `"status": "offline"` al cerrar. Timeout de inactividad de **90 segundos**.
   - Escaneo HTTP de respaldo en la subred `/24` sobre puertos **`5001–5020`** (`GET /api/status`, timeout 500 ms, máximo 64 conexiones en paralelo, cooldown automático de 5 minutos).
   - Directorio persistente en SQLite (`TrustedPeers`) con política **TOFU (Trust On First Use)**: confirmación explícita de huella SHA-256 en UI y bloqueo inmediato (`403 E-CERT-UNTRUSTED`) si un nodo fijado cambia su certificado sin reconfirmación.

3. **Estructura Estricta `.ZIP` v2.0 y Anti-ZIP-Bomb (`Network/PacketZipService.cs`):**
   - Exactamente **3 archivos planos en raíz**:
     - `package`: `datos.enc`, `certificado.pem`, `manifest.json` (`<NODEID>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8_MAYUS>.zip`).
     - `result`: `resultado.enc`, `certificado.pem`, `manifest.json` (`RES_<NODEID>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8_MAYUS>.zip`).
   - Rechazo estricto de subcarpetas, rutas relativas, archivos extra (`400 E-ZIP-STRUCTURE`), exceso de 50 MB comprimidos (`413 E-SIZE`), > 200 MB descomprimidos o razón > 100:1 (`400 E-ZIP-BOMB`).
   - Soporte `multipart` (`part-01.bin`..`part-64.bin`) y reenvío con `RepackageForForwarding` (Sección 9.6).

4. **Manifiesto v2.0, Firma Canónica de 11 Campos y Anti-Replay (`Core/Contracts/PacketManifest.cs`, `Network/ApiHostService.cs`):**
   - Hash canónico `publicParametersSha256` ordenando llaves con `StringComparer.Ordinal` (`llave=valor` unidos con `\n`, hex minúsculas).
   - Firma RSA-PSS-SHA256 sobre la cadena única de 11 campos:
     `version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256`
   - Protección Anti-Replay persistente en SQLite (`SeenPackets`, `409 E-REPLAY`).

5. **21 Algoritmos Oficiales en Local + Dueño Oficial de `AESGCM` (#1) y `DES` (#2):**
   - Los 21 algoritmos de `Security/CryptoCatalog.cs` operan al 100% en modo local en el Dashboard, mientras `EQ01` anuncia la propiedad oficial de `AESGCM` y `DES` en la red v2.0.

---

## Endpoints REST v2.0 (`:5001`)

- `GET /api/status` — Estado v2.0 del nodo (`EQ01`), algoritmos propios y huella SHA-256 del certificado.
- `GET /api/certificate` — Certificado público X.509 en formato PEM y metadatos de vigencia.
- `GET /api/algorithms` — Catálogo de los 21 algoritmos oficiales y su nodo dueño (`EQ01`–`EQ08`).
- `POST /api/requests/receive` — Recepción y validación estricta de paquetes `.zip` (`packetType = "package"`).
- `POST /api/results/receive` — Recepción y validación estricta de paquetes de resultado (`packetType = "result"`).

---

## Ejecución

```bash
dotnet build ModuloCrypto.sln
dotnet run --project ModuloCrypto.csproj
```

Para pruebas multi-instancia en la misma máquina (ej. simular `EQ02` en `:5002`):
```bash
dotnet run --project ModuloCrypto.csproj -- --team 2 --port 5002
```

Para ejecutar la suite de autopruebas del estándar v2.0:
```bash
dotnet bin/Debug/net10.0-windows/ModuloCrypto.dll --selftest
```

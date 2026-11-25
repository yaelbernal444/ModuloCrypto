# ModuloCrypto — Nodo Criptográfico Distribuido (.NET 10)

**ModuloCrypto** es un nodo de escritorio y servidor API REST embebido diseñado en **C# (.NET 10)** para operar como **`NODO-01`** dentro de una **red distribuida de 8 nodos** con enrutamiento tipo Tor e intercambio bidireccional de paquetes `.zip` firmados con certificados **X.509** (compatible tanto con nodos `ModuloCrypto` como con `CentroCiberseguridad.Web`).

---

## Arquitectura del Proyecto

El proyecto utiliza `<Project Sdk="Microsoft.NET.Sdk.Web">` con `<UseWindowsForms>true</UseWindowsForms>` para unificar:
- **Interfaz de Escritorio Holográfica (WinForms + GDI+ 60 FPS)** en pantalla completa (`Maximized`) con estética *Dark Violet Glassmorphism*.
- **Servidor ASP.NET Core Minimal API Embebido** escuchando en `http://0.0.0.0:5000` (o puerto configurable con `--port <puerto>`).
- **Persistencia Local en SQLite (`ModuloCrypto.db`)** mediante Entity Framework Core (`EnsureCreated()`) con contraseñas protegidas mediante **PBKDF2-SHA256 + Salt aleatorio**.

```text
ModuloCrypto/
├── ModuloCrypto.sln
├── ModuloCrypto.csproj
├── Program.cs
├── Core/
│   ├── Contracts/PacketManifest.cs     # Contrato JSON híbrido de manifest.json y respuestas REST
│   ├── Data/AppDbContext.cs            # EF Core + SQLite (Usuarios, RegistrosCifrados, SolicitudesEntrantes)
│   ├── Models/                         # Entidades SQLite y modelo PeerNode (8 nodos)
│   └── Services/                       # AuthService (PBKDF2-SHA256) y NodeRuntimeState
├── Security/
│   ├── ICryptoStrategy.cs              # Patrón Strategy para algoritmos criptográficos
│   ├── CryptoCatalog.cs                # Registro exclusivo de los 21 códigos oficiales
│   └── Strategies/                     # Implementaciones de los 21 algoritmos estándar
├── Network/
│   ├── ApiHostService.cs               # Minimal API dual embebida (/api/health, /api/status, /api/packets/receive, /api/requests/receive)
│   ├── NodeCertificateService.cs       # Certificado X.509 RSA-2048 protegido con Windows DPAPI
│   ├── PacketZipService.cs             # Empaquetado/lectura .zip híbrido (manifest.json, datos.enc, payload.bin, certificado.pem, root_cert.cer)
│   └── NodeNetworkClient.cs            # Cliente HTTP dual y escáner de subred LAN y puertos localhost
└── UI/
    ├── Theme/HologramTheme.cs          # Paleta oficial (#0B0914, #151226, #6C5CE7, #00D2FF, #A29BFE)
    ├── Controls/                       # GlassPanel, NeonButton, SidebarNavButton, StatusPill, HologramLockControl
    └── Forms/                          # FormLogin, FormRegisterModal, FormDashboard y vistas integradas
```

---

## Catálogo Oficial de los 21 Algoritmos (`Security/CryptoCatalog.cs`)

| # | Código Oficial | Nombre / Descripción |
|---|---|---|
| 1 | `AESGCM` | AES-256-GCM |
| 2 | `DES` | DES 56-bit |
| 3 | `TRIPLEDES` | Triple DES / 3DES |
| 4 | `CHACHA20` | ChaCha20-Poly1305 |
| 5 | `RSA` | RSA-OAEP / RSA-PSS |
| 6 | `ECC` | ECDH / ECDSA |
| 7 | `DIFFIEHELLMAN` | Diffie-Hellman |
| 8 | `CAESAR` | Cifrado César |
| 9 | `VIGENERE` | Cifrado Vigenère |
| 10 | `XORASM` | XOR en Registro |
| 11 | `LSBSTEGO` | Esteganografía LSB en PNG/BMP |
| 12 | `EUCLIDESAFFINE` | Euclides Extendido / Afín |
| 13 | `MILLERRABIN` | Miller-Rabin Modular |
| 14 | `FISHERYATES` | Permutación Fisher-Yates |
| 15 | `HASHSHA` | SHA-256 / SHA-512 |
| 16 | `HMACSHA256` | HMAC-SHA256 |
| 17 | `DIGITALSIG` | Firma Digital RSA-PSS |
| 18 | `QUANTUMPQC` | Simulación QKD BB84 / LWE |
| 19 | `DFTSPECTRAL` | Transformada Discreta de Fourier |
| 20 | `LAGRANGESHAMIR` | Umbral Shamir GF(256) |
| 21 | `LORENZSZ40` | Cifrado Lorenz SZ40/42 |

---

## Endpoints REST de la API Embebida (`:5000`)

- `GET /api/health` y `GET /api/status` — Estado del nodo (`NODO-01`), protocolo y huella SHA-256 del certificado X.509.
- `GET /api/algorithms` — Catálogo JSON de los 21 algoritmos oficiales.
- `POST /api/packets/receive` y `POST /api/requests/receive` — Recepción dual de paquetes `.zip`, validación de `manifest.json` y firma X.509 (`RSA-PSS-SHA256` / `PKCS#1`), y registro en `SolicitudesEntrantes`.
- `GET /api/crypto/decrypt/{packetId}` — Entrega de llave para peticiones de descifrado remoto.

---

## Ejecución Rápida y Seguridad

Requisitos: **Windows 10/11** y **.NET 10 SDK**.

```bash
dotnet build ModuloCrypto.sln
dotnet run --project ModuloCrypto.csproj
```

Para ejecutar en un puerto alternativo (ej. pruebas locales multi-nodo):
```bash
dotnet run --project ModuloCrypto.csproj -- --port 5002
```

**Primer Inicio (Sin Credenciales Precargadas):**
Por seguridad del repositorio público, la base de datos `ModuloCrypto.db` inicia sin usuarios ni contraseñas preconfiguradas. Al abrir la aplicación por primera vez, haz clic en **`Registrar Nuevo Integrante`** para crear tu cuenta de operador con tu **Nombre Completo**, **Usuario** y **Contraseña** (almacenada con **PBKDF2-SHA256** y salt aleatorio).

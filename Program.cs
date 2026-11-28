using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using ModuloCrypto.Network.V1;
using ModuloCrypto.Network.V2;
using ModuloCrypto.Security;
using ModuloCrypto.Security.Strategies;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Forms;
using ModuloCrypto.UI.Theme;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace ModuloCrypto;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var (teamNumber, explicitPort, cliVersion) = ParseCliArgs(args);
        NetworkAddressService.InitializeMonitoring();
        NodeRuntimeState.ConfigureForMode(cliVersion, teamNumber, explicitPort);

        if (args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
            return RunDualSelfTest().GetAwaiter().GetResult();

        ApplicationConfiguration.Initialize();

        // 1. Inicializar SQLite (ModuloCrypto.db) con WAL, auto-migración idempotente y verificación real TestConnection
        try
        {
            AppDbContext.InitializeDatabase();
            NodeRuntimeState.SqliteConnected = AppDbContext.TestConnection(out var dbDiag);
            NodeRuntimeState.SqliteDiagnostic = dbDiag;
        }
        catch (Exception ex)
        {
            NodeRuntimeState.SqliteConnected = false;
            NodeRuntimeState.SqliteDiagnostic = ex.Message;
            HologramDialog.ShowError(
                null,
                $"Error al inicializar la base de datos SQLite:\n{ex.Message}",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}");
        }

        // 2. Ciclo de vida diferido: Mostrar Login primero y levantar el servidor V1 o V2 elegido por el operador
        ProtocolVersionMode currentVersion = cliVersion;
        int currentTeam = teamNumber;

        bool keepRunning = true;
        try
        {
            while (keepRunning)
            {
                ProtocolVersionMode chosenVersion;
                int chosenTeam;
                Usuario authenticatedUser;

                using (var loginForm = new FormLogin(currentVersion, currentTeam))
                {
                    if (loginForm.ShowDialog() != DialogResult.OK || loginForm.AuthenticatedUser == null)
                        break;

                    authenticatedUser = loginForm.AuthenticatedUser;
                    chosenVersion = loginForm.SelectedProtocolVersion;
                    chosenTeam = loginForm.SelectedTeamNumber;
                }

                currentVersion = chosenVersion;
                currentTeam = chosenTeam;

                // Configurar identidad, puerto y directorio de pares según la versión seleccionada en el Login
                NodeRuntimeState.ConfigureForMode(chosenVersion, chosenTeam, explicitPort);
                NetworkAddressService.RefreshRuntimePrimaryEndpoint();

                INodeProtocolRuntime runtime = chosenVersion == ProtocolVersionMode.V2
                    ? new V2ProtocolRuntime()
                    : new V1ProtocolRuntime();

                NodeRuntimeState.ActiveRuntime = runtime;

                try
                {
                    runtime.StartAsync(NodeRuntimeState.ApiPort).GetAwaiter().GetResult();

                    using var dashboard = new FormDashboard(authenticatedUser, runtime);
                    Application.Run(dashboard);
                    keepRunning = dashboard.SignOutRequested;
                }
                finally
                {
                    // Detener y liberar completamente Kestrel y el socket UDP 5099 al cerrar sesión o salir
                    runtime.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    NodeRuntimeState.ActiveRuntime = null;
                }
            }
        }
        finally
        {
            try
            {
                AppDbContext.CheckpointWalTruncate();
            }
            catch { }
        }

        return 0;
    }

    private static (int TeamNumber, int? ExplicitPort, ProtocolVersionMode Version) ParseCliArgs(string[] args)
    {
        int team = 1;
        int? port = null;
        ProtocolVersionMode ver = ProtocolVersionMode.V2;

        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--team", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(args[i + 1], out int t) && t is >= 1 and <= 99)
            {
                team = t;
            }
            else if (args[i].Equals("--port", StringComparison.OrdinalIgnoreCase) &&
                     int.TryParse(args[i + 1], out int p) && p is > 0 and < 65536)
            {
                port = p;
            }
            else if (args[i].Equals("--protocol", StringComparison.OrdinalIgnoreCase) ||
                     args[i].Equals("--version-mode", StringComparison.OrdinalIgnoreCase))
            {
                if (args[i + 1].Contains('1'))
                    ver = ProtocolVersionMode.V1;
                else if (args[i + 1].Contains('2'))
                    ver = ProtocolVersionMode.V2;
            }
        }

        return (team, port, ver);
    }

    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<int> RunDualSelfTest()
    {
        string tempDbPath = Path.Combine(Path.GetTempPath(), $"ModuloCrypto_DualSelfTest_{Guid.NewGuid():N}.db");
        var tempFiles = new List<string?> { tempDbPath, tempDbPath + "-shm", tempDbPath + "-wal" };

        try
        {
            // =========================================================================
            // BLOQUE COMÚN: SQLite WAL + Migración Idempotente + PBKDF2 + IPv4 + 21 Algs
            // =========================================================================
            AppDbContext.InitializeDatabase(tempDbPath);
            if (!AppDbContext.TestConnection(out var sqliteDiag, tempDbPath) ||
                !sqliteDiag.Contains("WAL", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception($"Falló TestConnection SQLite WAL: {sqliteDiag}");
            }

            using (var checkDb = new AppDbContext(tempDbPath))
            {
                if (checkDb.Usuarios.Count() != 0)
                    throw new Exception("La BD SQLite nueva no inició vacía.");
            }

            var reg = AuthService.Register("Operador Dual", "dual_op", "ClaveSegura!2026", "EQ01", "Operador EQ01", tempDbPath);
            if (!reg.Success || reg.User == null || !reg.User.PasswordHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
                throw new Exception("Fallo en registro PBKDF2-SHA256.");

            var authOk = AuthService.Authenticate("dual_op", "ClaveSegura!2026", tempDbPath)
                ?? throw new Exception("Fallo en autenticación PBKDF2-SHA256.");

            var primaryEp = NetworkAddressService.GetPrimaryIpv4();
            if (string.IsNullOrWhiteSpace(primaryEp.Ipv4Address) || string.IsNullOrWhiteSpace(primaryEp.BroadcastAddress))
                throw new Exception("NetworkAddressService no devolvió un endpoint IPv4 válido.");

            byte[] sample = Encoding.UTF8.GetBytes("ModuloCrypto-Arquitectura-Dual-v1-v2-Payload-2026!");
            int passedAlgorithms = 0;
            foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            {
                var strat = CryptoCatalog.GetStrategy(alg.Code);
                var enc = strat.Encrypt(sample, "clave-prueba");
                var dec = strat.Decrypt(enc.OutputBytes, enc.SecretKeyBase64, enc.PublicParametersJson);
                if (alg.IsReversible && !sample.SequenceEqual(dec.OutputBytes))
                    throw new Exception($"Round-trip local falló para {alg.Code}");
                passedAlgorithms++;
            }

            // =========================================================================
            // BLOQUE VERSIÓN 1.0: V1ProtocolRuntime + ZIP 5 archivos + Recepción + Llave Remota
            // =========================================================================
            int v1Port = GetFreeTcpPort();
            NodeRuntimeState.ConfigureForMode(ProtocolVersionMode.V1, teamNumber: 1, explicitPort: v1Port);
            if (NodeRuntimeState.CurrentNodeId != "NODO-01" || NodeRuntimeState.ApiPort != v1Port)
                throw new Exception($"Configuración V1 inválida: {NodeRuntimeState.CurrentNodeId}:{NodeRuntimeState.ApiPort}");

            await using (var v1Runtime = new V1ProtocolRuntime())
            {
                bool v1Started = await v1Runtime.StartAsync(v1Port);
                if (!v1Started || !v1Runtime.IsApiOnline)
                    throw new Exception($"No pudo iniciar V1ProtocolRuntime en puerto {v1Port}: {v1Runtime.LastStartupError}");

                var aesV1 = CryptoCatalog.GetStrategy("AESGCM").Encrypt(sample, "clave-v1");
                var recV1 = new RegistroCifrado
                {
                    UsuarioId = 0,
                    PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant(),
                    NombreArchivo = "mensaje_v1.txt",
                    Extension = ".txt",
                    BytesCifrados = Convert.ToBase64String(aesV1.OutputBytes),
                    AlgoritmoCodigo = "AESGCM",
                    ParametrosPublicosJson = aesV1.PublicParametersJson,
                    LlaveSecretaBase64 = aesV1.SecretKeyBase64,
                    LinkDescifradoRemoto = $"http://127.0.0.1:{v1Port}/api/crypto/decrypt/",
                    NodoRaiz = "NODO-01",
                    RutaSaltosJson = "[\"NODO-01\"]",
                    Origen = "Local"
                };
                recV1.LinkDescifradoRemoto += recV1.PacketId;

                // Guardar registro en la BD principal para probar GET /api/crypto/decrypt/{packetId}
                using (var mainDb = new AppDbContext())
                {
                    var tempUser = mainDb.Usuarios.FirstOrDefault();
                    if (tempUser == null)
                    {
                        var rMain = AuthService.Register("Selftest V1", $"st_v1_{Guid.NewGuid():N}"[..14], "Pass123!");
                        tempUser = rMain.User!;
                    }
                    recV1.UsuarioId = tempUser.Id;
                    mainDb.RegistrosCifrados.Add(recV1);
                    mainDb.SaveChanges();
                }

                string v1ZipPath = V1PacketZipService.CreatePacketZip(recV1, aesV1.OutputBytes, new List<string> { "NODO-01" });
                tempFiles.Add(v1ZipPath);

                using (var zV1 = ZipFile.OpenRead(v1ZipPath))
                {
                    if (zV1.Entries.Count != 5 ||
                        zV1.GetEntry("manifest.json") == null ||
                        zV1.GetEntry("datos.enc") == null ||
                        zV1.GetEntry("payload.bin") == null ||
                        zV1.GetEntry("certificado.pem") == null ||
                        zV1.GetEntry("root_cert.cer") == null)
                    {
                        throw new Exception($"El paquete V1 no contiene los 5 archivos híbridos esperados (tiene {zV1.Entries.Count}).");
                    }
                }

                var v1Peer = new PeerNode
                {
                    NodeId = "NODO-01",
                    IpAddress = "127.0.0.1",
                    Port = v1Port,
                    ProtocolType = "ModuloCrypto v1.0"
                };

                var (pingV1Ok, _, _) = await V1NetworkClient.PingNodeAsync(v1Peer);
                if (!pingV1Ok)
                    throw new Exception("Falló V1NetworkClient.PingNodeAsync contra V1ProtocolRuntime.");

                // Probar recepción en /api/packets/receive y /api/requests/receive
                var sendV1Native = await V1NetworkClient.SendZipPacketAsync(v1Peer, v1ZipPath, recV1.PacketId);
                if (!sendV1Native.Success)
                    throw new Exception($"Falló envío V1 (/api/packets/receive): {sendV1Native.Message}");

                v1Peer.ProtocolType = "CentroCiberseguridad v1";
                var sendV1Centro = await V1NetworkClient.SendZipPacketAsync(v1Peer, v1ZipPath, recV1.PacketId);
                if (!sendV1Centro.Success)
                    throw new Exception($"Falló envío V1 (/api/requests/receive): {sendV1Centro.Message}");

                // Probar descarga de llave remota GET /api/crypto/decrypt/{packetId}
                var remoteKeyRes = await V1NetworkClient.RequestRemoteKeyAsync(recV1.LinkDescifradoRemoto);
                if (!remoteKeyRes.Success || remoteKeyRes.LlaveSecretaBase64 != recV1.LlaveSecretaBase64)
                    throw new Exception($"Falló descarga de llave remota V1: {remoteKeyRes.Message}");
            }

            // =========================================================================
            // BLOQUE VERSIÓN 2.0: V2ProtocolRuntime (EQ01) + CC-ENV-1 + 3-File ZIP + Forward/Inverse + 14 Validaciones
            // =========================================================================
            int v2Port = GetFreeTcpPort();
            NodeRuntimeState.ConfigureForMode(ProtocolVersionMode.V2, teamNumber: 1, explicitPort: v2Port);
            if (NodeRuntimeState.CurrentNodeId != "EQ01" || NodeRuntimeState.ApiPort != v2Port)
                throw new Exception($"Configuración V2 inválida: {NodeRuntimeState.CurrentNodeId}:{NodeRuntimeState.ApiPort}");

            var certV2 = V2CertificateService.Initialize(forceRegenerate: true);
            if (!certV2.Subject.Contains("CN=EQ01", StringComparison.OrdinalIgnoreCase) ||
                !certV2.Subject.Contains("OU=Equipo 01", StringComparison.OrdinalIgnoreCase) ||
                !certV2.Subject.Contains("O=Centro de Ciberseguridad", StringComparison.OrdinalIgnoreCase) ||
                !certV2.Subject.Contains("C=MX", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception($"Subject X.509 v2.0 inválido: {certV2.Subject}");
            }

            string thumbV2 = V2CertificateService.GetThumbprintSha256Hex();
            if (!Regex.IsMatch(thumbV2, "^[0-9A-F]{64}$"))
                throw new Exception($"Huella SHA-256 v2.0 inválida: {thumbV2}");

            // Sobre híbrido CC-ENV-1 (verificación estricta de tamaños en bytes + negativa E-ENV-RECIPIENT y E-ENV-DECRYPT)
            byte[] secretForEnv = RandomNumberGenerator.GetBytes(32);
            string envAad = Guid.NewGuid().ToString("D").ToLowerInvariant();
            var sealedEnv = V2EnvelopeService.Seal(secretForEnv, certV2, "EQ01", envAad);

            if (Convert.FromBase64String(sealedEnv.WrappedKeyBase64).Length != 256 ||
                Convert.FromBase64String(sealedEnv.NonceBase64).Length != 12 ||
                Convert.FromBase64String(sealedEnv.TagBase64).Length != 16)
            {
                throw new Exception("CC-ENV-1 no cumplió los tamaños exactos (wrappedKey=256B, nonce=12B, tag=16B).");
            }

            byte[] openedSecret = V2EnvelopeService.Open(sealedEnv, envAad, certV2);
            if (!secretForEnv.SequenceEqual(openedSecret))
                throw new Exception("Falló round-trip del sobre híbrido CC-ENV-1.");

            var wrongRecipientEnv = new CcHybridEnvelope
            {
                Envelope = "CC-ENV-1",
                RecipientNode = "EQ02",
                RecipientThumbprintSha256 = new string('F', 64),
                WrappedKeyBase64 = sealedEnv.WrappedKeyBase64,
                NonceBase64 = sealedEnv.NonceBase64,
                CiphertextBase64 = sealedEnv.CiphertextBase64,
                TagBase64 = sealedEnv.TagBase64
            };
            ExpectValidationException(() => V2EnvelopeService.Open(wrongRecipientEnv, envAad, certV2), "E-ENV-RECIPIENT", 401);

            var badTagEnv = new CcHybridEnvelope
            {
                Envelope = "CC-ENV-1",
                RecipientNode = "EQ01",
                RecipientThumbprintSha256 = sealedEnv.RecipientThumbprintSha256,
                WrappedKeyBase64 = sealedEnv.WrappedKeyBase64,
                NonceBase64 = sealedEnv.NonceBase64,
                CiphertextBase64 = sealedEnv.CiphertextBase64,
                TagBase64 = Convert.ToBase64String(new byte[16])
            };
            ExpectValidationException(() => V2EnvelopeService.Open(badTagEnv, envAad, certV2), "E-ENV-DECRYPT", 401);

            await using (var v2Runtime = new V2ProtocolRuntime())
            {
                bool v2Started = await v2Runtime.StartAsync(v2Port);
                if (!v2Started || !v2Runtime.IsApiOnline)
                    throw new Exception($"No pudo iniciar V2ProtocolRuntime en puerto {v2Port}: {v2Runtime.LastStartupError}");

                var v2Peer = new PeerNode
                {
                    NodeId = "EQ01",
                    TeamNumber = 1,
                    IpAddress = "127.0.0.1",
                    Port = v2Port,
                    ProtocolType = "v2.0"
                };

                // 1. Validar GET /api/status y GET /api/certificate (application/x-pem-file)
                var (pingV2Ok, _, statusInfo) = await V2NetworkClient.PingNodeAsync(v2Peer);
                if (!pingV2Ok || statusInfo == null || statusInfo.ProtocolVersion != "2.0" || string.IsNullOrWhiteSpace(v2Peer.CertificatePem))
                    throw new Exception("Falló validación de /api/status o /api/certificate en V2ProtocolRuntime.");

                using (var httpCheck = new HttpClient())
                {
                    var certResp = await httpCheck.GetAsync($"http://127.0.0.1:{v2Port}/api/certificate");
                    string mediaType = certResp.Content.Headers.ContentType?.MediaType ?? "";
                    if (!certResp.IsSuccessStatusCode || !mediaType.Equals("application/x-pem-file", StringComparison.OrdinalIgnoreCase))
                        throw new Exception($"GET /api/certificate no devolvió application/x-pem-file (actual: {mediaType}).");

                    var algsResp = await httpCheck.GetAsync($"http://127.0.0.1:{v2Port}/api/algorithms");
                    string algsJson = await algsResp.Content.ReadAsStringAsync();
                    if (!algsResp.IsSuccessStatusCode || !algsJson.Contains("AESGCM") || !algsJson.Contains("DES"))
                        throw new Exception("GET /api/algorithms no devolvió los perfiles de AESGCM y DES para EQ01.");

                    var keyResp = await httpCheck.GetAsync($"http://127.0.0.1:{v2Port}/api/keys/default");
                    if (!keyResp.IsSuccessStatusCode)
                        throw new Exception("GET /api/keys/default falló.");
                }

                // 2. Validar Diagnóstico de Conectividad (ICMP + TCP + HTTP)
                var diagReport = await ConnectivityDiagnostics.RunFullDiagnosticAsync("127.0.0.1", v2Port, ProtocolVersionMode.V2);
                if (!diagReport.TcpPortOpen || !diagReport.HttpApiSuccess || diagReport.HasVersionMismatch)
                    throw new Exception($"Falló ConnectivityDiagnostics en v2.0: {diagReport.SummaryTitle}");

                // 3. Validar POST /api/crypto/forward y POST /api/crypto/inverse para AESGCM y DES (Emisión estricta Tabla 4.2 + resultEnvelope sin ciphertextBase64)
                foreach (string ownedAlg in new[] { "AESGCM", "DES" })
                {
                    var (fwdOk, fwdRes, fwdErr) = await V2NetworkClient.CallRemoteForwardAsync(
                        v2Peer,
                        ownedAlg,
                        sample,
                        "prueba_v2.txt",
                        ".txt",
                        keySizeBits: 256);

                    if (!fwdOk || fwdRes == null || fwdRes.SecretKeyEnvelope == null)
                        throw new Exception($"Falló POST /api/crypto/forward para {ownedAlg}: {fwdErr}");

                    if (!V2FormatValidators.IsValidKeyId(fwdRes.KeyRef.KeyId))
                        throw new Exception($"keyRef.keyId no cumple el formato estricto v2.0: {fwdRes.KeyRef.KeyId}");

                    if (ownedAlg == "AESGCM")
                    {
                        if (fwdRes.PublicParameters.Count != 3 ||
                            fwdRes.PublicParameters["keySizeBits"] != "256" ||
                            Convert.FromBase64String(fwdRes.PublicParameters["nonceBase64"]).Length != 12 ||
                            Convert.FromBase64String(fwdRes.PublicParameters["tagBase64"]).Length != 16)
                        {
                            throw new Exception("Emisión AESGCM de EQ01 no cumple estrictamente la Tabla 4.2.");
                        }
                    }
                    else if (ownedAlg == "DES")
                    {
                        if (fwdRes.PublicParameters.Count != 3 ||
                            fwdRes.PublicParameters["mode"] != "CBC" ||
                            fwdRes.PublicParameters["padding"] != "PKCS7" ||
                            Convert.FromBase64String(fwdRes.PublicParameters["ivBase64"]).Length != 8)
                        {
                            throw new Exception("Emisión DES de EQ01 no cumple estrictamente la Tabla 4.2.");
                        }
                    }

                    var openedFwdSecrets = V2EnvelopeService.OpenSecretsDictionary(
                        fwdRes.SecretKeyEnvelope,
                        fwdRes.RequestId,
                        fwdRes.PacketId);
                    byte[] rawKeyFromFwd = Convert.FromBase64String(openedFwdSecrets["key"]);

                    byte[] cipherFromForward = Convert.FromBase64String(fwdRes.CiphertextBase64);

                    var (invOk, plainFromInverse, resZip, invErr) = await V2NetworkClient.CallRemoteInverseAsync(
                        v2Peer,
                        ownedAlg,
                        fwdRes.PacketId,
                        cipherFromForward,
                        fwdRes.PublicParameters,
                        keyId: fwdRes.KeyRef.KeyId,
                        rawSecretBytesToSeal: rawKeyFromFwd);

                    if (!invOk || plainFromInverse == null || resZip == null || !sample.SequenceEqual(plainFromInverse))
                        throw new Exception($"Falló POST /api/crypto/inverse para {ownedAlg}: {invErr}");

                    if (resZip.Manifest.ResultEnvelope == null || resZip.Manifest.ResultEnvelope.CiphertextBase64 != null)
                        throw new Exception("El resultEnvelope del paquete result no debe incluir ciphertextBase64.");

                    if (Convert.FromBase64String(resZip.Manifest.ManifestSignatureBase64).Length != 256)
                        throw new Exception("La firma RSA-PSS-SHA256 del manifiesto no mide 256 bytes.");
                }

                // 4. Prueba obligatoria de paquete estilo Equipo 6 (EQ06):
                // datos.enc de 6 bytes, publicParameters con "ivBase64" (12 B), "tagBase64" (16 B), "opt.keySizeBits": "256", "mode": "v3-local"
                // probado tanto con AAD = packetId como con AAD = null, y pasando la llave en Base64, Hex (64 chars) y passphrase UTF-8
                byte[] eq06Plain6Bytes = Encoding.UTF8.GetBytes("EQ06OK"); // 6 bytes exactos
                string eq06Passphrase = "Passphrase-Equipo06-2026!";
                byte[] eq06DerivedKey32 = SHA256.HashData(Encoding.UTF8.GetBytes(eq06Passphrase));
                string eq06KeyBase64 = Convert.ToBase64String(eq06DerivedKey32);
                string eq06KeyHex64 = Convert.ToHexString(eq06DerivedKey32).ToLowerInvariant();

                foreach (bool useAadPacketId in new[] { true, false })
                {
                    string eq06PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant();
                    byte[] eq06Iv12 = RandomNumberGenerator.GetBytes(12);
                    byte[] eq06Cipher6 = new byte[6];
                    byte[] eq06Tag16 = new byte[16];

                    using (var aesEq06 = new AesGcm(eq06DerivedKey32, 16))
                    {
                        if (useAadPacketId)
                            aesEq06.Encrypt(eq06Iv12, eq06Plain6Bytes, eq06Cipher6, eq06Tag16, Encoding.UTF8.GetBytes(eq06PacketId));
                        else
                            aesEq06.Encrypt(eq06Iv12, eq06Plain6Bytes, eq06Cipher6, eq06Tag16);
                    }

                    var eq06PubParams = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["ivBase64"] = Convert.ToBase64String(eq06Iv12),
                        ["tagBase64"] = Convert.ToBase64String(eq06Tag16),
                        ["opt.keySizeBits"] = "256",
                        ["mode"] = "v3-local"
                    };

                    var eq06Rec = new RegistroCifrado
                    {
                        PacketId = eq06PacketId,
                        AlgoritmoCodigo = "AESGCM",
                        NombreArchivo = "corto_eq06.txt",
                        Extension = ".txt",
                        NodoRaiz = "EQ01"
                    };

                    string eq06ZipPath = V2PacketZipService.CreatePacketZip(
                        eq06Rec,
                        eq06Cipher6,
                        packetType: "package",
                        operation: "forward",
                        explicitPublicParameters: eq06PubParams);
                    tempFiles.Add(eq06ZipPath);

                    var parsedEq06 = V2PacketZipService.ReadPacketZip(eq06ZipPath, enforceStrictSignature: true, validateTimestamp: true);
                    if (parsedEq06.PayloadBytes.Length != 6 ||
                        parsedEq06.Manifest.PublicParameters.Count != 4 ||
                        parsedEq06.Manifest.PublicParameters.ContainsKey("originalFileName") ||
                        parsedEq06.Manifest.PublicParameters.ContainsKey("originalExtension"))
                    {
                        throw new Exception("El paquete estilo EQ06 fue contaminado con campos extra en publicParameters.");
                    }

                    string eq06PubJson = JsonSerializer.Serialize(parsedEq06.Manifest.PublicParameters);
                    var eq06Ctx = new DecryptionContext(PacketId: eq06PacketId, OriginalFileName: "corto_eq06.txt", OriginalExtension: ".txt");
                    var aesStrat = CryptoCatalog.GetStrategy("AESGCM");

                    foreach (string keyFormat in new[] { eq06KeyBase64, eq06KeyHex64, eq06Passphrase })
                    {
                        var decEq06 = aesStrat.Decrypt(parsedEq06.PayloadBytes, keyFormat, eq06PubJson, eq06Ctx);
                        if (!eq06Plain6Bytes.SequenceEqual(decEq06.OutputBytes))
                            throw new Exception($"Falló descifrado tolerante estilo EQ06 (useAad={useAadPacketId}, formato llave={keyFormat[..8]}...).");
                    }
                }

                // 5. Validar paquete .zip estricto de 3 archivos + Reenvío 9.6 + Pruebas Negativas de Conformidad (Anexo B)
                string strictPkgId = Guid.NewGuid().ToString("D").ToLowerInvariant();
                var aesRes = CryptoCatalog.GetStrategy("AESGCM").Encrypt(sample, null, strictPkgId);
                var recV2 = new RegistroCifrado
                {
                    UsuarioId = authOk.Id,
                    PacketId = strictPkgId,
                    NombreArchivo = "mensaje_v2.txt",
                    Extension = ".txt",
                    BytesCifrados = Convert.ToBase64String(aesRes.OutputBytes),
                    AlgoritmoCodigo = "AESGCM",
                    ParametrosPublicosJson = aesRes.PublicParametersJson,
                    LlaveSecretaBase64 = aesRes.SecretKeyBase64,
                    LinkDescifradoRemoto = V2FormatValidators.BuildKeyId("EQ01", strictPkgId),
                    NodoRaiz = "EQ01",
                    RutaSaltosJson = "[\"EQ01\"]",
                    Origen = "Local"
                };

                string packageZipPath = V2PacketZipService.CreatePacketZip(recV2, aesRes.OutputBytes, packetType: "package");
                tempFiles.Add(packageZipPath);

                using (var zPkg = ZipFile.OpenRead(packageZipPath))
                {
                    if (zPkg.Entries.Count != 3 ||
                        zPkg.GetEntry("datos.enc") == null ||
                        zPkg.GetEntry("certificado.pem") == null ||
                        zPkg.GetEntry("manifest.json") == null)
                    {
                        throw new Exception("El paquete package v2.0 no contiene exactamente los 3 archivos planos requeridos.");
                    }
                }

                string forwardedZipPath = V2PacketZipService.RepackageForForwarding(packageZipPath);
                tempFiles.Add(forwardedZipPath);
                var parsedFwd = V2PacketZipService.ReadPacketZip(forwardedZipPath, enforceStrictSignature: true);
                if (!parsedFwd.SignatureValid || parsedFwd.Manifest.ProducerNode != "EQ01" || parsedFwd.Manifest.PublicParameters.Count != 3)
                    throw new Exception("Falló RepackageForForwarding (Sección 9.6).");

                // Prueba negativa 1: 400 E-ZIP-STRUCTURE (4 archivos)
                string zip4Files = Path.Combine(Path.GetTempPath(), $"v2_neg_4files_{Guid.NewGuid():N}.zip");
                tempFiles.Add(zip4Files);
                File.Copy(packageZipPath, zip4Files, true);
                using (var z4 = ZipFile.Open(zip4Files, ZipArchiveMode.Update))
                {
                    using var sw = new StreamWriter(z4.CreateEntry("extra.txt").Open());
                    sw.Write("prohibido");
                }
                ExpectValidationException(() => V2PacketZipService.ReadPacketZip(zip4Files), "E-ZIP-STRUCTURE", 400);

                // Prueba negativa 2: 422 E-HASH (datos.enc alterado)
                string zipBadHash = Path.Combine(Path.GetTempPath(), $"v2_neg_hash_{Guid.NewGuid():N}.zip");
                tempFiles.Add(zipBadHash);
                File.Copy(packageZipPath, zipBadHash, true);
                using (var zh = ZipFile.Open(zipBadHash, ZipArchiveMode.Update))
                {
                    zh.GetEntry("datos.enc")!.Delete();
                    using var ds = zh.CreateEntry("datos.enc").Open();
                    ds.Write(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
                }
                ExpectValidationException(() => V2PacketZipService.ReadPacketZip(zipBadHash), "E-HASH", 422);

                // Prueba negativa 3: 422 E-PARAMS-HASH (publicParameters alterado sin actualizar publicParametersSha256)
                string zipBadParams = CreateTamperedManifestZip(packageZipPath, m =>
                {
                    m.PublicParameters["tampered"] = "true";
                });
                tempFiles.Add(zipBadParams);
                ExpectValidationException(() => V2PacketZipService.ReadPacketZip(zipBadParams), "E-PARAMS-HASH", 422);

                // Prueba negativa 4: 422 E-SIGNATURE (firma RSA-PSS alterada)
                string zipBadSig = CreateTamperedManifestZip(packageZipPath, m =>
                {
                    m.ManifestSignatureBase64 = Convert.ToBase64String(new byte[256]);
                });
                tempFiles.Add(zipBadSig);
                ExpectValidationException(() => V2PacketZipService.ReadPacketZip(zipBadSig), "E-SIGNATURE", 422);

                // Prueba negativa 5: 422 E-TIMESTAMP (timestamp fuera de ±10 minutos, re-firmado con certificado válido)
                string zipOldTs = CreateTamperedManifestZip(packageZipPath, m =>
                {
                    m.TimestampUtc = DateTime.UtcNow.AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");
                    m.ManifestSignatureBase64 = V2CertificateService.SignDataPss(Encoding.UTF8.GetBytes(m.BuildCanonicalSigningString()));
                });
                tempFiles.Add(zipOldTs);
                ExpectValidationException(() => V2PacketZipService.ReadPacketZip(zipOldTs, validateTimestamp: true), "E-TIMESTAMP", 422);

                // Prueba negativa 6: 409 E-DUPLICATE (mismo packetId procesado 2 veces en SQLite SeenPackets -> 409)
                _ = V2PacketZipService.ReadPacketZip(packageZipPath, validateTimestamp: true, checkAndRecordReplay: true, customDbPath: tempDbPath);
                ExpectValidationException(
                    () => V2PacketZipService.ReadPacketZip(packageZipPath, validateTimestamp: true, checkAndRecordReplay: true, customDbPath: tempDbPath),
                    "E-DUPLICATE",
                    409);
            }

            // =========================================================================
            // BLOQUE 3: MIGRACIÓN DE BD ANTIGUA CON 4 SOLICITUDES PENDIENTES -> 5.ª SOLICITUD -> ACEPTACIÓN + CHECKPOINT WAL
            // =========================================================================
            string legacyDbPath = Path.Combine(Path.GetTempPath(), $"ModuloCrypto_Legacy4Pending_{Guid.NewGuid():N}.db");
            tempFiles.Add(legacyDbPath);
            tempFiles.Add(legacyDbPath + "-shm");
            tempFiles.Add(legacyDbPath + "-wal");

            // 1. Crear una base SQLite antigua (faltando columnas v2.0 y tablas nuevas) con 4 solicitudes en estado "Pendiente"
            using (var rawConn = new SqliteConnection(AppDbContext.BuildSqliteConnectionString(legacyDbPath)))
            {
                rawConn.Open();
                using var cmd = rawConn.CreateCommand();
                cmd.CommandText = @"
                    CREATE TABLE Usuarios (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        NombreUsuario TEXT NOT NULL UNIQUE,
                        PasswordHash TEXT NOT NULL DEFAULT ''
                    );
                    CREATE TABLE RegistrosCifrados (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UsuarioId INTEGER NOT NULL DEFAULT 0,
                        PacketId TEXT NOT NULL DEFAULT '',
                        NombreArchivo TEXT NOT NULL DEFAULT '',
                        BytesCifrados TEXT NOT NULL DEFAULT '',
                        AlgoritmoCodigo TEXT NOT NULL DEFAULT 'AESGCM'
                    );
                    CREATE TABLE SolicitudesEntrantes (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        PacketId TEXT NOT NULL DEFAULT '',
                        NodoOrigen TEXT NOT NULL DEFAULT '',
                        NombreZip TEXT NOT NULL DEFAULT '',
                        Estado TEXT NOT NULL DEFAULT 'Pendiente'
                    );
                    INSERT INTO Usuarios (NombreUsuario, PasswordHash) VALUES ('legacy_admin', 'PBKDF2$100000$AA==$AA==');
                    INSERT INTO SolicitudesEntrantes (PacketId, NodoOrigen, NombreZip, Estado) VALUES ('old-pkt-1', 'NODO-02', 'old1.zip', 'Pendiente');
                    INSERT INTO SolicitudesEntrantes (PacketId, NodoOrigen, NombreZip, Estado) VALUES ('old-pkt-2', 'NODO-03', 'old2.zip', 'Pendiente');
                    INSERT INTO SolicitudesEntrantes (PacketId, NodoOrigen, NombreZip, Estado) VALUES ('old-pkt-3', 'NODO-04', 'old3.zip', 'Pendiente');
                    INSERT INTO SolicitudesEntrantes (PacketId, NodoOrigen, NombreZip, Estado) VALUES ('old-pkt-4', 'NODO-05', 'old4.zip', 'Pendiente');
                ";
                cmd.ExecuteNonQuery();
            }

            // 2. Ejecutar AppDbContext.InitializeDatabase(legacyDbPath) para migrar todas las tablas y columnas faltantes
            AppDbContext.InitializeDatabase(legacyDbPath);

            // 3. Insertar una 5.ª solicitud con todos los campos v2.0 completos
            string fifthPacketId = Guid.NewGuid().ToString("D").ToLowerInvariant();
            int fifthSolicitudId;
            using (var migratedDb = new AppDbContext(legacyDbPath))
            {
                int initialPending = migratedDb.SolicitudesEntrantes.AsNoTracking().Count(s => s.Estado == "Pendiente");
                if (initialPending != 4)
                    throw new Exception($"Se esperaban 4 solicitudes pendientes iniciales tras migrar BD antigua, pero hay {initialPending}.");

                var fifthSol = new SolicitudEntrante
                {
                    PacketId = fifthPacketId,
                    NodoOrigen = "EQ06",
                    IpOrigen = "192.168.1.106",
                    NombreZip = $"EQ06_AESGCM_{DateTime.UtcNow:yyyyMMdd_HHmmss}_ABCD1234.zip",
                    AlgoritmoCodigo = "AESGCM",
                    FirmaX509Valida = true,
                    RutaZipTemporal = Path.Combine(AppDbContext.IncomingPacketsDirectory, "eq06_test.zip"),
                    Estado = "Pendiente",
                    FechaRecepcion = DateTime.Now
                };
                migratedDb.SolicitudesEntrantes.Add(fifthSol);
                await migratedDb.SaveChangesAsync();
                fifthSolicitudId = fifthSol.Id;
            }

            // 4. Verificar con nuevo AppDbContext (AsNoTracking) que ahora hay 5 pendientes, y aceptar la 5.ª solicitud insertando en RegistrosCifrados
            using (var acceptDb = new AppDbContext(legacyDbPath))
            {
                int pendingAfterInsert = acceptDb.SolicitudesEntrantes.AsNoTracking().Count(s => s.Estado == "Pendiente");
                if (pendingAfterInsert != 5)
                    throw new Exception($"Se esperaban 5 solicitudes pendientes tras insertar la 5.ª solicitud, pero hay {pendingAfterInsert}.");

                var solToAccept = acceptDb.SolicitudesEntrantes.Find(fifthSolicitudId)
                    ?? throw new Exception("No se encontró la 5.ª solicitud recién insertada.");

                var userEntity = acceptDb.Usuarios.First();
                solToAccept.Estado = "Aceptada";

                acceptDb.RegistrosCifrados.Add(new RegistroCifrado
                {
                    UsuarioId = userEntity.Id,
                    PacketId = fifthPacketId,
                    NombreArchivo = "prueba_eq06.txt",
                    Extension = ".txt",
                    BytesCifrados = Convert.ToBase64String(Encoding.UTF8.GetBytes("EQ06OK")),
                    AlgoritmoCodigo = "AESGCM",
                    ParametrosPublicosJson = "{\"keySizeBits\":\"256\"}",
                    LlaveSecretaBase64 = Convert.ToBase64String(new byte[32]),
                    LinkDescifradoRemoto = V2FormatValidators.BuildKeyId("EQ06", fifthPacketId),
                    NodoRaiz = "EQ06",
                    FirmaRaizBase64 = "SIG_OK",
                    RutaSaltosJson = "[\"EQ06\",\"EQ01\"]",
                    Origen = "Recibido",
                    FechaOperacion = DateTime.Now
                });

                await acceptDb.SaveChangesAsync();
            }

            // 5. Verificar con un nuevo AppDbContext fresco que el conteo de pendientes bajó de 5 a 4 y que el registro aparece en Consultas
            using (var verifyFreshDb = new AppDbContext(legacyDbPath))
            {
                int finalPending = verifyFreshDb.SolicitudesEntrantes.AsNoTracking().Count(s => s.Estado == "Pendiente");
                int acceptedCount = verifyFreshDb.SolicitudesEntrantes.AsNoTracking().Count(s => s.Estado == "Aceptada");
                var consultaRecord = verifyFreshDb.RegistrosCifrados.AsNoTracking().FirstOrDefault(r => r.PacketId == fifthPacketId);

                if (finalPending != 4 || acceptedCount != 1 || consultaRecord == null || consultaRecord.NodoRaiz != "EQ06")
                {
                    throw new Exception($"Fallo de verificación fresca en Solicitudes/Consultas: pending={finalPending}, accepted={acceptedCount}, recordFound={consultaRecord != null}");
                }
            }

            // 6. Ejecutar PRAGMA wal_checkpoint(TRUNCATE); sin error sobre ambas bases de prueba y la BD única consolidada
            AppDbContext.CheckpointWalTruncate(legacyDbPath);
            AppDbContext.CheckpointWalTruncate(tempDbPath);
            AppDbContext.CheckpointWalTruncate();

            // BLOQUE 4: INTEROPERABILIDAD ESTRICTA v2.0 (ADR 0012 / 0005 / 0006 / 0007 / NoCompression) + PARSEO DE LLAVES (21 ALGORITMOS)
            V2CertificateService.Initialize(forceRegenerate: true);
            using (var certAdr0012 = V2CertificateService.LoadCertificateFromPemOrBase64(V2CertificateService.ExportPublicCertPem()))
            {
                if (new DateTimeOffset(certAdr0012.NotBefore.ToUniversalTime()) > DateTimeOffset.UtcNow.AddMinutes(-9))
                    throw new Exception($"ADR 0012 falló: notBefore={certAdr0012.NotBefore:O} no tiene margen de -10 minutos.");
                if (!certAdr0012.Subject.StartsWith("CN=EQ01", StringComparison.Ordinal))
                    throw new Exception($"ADR 0012 falló: Subject '{certAdr0012.Subject}' no inicia con CN=EQ01.");
                var bcExt = certAdr0012.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
                if (bcExt == null || !bcExt.Critical)
                    throw new Exception("ADR 0012 falló: BasicConstraints no es crítico.");
            }

            // Verificar compresión store (NoCompression) para evitar E-ZIP-BOMB en payloads repetitivos
            byte[] compressiblePayload = Encoding.UTF8.GetBytes(new string('A', 4096));
            string storeZipPath = Path.Combine(Path.GetTempPath(), $"v2_store_test_{Guid.NewGuid():N}.zip");
            tempFiles.Add(storeZipPath);
            var storeDummyReg = new RegistroCifrado
            {
                PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant(),
                NombreArchivo = "store.txt",
                Extension = ".txt",
                AlgoritmoCodigo = "AESGCM",
                ParametrosPublicosJson = "{}",
                NodoRaiz = "EQ01"
            };
            V2PacketZipService.CreatePacketZip(
                storeDummyReg,
                compressiblePayload,
                packetType: "package",
                destinationPath: storeZipPath);
            using (var storeArch = ZipFile.OpenRead(storeZipPath))
            {
                var datosEntry = storeArch.GetEntry("datos.enc") ?? throw new Exception("Falta datos.enc en prueba NoCompression.");
                var pemEntry = storeArch.GetEntry("certificado.pem") ?? throw new Exception("Falta certificado.pem en prueba NoCompression.");
                if (datosEntry.CompressedLength != datosEntry.Length || pemEntry.CompressedLength != pemEntry.Length)
                    throw new Exception($"Fallo NoCompression: datos={datosEntry.CompressedLength}/{datosEntry.Length}, pem={pemEntry.CompressedLength}/{pemEntry.Length}.");
            }

            // Pruebas HTTP activas ADR 0005, ADR 0006 y ADR 0007 / Anexo A.2
            int interopPort = GetFreeTcpPort();
            NodeRuntimeState.ConfigureForMode(ProtocolVersionMode.V2, teamNumber: 1, explicitPort: interopPort);
            var cleanupPacketIds = new List<string>();
            await using (var interopRuntime = new V2ProtocolRuntime())
            {
                if (!await interopRuntime.StartAsync(interopPort))
                    throw new Exception($"No pudo iniciar interopRuntime en puerto {interopPort}: {interopRuntime.LastStartupError}");

                try
                {
                    string eq01Thumb = V2CertificateService.Thumbprint;
                    var eq01Peer = new PeerNode
                    {
                        NodeId = "EQ01",
                        TeamNumber = 1,
                        IpAddress = "127.0.0.1",
                        Port = interopPort,
                        CertThumbprint = eq01Thumb,
                        PinnedThumbprintSha256 = eq01Thumb,
                        CertificatePem = V2CertificateService.ExportPublicCertPem(),
                        IsConfirmed = true,
                        Status = "online"
                    };

                    // ADR 0007 / Anexo A.2: forward + inverse + validación estricta del paquete result
                    byte[] anexoPlain = Encoding.UTF8.GetBytes("ModuloCrypto Anexo A.2 Result Envelope Check");
                    var (fwdOk, fwdResp, fwdErr) = await V2NetworkClient.CallRemoteForwardAsync(
                        eq01Peer, "AESGCM", anexoPlain, "anexo.txt", ".txt");
                    if (!fwdOk || fwdResp == null)
                        throw new Exception($"CallRemoteForwardAsync falló en interop: {fwdErr}");
                    cleanupPacketIds.Add(fwdResp.PacketId);

                    byte[] fwdCipher = Convert.FromBase64String(fwdResp.CiphertextBase64);
                    var (invOk, invPlain, resultZip, invErr) = await V2NetworkClient.CallRemoteInverseAsync(
                        eq01Peer,
                        "AESGCM",
                        fwdResp.PacketId,
                        fwdCipher,
                        fwdResp.PublicParameters,
                        keyId: fwdResp.KeyRef.KeyId);
                    if (!invOk || invPlain == null || resultZip == null || !invPlain.SequenceEqual(anexoPlain))
                        throw new Exception($"CallRemoteInverseAsync falló en Anexo A.2: {invErr}");
                    if (resultZip.Manifest.PublicParameters.Count != 0 ||
                        resultZip.Manifest.PublicParametersSha256 != PacketManifest.EmptySha256Lower ||
                        resultZip.Manifest.KeyRef != null ||
                        resultZip.Manifest.ResultEnvelope == null)
                    {
                        throw new Exception("ADR 0007 falló: el paquete result no cumplió publicParameters={} / KeyRef=null / resultEnvelope.");
                    }
                    byte[] directOpenedRes = V2EnvelopeService.Open(
                        resultZip.Manifest.ResultEnvelope,
                        expectedAadContext: resultZip.Manifest.PacketId,
                        detachedCiphertext: resultZip.PayloadBytes);
                    if (!directOpenedRes.SequenceEqual(anexoPlain))
                        throw new Exception("Anexo A.2 falló: AAD = result.packetId no abrió resultado.enc.");

                    // Bloque 5: Flujo v3-local usando publicParameters["keyId"] sin secretos de usuario en /api/crypto/inverse
                    var v3PubParams = new Dictionary<string, string>(fwdResp.PublicParameters, StringComparer.Ordinal)
                    {
                        ["mode"] = "v3-local",
                        ["keyId"] = fwdResp.KeyRef.KeyId
                    };
                    var (v3Ok, v3Plain, v3ResZip, v3Err) = await V2NetworkClient.CallRemoteInverseAsync(
                        eq01Peer,
                        "AESGCM",
                        fwdResp.PacketId,
                        fwdCipher,
                        v3PubParams,
                        keyId: v3PubParams["keyId"]);
                    if (!v3Ok || v3Plain == null || !v3Plain.SequenceEqual(anexoPlain) || v3ResZip == null)
                        throw new Exception($"Compatibilidad v3-local con publicParameters['keyId'] falló: {v3Err}");

                    // ADR 0005: paquete .zip repetido y paquete .zip con timestamp > 15 min aceptados en /api/crypto/inverse con requestId distinto
                    string replayPkgZip = Path.Combine(Path.GetTempPath(), $"v2_adr0005_pkg_{Guid.NewGuid():N}.zip");
                    string expiredPkgZip = Path.Combine(Path.GetTempPath(), $"v2_adr0005_exp_{Guid.NewGuid():N}.zip");
                    tempFiles.Add(replayPkgZip);
                    tempFiles.Add(expiredPkgZip);

                    var replayReg = new RegistroCifrado
                    {
                        PacketId = fwdResp.PacketId,
                        NombreArchivo = "anexo.txt",
                        Extension = ".txt",
                        AlgoritmoCodigo = "AESGCM",
                        ParametrosPublicosJson = JsonSerializer.Serialize(fwdResp.PublicParameters),
                        LinkDescifradoRemoto = fwdResp.KeyRef.KeyId,
                        NodoRaiz = "EQ01"
                    };
                    V2PacketZipService.CreatePacketZip(
                        replayReg,
                        fwdCipher,
                        packetType: "package",
                        destinationPath: replayPkgZip,
                        explicitPublicParameters: fwdResp.PublicParameters,
                        explicitKeyRef: fwdResp.KeyRef,
                        useExplicitKeyRef: true);
                    byte[] replayPkgBytes = await File.ReadAllBytesAsync(replayPkgZip);

                    for (int attempt = 1; attempt <= 2; attempt++)
                    {
                        var (repOk, repPlain, _, repErr) = await V2NetworkClient.CallRemoteInverseAsync(
                            eq01Peer,
                            "AESGCM",
                            fwdResp.PacketId,
                            replayPkgBytes,
                            fwdResp.PublicParameters,
                            keyId: fwdResp.KeyRef.KeyId);
                        if (!repOk || repPlain == null || !repPlain.SequenceEqual(anexoPlain))
                            throw new Exception($"ADR 0005 replay intento #{attempt} falló: {repErr}");
                    }

                    // Construir .zip con timestamp > 30 min antiguo firmado válidamente
                    var parsedForExpire = V2PacketZipService.ReadPacketZip(replayPkgZip, enforceStrictSignature: false);
                    parsedForExpire.Manifest.TimestampUtc = DateTime.UtcNow.AddMinutes(-35).ToString("yyyy-MM-ddTHH:mm:ssZ");
                    parsedForExpire.Manifest.ManifestSignatureBase64 = V2CertificateService.SignDataPss(
                        Encoding.UTF8.GetBytes(parsedForExpire.Manifest.BuildCanonicalSigningString()));
                    using (var expArch = ZipFile.Open(expiredPkgZip, ZipArchiveMode.Create))
                    {
                        using (var ds = expArch.CreateEntry("datos.enc", CompressionLevel.NoCompression).Open())
                            ds.Write(parsedForExpire.PayloadBytes, 0, parsedForExpire.PayloadBytes.Length);
                        using (var swPem = new StreamWriter(expArch.CreateEntry("certificado.pem", CompressionLevel.NoCompression).Open(), new UTF8Encoding(false)))
                            swPem.Write(parsedForExpire.CertificatePem);
                        using (var swMan = new StreamWriter(expArch.CreateEntry("manifest.json", CompressionLevel.NoCompression).Open(), new UTF8Encoding(false)))
                            swMan.Write(JsonSerializer.Serialize(parsedForExpire.Manifest));
                    }
                    byte[] expiredPkgBytes = await File.ReadAllBytesAsync(expiredPkgZip);
                    var (expOk, expPlain, _, expErr) = await V2NetworkClient.CallRemoteInverseAsync(
                        eq01Peer,
                        "AESGCM",
                        fwdResp.PacketId,
                        expiredPkgBytes,
                        fwdResp.PublicParameters,
                        keyId: fwdResp.KeyRef.KeyId);
                    if (!expOk || expPlain == null || !expPlain.SequenceEqual(anexoPlain))
                        throw new Exception($"ADR 0005 paquete antiguo (>15 min) fue rechazado: {expErr}");

                    // ADR 0006: petición /api/crypto/forward firmada por nodo nuevo EQ09 no registrado previamente -> 200 OK y Source="request", IsConfirmed=false
                    using var rsaEq09 = RSA.Create(2048);
                    var dnEq09 = new X500DistinguishedNameBuilder();
                    dnEq09.AddCommonName("EQ09");
                    dnEq09.AddOrganizationalUnitName("Equipo-09");
                    dnEq09.AddOrganizationName("CentroCiberseguridad");
                    dnEq09.AddCountryOrRegion("MX");
                    var reqEq09Cert = new CertificateRequest(dnEq09.Build(), rsaEq09, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    reqEq09Cert.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
                    reqEq09Cert.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
                    reqEq09Cert.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(reqEq09Cert.PublicKey, false));
                    byte[] serialEq09 = RandomNumberGenerator.GetBytes(9);
                    serialEq09[0] = (byte)((serialEq09[0] & 0x7F) | 0x40);
                    using var certEq09 = reqEq09Cert.Create(
                        reqEq09Cert.SubjectName,
                        X509SignatureGenerator.CreateForRSA(rsaEq09, RSASignaturePadding.Pkcs1),
                        DateTimeOffset.UtcNow.AddMinutes(-10),
                        DateTimeOffset.UtcNow.AddDays(365),
                        serialEq09);

                    string eq09PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant();
                    string eq09ReqId = Guid.NewGuid().ToString("D").ToLowerInvariant();
                    cleanupPacketIds.Add(eq09PacketId);

                    var fwdReqEq09 = new V2CryptoForwardRequest
                    {
                        RequestId = eq09ReqId,
                        PacketId = eq09PacketId,
                        RequesterNode = "EQ09",
                        TargetNode = "EQ01",
                        AlgorithmCode = "AESGCM",
                        Operation = "forward",
                        OriginalFileName = "eq09.txt",
                        OriginalExtension = ".txt",
                        KeySizeBits = 256,
                        TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    };
                    byte[] rawEq09Req = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fwdReqEq09));
                    string sigEq09 = Convert.ToBase64String(rsaEq09.SignData(rawEq09Req, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                    string pemEq09 = certEq09.ExportCertificatePem();

                    using var eq09Form = new MultipartFormDataContent();
                    var eq09JsonContent = new ByteArrayContent(rawEq09Req);
                    eq09JsonContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                    eq09Form.Add(eq09JsonContent, "request", "request.json");
                    eq09Form.Add(new StringContent(sigEq09, Encoding.UTF8), "requestSignature");
                    eq09Form.Add(new StringContent(pemEq09, Encoding.UTF8), "requesterCertificate");
                    var eq09Payload = new ByteArrayContent(Encoding.UTF8.GetBytes("ADR0006 OK"));
                    eq09Payload.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                    eq09Form.Add(eq09Payload, "payload", "eq09.txt");

                    using var eq09Client = new HttpClient();
                    using var eq09Msg = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{interopPort}/api/crypto/forward") { Content = eq09Form };
                    eq09Msg.Headers.TryAddWithoutValidation("X-CC-Node", "EQ09");
                    eq09Msg.Headers.TryAddWithoutValidation("X-CC-Protocol", "2.0");
                    eq09Msg.Headers.TryAddWithoutValidation("X-CC-Request-Id", eq09ReqId);

                    var eq09Resp = await eq09Client.SendAsync(eq09Msg);
                    if (!eq09Resp.IsSuccessStatusCode)
                    {
                        string eq09Err = await eq09Resp.Content.ReadAsStringAsync();
                        throw new Exception($"ADR 0006 falló: EQ09 no fue aceptado ({(int)eq09Resp.StatusCode}): {eq09Err}");
                    }

                    using (var eq09Db = new AppDbContext())
                    {
                        var registeredEq09 = eq09Db.TrustedPeers.AsNoTracking().FirstOrDefault(p => p.NodeId == "EQ09");
                        if (registeredEq09 == null || registeredEq09.Source != "request" || registeredEq09.IsConfirmed)
                            throw new Exception($"ADR 0006 falló al auto-registrar EQ09: found={registeredEq09 != null}, source={registeredEq09?.Source}, confirmed={registeredEq09?.IsConfirmed}");
                    }
                }
                finally
                {
                    // Limpiar registros efímeros generados en la BD de producción por la prueba HTTP
                    try
                    {
                        NodeRuntimeState.NetworkPeers.RemoveAll(p => p.NodeId == "EQ09");
                        using var cleanDb = new AppDbContext();
                        var pEq09 = cleanDb.TrustedPeers.Where(p => p.NodeId == "EQ09").ToList();
                        if (pEq09.Count > 0) cleanDb.TrustedPeers.RemoveRange(pEq09);
                        var testRegs = cleanDb.RegistrosCifrados.Where(r => cleanupPacketIds.Contains(r.PacketId)).ToList();
                        if (testRegs.Count > 0) cleanDb.RegistrosCifrados.RemoveRange(testRegs);
                        cleanDb.SaveChanges();
                        AppDbContext.CheckpointWalTruncate();
                    }
                    catch { }
                }
            }

            // Bloque 3 (Interoperabilidad EQ08 + parseo robusto de llaves en los 21 algoritmos)
            byte[] sampleMsg = Encoding.UTF8.GetBytes("MensajeInteropEQ08!");
            var hashStrategy = CryptoCatalog.GetStrategy("HASHSHA");
            string sha256HexLower = Convert.ToHexString(SHA256.HashData(sampleMsg)).ToLowerInvariant();
            string sha512HexLower = Convert.ToHexString(SHA512.HashData(sampleMsg)).ToLowerInvariant();

            var hashOk256 = hashStrategy.Decrypt(sampleMsg, "", JsonSerializer.Serialize(new { hashAlgorithm = "SHA-256", digestHex = sha256HexLower }));
            var hashOk512 = hashStrategy.Decrypt(sampleMsg, "", JsonSerializer.Serialize(new { hashAlgorithm = "SHA-512", digestHex = sha512HexLower }));
            var hashFail256 = hashStrategy.Decrypt(sampleMsg, "", JsonSerializer.Serialize(new { hashAlgorithm = "SHA-256", digestHex = new string('0', 64) }));
            if (!hashOk256.Success || !hashOk256.OutputBytes.SequenceEqual(sampleMsg) ||
                !hashOk512.Success || !hashOk512.OutputBytes.SequenceEqual(sampleMsg) ||
                hashFail256.Success || !hashFail256.OutputBytes.SequenceEqual(sampleMsg))
            {
                throw new Exception("Falló verificación HASHSHA v2.0 (digestHex / archivo intacto).");
            }

            var hmacStrategy = CryptoCatalog.GetStrategy("HMACSHA256");
            byte[] shortPayload = Encoding.UTF8.GetBytes("Hola EQ08 < 32 B");
            byte[] rawHmacKey = Encoding.UTF8.GetBytes("secreto-hmac-interop");
            string extMacHex = Convert.ToHexString(HMACSHA256.HashData(rawHmacKey, shortPayload)).ToLowerInvariant();
            string hmacPubExt = JsonSerializer.Serialize(new { macAlgorithm = "HMAC-SHA256", macHex = extMacHex });
            var hmacExtOk = hmacStrategy.Decrypt(shortPayload, "secreto-hmac-interop", hmacPubExt);
            var hmacExtBad = hmacStrategy.Decrypt(shortPayload, "otra-clave-incorrecta", hmacPubExt);
            if (!hmacExtOk.Success || !hmacExtOk.OutputBytes.SequenceEqual(shortPayload) ||
                hmacExtBad.Success || !hmacExtBad.OutputBytes.SequenceEqual(shortPayload))
            {
                throw new Exception("Falló verificación HMACSHA256 v2.0 sin recorte de 32 bytes.");
            }
            string normHmacB64 = KeyInputParser.NormalizeHmacKeyBase64("mi-clave-corta");
            if (Convert.FromBase64String(normHmacB64).Length < 32)
                throw new Exception("NormalizeHmacKeyBase64 debe garantizar >= 32 bytes.");

            // CAESAR ("3", A-Z y BYTE)
            var caesarStrategy = CryptoCatalog.GetStrategy("CAESAR");
            var caesarAzDec = caesarStrategy.Decrypt(Encoding.UTF8.GetBytes("Krod Pxqgr 123!"), "3", JsonSerializer.Serialize(new { alphabet = "A-Z" }));
            if (Encoding.UTF8.GetString(caesarAzDec.OutputBytes) != "Hola Mundo 123!")
                throw new Exception($"Falló CAESAR A-Z con shift '3': '{Encoding.UTF8.GetString(caesarAzDec.OutputBytes)}'");
            byte[] byteShifted = sampleMsg.Select(b => (byte)((b + 3) & 0xFF)).ToArray();
            if (!caesarStrategy.Decrypt(byteShifted, "3", JsonSerializer.Serialize(new { alphabet = "BYTE" })).OutputBytes.SequenceEqual(sampleMsg))
                throw new Exception("Falló CAESAR BYTE con shift entero '3'.");

            // VIGENERE ("CRIPTOGRAFIA", A-Z y BYTE sin keyLength)
            var vigStrategy = CryptoCatalog.GetStrategy("VIGENERE");
            byte[] vigKeyBytes = Encoding.UTF8.GetBytes("CRIPTOGRAFIA");
            byte[] vigByteCipher = sampleMsg.Select((b, i) => (byte)((b + vigKeyBytes[i % vigKeyBytes.Length]) & 0xFF)).ToArray();
            if (!vigStrategy.Decrypt(vigByteCipher, "CRIPTOGRAFIA", "{}").OutputBytes.SequenceEqual(sampleMsg))
                throw new Exception("Falló VIGENERE BYTE al parsear 'CRIPTOGRAFIA' sin corromper por Base64.");

            // XORASM (modo v2.0 ROL 3 con clave "clave123")
            var xorStrategy = CryptoCatalog.GetStrategy("XORASM");
            byte[] xorKey = Encoding.UTF8.GetBytes("clave123");
            byte[] xorCipher = sampleMsg.Select((b, i) =>
            {
                byte x = (byte)(b ^ xorKey[i % xorKey.Length]);
                return (byte)(((x << 3) | (x >> 5)) & 0xFF);
            }).ToArray();
            var xorDec = xorStrategy.Decrypt(xorCipher, "clave123", JsonSerializer.Serialize(new { rotation = "ROL", rotationBits = 3 }));
            if (!xorDec.OutputBytes.SequenceEqual(sampleMsg))
                throw new Exception("Falló XORASM v2.0 con ROL 3 y clave 'clave123'.");

            // EUCLIDESAFFINE ("5,8", mod 256 y mod 26)
            var affStrategy = CryptoCatalog.GetStrategy("EUCLIDESAFFINE");
            byte[] affCipher256 = sampleMsg.Select(b => (byte)((5 * b + 8) & 0xFF)).ToArray();
            if (!affStrategy.Decrypt(affCipher256, "5,8", JsonSerializer.Serialize(new { modulus = 256 })).OutputBytes.SequenceEqual(sampleMsg))
                throw new Exception("Falló EUCLIDESAFFINE mod 256 con llave '5,8'.");

            // Verificar que entradas inválidas nunca lancen FormatException crudo en estrategias protegidas
            foreach (string codeGuard in new[] { "CAESAR", "XORASM", "EUCLIDESAFFINE", "MILLERRABIN", "RSA", "ECC", "DIFFIEHELLMAN", "DIGITALSIG", "DFTSPECTRAL", "LAGRANGESHAMIR" })
            {
                try
                {
                    _ = CryptoCatalog.GetStrategy(codeGuard).Decrypt(new byte[16], "no-es-base64!!!", "{}");
                }
                catch (FormatException fex)
                {
                    throw new Exception($"La estrategia {codeGuard} lanzó FormatException sin controlar: {fex.Message}");
                }
                catch
                {
                    // Se permite CryptographicException o JsonException controlada
                }
            }

            // Bloque 5: Verificaciones obligatorias de subred /22, Tabla 4.1, HologramDialog sin fugas, ResetDashboardState y flujo EQ08 remoto (HASHSHA/HMACSHA256)
            var plan24 = NetworkAddressService.ComputeSubnetScanPlan("192.168.10.42", "255.255.255.0", includeLocalIp: true);
            if (plan24.PrefixLength != 24 || plan24.EffectivePrefixLength != 24 ||
                plan24.SubnetHosts.Count != 254 ||
                plan24.SubnetHosts.Contains("192.168.10.0") ||
                plan24.SubnetHosts.Contains("192.168.10.255") ||
                !plan24.SubnetHosts.Contains("192.168.10.1") ||
                !plan24.SubnetHosts.Contains("192.168.10.254"))
            {
                throw new Exception($"Falló cálculo de subred /24: hosts={plan24.SubnetHosts.Count}, eff=/{plan24.EffectivePrefixLength}");
            }

            var plan20 = NetworkAddressService.ComputeSubnetScanPlan("10.10.5.42", "255.255.240.0", includeLocalIp: true);
            if (plan20.PrefixLength != 20 || plan20.EffectivePrefixLength != 22 ||
                plan20.NetworkAddress != "10.10.4.0" || plan20.BroadcastAddress != "10.10.7.255" ||
                plan20.SubnetHosts.Count != 1022 ||
                plan20.SubnetHosts.Contains("10.10.4.0") ||
                plan20.SubnetHosts.Contains("10.10.7.255") ||
                plan20.SubnetHosts.Contains("10.10.0.0") ||
                plan20.SubnetHosts.Contains("10.10.15.255") ||
                !plan20.SubnetHosts.Contains("10.10.4.1") ||
                !plan20.SubnetHosts.Contains("10.10.5.10") ||
                !plan20.SubnetHosts.Contains("10.10.6.10") ||
                !plan20.SubnetHosts.Contains("10.10.7.254"))
            {
                throw new Exception($"Falló cálculo de subred /22 desde /20: hosts={plan20.SubnetHosts.Count}, net={plan20.NetworkAddress}, bcast={plan20.BroadcastAddress}");
            }

            // Verificar persistencia ScanHosts restaurando lista previa
            var originalScanHosts = NetworkAddressService.LoadScanHosts();
            try
            {
                var parsedScan = NetworkAddressService.ParseScanHostsCsv("192.168.1.99, 10.10.5.12:5006, invalido");
                NetworkAddressService.SaveScanHosts(parsedScan);
                var reloadedScan = NetworkAddressService.LoadScanHosts();
                if (reloadedScan.Count != 2 || !reloadedScan.Contains("192.168.1.99") || !reloadedScan.Contains("10.10.5.12:5006"))
                    throw new Exception("Falló persistencia ScanHosts.");
            }
            finally
            {
                NetworkAddressService.SaveScanHosts(originalScanHosts);
            }

            // Verificar Tabla 4.1 exacta EQ01..EQ08
            if (!NodeRuntimeState.GetOwnedAlgorithmsForTeam(4).SequenceEqual(new[] { "DIFFIEHELLMAN", "CAESAR" }) ||
                !NodeRuntimeState.GetOwnedAlgorithmsForTeam(6).SequenceEqual(new[] { "LSBSTEGO", "EUCLIDESAFFINE" }) ||
                !NodeRuntimeState.GetOwnedAlgorithmsForTeam(8).SequenceEqual(new[] { "HASHSHA", "HMACSHA256" }))
            {
                throw new Exception("Falló verificación de Tabla 4.1 exacta para EQ01–EQ08.");
            }

            // Verificar HologramDialog (5 variantes) sin fugas y estética oscura exacta + ResetDashboardState en FormDashboard
            foreach (HologramDialogType dlgType in Enum.GetValues<HologramDialogType>())
            {
                using var testDlg = new HologramDialog(dlgType, "Mensaje de diagnóstico\nLínea 2", "Título Prueba", HologramDialogButtons.YesNoCancel);
                if (testDlg.BackColor != HologramTheme.BackgroundBase || testDlg.FormBorderStyle != FormBorderStyle.None)
                    throw new Exception($"HologramDialog({dlgType}) no cumple tema oscuro sin bordes.");
            }

            using (var testDash = new FormDashboard(new Usuario { Id = 1, NombreUsuario = "selftest_op", NombreCompleto = "Operador SelfTest" }))
            {
                testDash.ResetDashboardState();
                if (!testDash.VerifyCleanResetSnapshot())
                    throw new Exception("ResetDashboardState() dejó estado residual en Visor, Manifiesto o Holograma.");
            }

            // Flujo HTTP v2.0 activo con nodo EQ08 simulado (HASHSHA + HMACSHA256 forward/inverse + verification.valid)
            int eq08Port = GetFreeTcpPort();
            string eq08CertPfx = Path.Combine(AppDbContext.AppDataDirectory, "node_identity_v2_EQ08.pfx");
            string eq08CertKey = Path.Combine(AppDbContext.AppDataDirectory, "node_identity_v2_EQ08.key");
            bool eq08HadPfx = File.Exists(eq08CertPfx);
            var eq08CleanupPkts = new List<string>();

            try
            {
                NodeRuntimeState.ConfigureForMode(ProtocolVersionMode.V2, teamNumber: 8, explicitPort: eq08Port);
                V2CertificateService.Initialize();
                string eq08Thumb = V2CertificateService.Thumbprint;
                string eq08Pem = V2CertificateService.ExportPublicCertPem();

                await using var eq08Runtime = new V2ProtocolRuntime();
                if (!await eq08Runtime.StartAsync(eq08Port))
                    throw new Exception($"No pudo iniciar eq08Runtime en puerto {eq08Port}: {eq08Runtime.LastStartupError}");

                var eq08Peer = new PeerNode
                {
                    NodeId = "EQ08",
                    TeamNumber = 8,
                    IpAddress = "127.0.0.1",
                    Port = eq08Port,
                    CertThumbprint = eq08Thumb,
                    PinnedThumbprintSha256 = eq08Thumb,
                    CertificatePem = eq08Pem,
                    IsConfirmed = true,
                    Status = "online"
                };

                byte[] msgEq08 = Encoding.UTF8.GetBytes("Prueba Real EQ08 HASHSHA & HMACSHA256");

                // HASHSHA forward -> inverse
                var (hFwdOk, hFwdResp, hFwdErr) = await V2NetworkClient.CallRemoteForwardAsync(
                    eq08Peer, "HASHSHA", msgEq08, "hash_eq08.txt", ".txt", keySizeBits: null,
                    options: new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-256" });
                if (!hFwdOk || hFwdResp == null)
                    throw new Exception($"EQ08 HASHSHA forward falló: {hFwdErr}");
                eq08CleanupPkts.Add(hFwdResp.PacketId);

                var (hInvOk, hPlain, hResZip, hInvErr) = await V2NetworkClient.CallRemoteInverseAsync(
                    eq08Peer, "HASHSHA", hFwdResp.PacketId, Convert.FromBase64String(hFwdResp.CiphertextBase64), hFwdResp.PublicParameters);
                if (!hInvOk || hPlain == null || !hPlain.SequenceEqual(msgEq08) || hResZip?.Manifest.Verification?.Valid != true)
                    throw new Exception($"EQ08 HASHSHA inverse falló: {hInvErr}");

                // HMACSHA256 forward -> inverse con secreto normalizado >= 32 B
                var (mFwdOk, mFwdResp, mFwdErr) = await V2NetworkClient.CallRemoteForwardAsync(
                    eq08Peer, "HMACSHA256", msgEq08, "hmac_eq08.txt", ".txt", keySizeBits: null,
                    secretsDictionary: new Dictionary<string, string> { ["key"] = "secreto-eq08-test" },
                    options: new Dictionary<string, string> { ["macAlgorithm"] = "HMAC-SHA256" });
                if (!mFwdOk || mFwdResp == null)
                    throw new Exception($"EQ08 HMACSHA256 forward falló: {mFwdErr}");
                eq08CleanupPkts.Add(mFwdResp.PacketId);

                var (mInvOk, mPlain, mResZip, mInvErr) = await V2NetworkClient.CallRemoteInverseAsync(
                    eq08Peer, "HMACSHA256", mFwdResp.PacketId, Convert.FromBase64String(mFwdResp.CiphertextBase64), mFwdResp.PublicParameters,
                    secretsDictionary: new Dictionary<string, string> { ["key"] = "secreto-eq08-test" });
                if (!mInvOk || mPlain == null || !mPlain.SequenceEqual(msgEq08) || mResZip?.Manifest.Verification?.Valid != true)
                    throw new Exception($"EQ08 HMACSHA256 inverse falló: {mInvErr}");
            }
            finally
            {
                try
                {
                    using var dbClean8 = new AppDbContext();
                    var regs8 = dbClean8.RegistrosCifrados.Where(r => eq08CleanupPkts.Contains(r.PacketId)).ToList();
                    if (regs8.Count > 0)
                    {
                        dbClean8.RegistrosCifrados.RemoveRange(regs8);
                        dbClean8.SaveChanges();
                    }
                    AppDbContext.CheckpointWalTruncate();
                }
                catch { }

                if (!eq08HadPfx)
                {
                    TryDeleteFile(eq08CertPfx);
                    TryDeleteFile(eq08CertKey);
                }

                NodeRuntimeState.ConfigureForMode(ProtocolVersionMode.V2, teamNumber: 1);
                V2CertificateService.Initialize();
            }

            Console.WriteLine(
                $"SELFTEST_OK: DualArchitecture=v1.0+v2.0, SinglePersistentDB={AppDbContext.DatabasePath}, Consolidation={AppDbContext.LastConsolidationReport}, " +
                $"SQLiteWAL_CheckpointTruncate=OK, Legacy4PendingMigrationTo5thAndConsultas=OK, IPv4={primaryEp.Ipv4Address}({primaryEp.InterfaceName}), " +
                $"Algorithms={passedAlgorithms}/21, Subnet_20_22_24_ScanHosts_Table4_1=OK, DarkUI_HologramDialog_ResetDashboard=OK, " +
                $"V1_5FileZIP_DualAPI_RemoteKey=OK, V2_v3LocalKeyId_EQ08_HASH_HMAC_Inverse=OK, " +
                $"V2_StrictEmission_EQ01_Table4_2(AESGCM,DES)=OK, V2_CC_ENV_1_ExactByteSizes(32B,12B,16B,256B,NoCiphertextInResultEnvelope)=OK, " +
                $"V2_EQ06_6ByteAliasTolerance(ivBase64,opt.keySizeBits,AAD_PacketId_or_Null,Base64_Hex_Passphrase)=OK, " +
                $"V2_Interop_ADRs(0005,0006,0007,0012,NoCompression,UseProxyFalse)=OK, EQ08_HashHmac_ClassicalKeys(NoFormatException)=OK, " +
                $"V2_14StepValidation(E-ZIP-STRUCTURE:400,E-HASH:422,E-PARAMS-HASH:422,E-SIGNATURE:422,E-TIMESTAMP:422,E-DUPLICATE:409,E-ENV-RECIPIENT:401,E-ENV-DECRYPT:401)=OK");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"SELFTEST_FAIL: {ex}");
            return 1;
        }
        finally
        {
            foreach (var f in tempFiles)
                TryDeleteFile(f);
        }
    }

    private static string CreateTamperedManifestZip(string sourceZipPath, Action<PacketManifest> mutate)
    {
        var parsed = V2PacketZipService.ReadPacketZip(sourceZipPath, enforceStrictSignature: false);
        mutate(parsed.Manifest);

        string outZip = Path.Combine(Path.GetTempPath(), $"v2_tampered_{Guid.NewGuid():N}.zip");
        using var archive = ZipFile.Open(outZip, ZipArchiveMode.Create);

        using (var ds = archive.CreateEntry("datos.enc").Open())
            ds.Write(parsed.PayloadBytes, 0, parsed.PayloadBytes.Length);

        using (var swPem = new StreamWriter(archive.CreateEntry("certificado.pem").Open(), new UTF8Encoding(false)))
            swPem.Write(parsed.CertificatePem);

        using (var swMan = new StreamWriter(archive.CreateEntry("manifest.json").Open(), new UTF8Encoding(false)))
            swMan.Write(JsonSerializer.Serialize(parsed.Manifest));

        return outZip;
    }

    private static void ExpectValidationException(Action action, string expectedCode, int expectedStatus)
    {
        try
        {
            action();
        }
        catch (PacketValidationException pve) when (pve.ErrorCode == expectedCode && pve.HttpStatusCode == expectedStatus)
        {
            return;
        }
        catch (PacketValidationException pve)
        {
            throw new Exception($"Se esperaba {expectedCode} ({expectedStatus}), pero se recibió {pve.ErrorCode} ({pve.HttpStatusCode}): {pve.Message}");
        }

        throw new Exception($"La prueba negativa no lanzó PacketValidationException (se esperaba {expectedCode} HTTP {expectedStatus}).");
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

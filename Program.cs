using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using ModuloCrypto.Network.V1;
using ModuloCrypto.Network.V2;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Forms;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
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
            MessageBox.Show(
                $"Error al inicializar la base de datos SQLite:\n{ex.Message}",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        // 2. Ciclo de vida diferido: Mostrar Login primero y levantar el servidor V1 o V2 elegido por el operador
        ProtocolVersionMode currentVersion = cliVersion;
        int currentTeam = teamNumber;

        bool keepRunning = true;
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

            Console.WriteLine(
                $"SELFTEST_OK: DualArchitecture=v1.0+v2.0, SQLiteWAL=OK, IPv4={primaryEp.Ipv4Address}({primaryEp.InterfaceName}), " +
                $"Algorithms={passedAlgorithms}/21, V1_5FileZIP_DualAPI_RemoteKey=OK, " +
                $"V2_StrictEmission_EQ01_Table4_2(AESGCM,DES)=OK, V2_CC_ENV_1_ExactByteSizes(32B,12B,16B,256B,NoCiphertextInResultEnvelope)=OK, " +
                $"V2_EQ06_6ByteAliasTolerance(ivBase64,opt.keySizeBits,AAD_PacketId_or_Null,Base64_Hex_Passphrase)=OK, " +
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

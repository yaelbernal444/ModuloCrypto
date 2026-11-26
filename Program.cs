using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Forms;
using System.IO.Compression;
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
        var (teamNumber, explicitPort) = ParseCliArgs(args);
        NodeRuntimeState.ConfigureTeamAndPort(teamNumber, explicitPort);

        if (args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
            return RunSelfTest();

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

        // 2. Inicializar Certificado X.509 RSA-2048 v2.0 (Vigencia 365 días, RSA-PSS-SHA256, protegido con DPAPI)
        try
        {
            NodeCertificateService.Initialize();
        }
        catch
        {
            NodeRuntimeState.CertificateActive = false;
        }

        // 3. Arrancar servidor ASP.NET Core Minimal API embebido en http://0.0.0.0:<ApiPort>
        var apiHost = new ApiHostService();
        apiHost.StartAsync(NodeRuntimeState.ApiPort).GetAwaiter().GetResult();

        // 4. Arrancar servicio de autodescubrimiento UDP en puerto 5099 (CC-BEACON cada 30s + beacon offline al cerrar)
        var udpDiscovery = new UdpDiscoveryService();
        udpDiscovery.Start();

        try
        {
            bool keepRunning = true;
            while (keepRunning)
            {
                using var loginForm = new FormLogin();
                if (loginForm.ShowDialog() != DialogResult.OK || loginForm.AuthenticatedUser == null)
                    break;

                using var dashboard = new FormDashboard(loginForm.AuthenticatedUser);
                Application.Run(dashboard);
                keepRunning = dashboard.SignOutRequested;
            }
        }
        finally
        {
            udpDiscovery.DisposeAsync().AsTask().GetAwaiter().GetResult();
            apiHost.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        return 0;
    }

    private static (int TeamNumber, int? ExplicitPort) ParseCliArgs(string[] args)
    {
        int team = 1;
        int? port = null;

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
        }

        return (team, port);
    }

    private static int RunSelfTest()
    {
        string tempDbPath = Path.Combine(Path.GetTempPath(), $"ModuloCrypto_SelfTest_v2_{Guid.NewGuid():N}.db");
        string? packageZipPath = null;
        string? resultZipPath = null;
        string? forwardedZipPath = null;
        string? multipartZipPath = null;
        string? invalidZipPath = null;

        try
        {
            // 1. Verificar Punto 1: Identidad EQ01, puerto 5001 y Certificado X.509 v2.0
            if (NodeRuntimeState.TeamNumber != 1 || NodeRuntimeState.CurrentNodeId != "EQ01" || NodeRuntimeState.ApiPort != 5001)
                throw new Exception($"Identidad esperada EQ01:5001, actual {NodeRuntimeState.CurrentNodeId}:{NodeRuntimeState.ApiPort}");

            var cert = NodeCertificateService.Initialize(forceRegenerate: true);
            if (!cert.Subject.Contains("CN=EQ01", StringComparison.OrdinalIgnoreCase) ||
                !cert.Subject.Contains("OU=Equipo 01", StringComparison.OrdinalIgnoreCase) ||
                !cert.Subject.Contains("O=Centro de Ciberseguridad", StringComparison.OrdinalIgnoreCase) ||
                !cert.Subject.Contains("C=MX", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception($"El Subject X.509 no cumple el formato v2.0: {cert.Subject}");
            }

            double validityDays = (cert.NotAfter.ToUniversalTime() - cert.NotBefore.ToUniversalTime()).TotalDays;
            if (Math.Abs(validityDays - 365.0) > 0.05)
                throw new Exception($"Vigencia X.509 esperada 365 días, actual: {validityDays:F2}");

            if (cert.GetSerialNumber().Length < 8)
                throw new Exception("El número de serie X.509 tiene menos de 64 bits (8 bytes).");

            string thumb = NodeCertificateService.GetThumbprintSha256Hex();
            if (!Regex.IsMatch(thumb, "^[0-9A-F]{64}$"))
                throw new Exception($"Huella SHA-256 inválida (se esperan 64 HEX MAYÚSCULAS): {thumb}");

            // 2. Verificar BD SQLite vacía sin usuarios precreados + modo WAL + PBKDF2-SHA256 + tablas TrustedPeers y SeenPackets
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

            var reg = AuthService.Register("Operador EQ01", "eq01_op", "ClaveSegura!2026", "EQ01", "Operador EQ01", tempDbPath);
            if (!reg.Success || reg.User == null || !reg.User.PasswordHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
                throw new Exception("Fallo en registro PBKDF2-SHA256.");

            var authOk = AuthService.Authenticate("eq01_op", "ClaveSegura!2026", tempDbPath)
                ?? throw new Exception("Fallo en autenticación PBKDF2-SHA256.");

            // 3. Verificar Punto 2: CC-BEACON UDP 5099 <= 1024 bytes
            var beacon = new CcBeaconMessage
            {
                Type = "CC-BEACON",
                ProtocolVersion = "2.0",
                NodeId = NodeRuntimeState.CurrentNodeId,
                TeamNumber = NodeRuntimeState.TeamNumber,
                Ip = NodeRuntimeState.LocalIpAddress,
                HttpPort = NodeRuntimeState.ApiPort,
                Status = "online",
                Algorithms = NodeRuntimeState.OwnedAlgorithms.ToList(),
                CertificateThumbprintSha256 = thumb
            };
            byte[] beaconBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(beacon));
            if (beaconBytes.Length > 1024)
                throw new Exception($"CC-BEACON supera los 1024 bytes ({beaconBytes.Length}).");

            // 4. Verificar los 21 Algoritmos Oficiales en Local
            byte[] sample = Encoding.UTF8.GetBytes("ModuloCrypto-Estándar-v2.0-EQ01-Payload-2026!");
            int passed = 0;
            foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            {
                var strat = CryptoCatalog.GetStrategy(alg.Code);
                var enc = strat.Encrypt(sample, "clave-prueba");
                var dec = strat.Decrypt(enc.OutputBytes, enc.SecretKeyBase64, enc.PublicParametersJson);
                if (alg.IsReversible && !sample.SequenceEqual(dec.OutputBytes))
                    throw new Exception($"Round-trip local falló para {alg.Code}");
                passed++;
            }

            // 5. Verificar Punto 4: Hash canónico de publicParameters vacío y ordenado con StringComparer.Ordinal
            string emptyParamsHash = PacketManifest.ComputePublicParametersSha256(new Dictionary<string, string>());
            if (emptyParamsHash != PacketManifest.EmptySha256Lower)
                throw new Exception($"Hash canónico vacío incorrecto: {emptyParamsHash}");

            var sampleParams = new Dictionary<string, string>
            {
                ["zKey"] = "valorZ",
                ["aKey"] = "valorA"
            };
            string expectedOrderedSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("aKey=valorA\nzKey=valorZ"))).ToLowerInvariant();
            if (PacketManifest.ComputePublicParametersSha256(sampleParams) != expectedOrderedSha)
                throw new Exception("Canonicalización StringComparer.Ordinal de publicParameters falló.");

            // 6. Verificar Punto 3 y 4: Estructura estricta .ZIP v2.0 (3 archivos planos: datos.enc, certificado.pem, manifest.json)
            var aesRes = CryptoCatalog.GetStrategy("AESGCM").Encrypt(sample);
            var rec = new RegistroCifrado
            {
                UsuarioId = authOk.Id,
                PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant(),
                NombreArchivo = "mensaje_v2.txt",
                Extension = ".txt",
                BytesCifrados = Convert.ToBase64String(aesRes.OutputBytes),
                AlgoritmoCodigo = "AESGCM",
                ParametrosPublicosJson = aesRes.PublicParametersJson,
                LlaveSecretaBase64 = aesRes.SecretKeyBase64,
                NodoRaiz = "EQ01",
                RutaSaltosJson = "[\"EQ01\"]",
                Origen = "Local"
            };

            packageZipPath = PacketZipService.CreatePacketZip(rec, aesRes.OutputBytes, packetType: "package");
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

            var parsedPkg = PacketZipService.ReadPacketZip(packageZipPath, enforceStrictSignature: true);
            if (!parsedPkg.SignatureValid || !parsedPkg.IntegrityValid || parsedPkg.Manifest.Version != "2.0")
                throw new Exception("Falló la validación RSA-PSS-SHA256 de 11 campos en package v2.0.");

            // 7. Verificar paquete result (RES_<NODEID>_... con resultado.enc, certificado.pem, manifest.json)
            resultZipPath = PacketZipService.CreatePacketZip(rec, aesRes.OutputBytes, packetType: "result", operation: "inverse", requestId: rec.PacketId);
            if (!Path.GetFileName(resultZipPath).StartsWith("RES_EQ01_AESGCM_", StringComparison.Ordinal))
                throw new Exception($"Nomenclatura de result .zip inválida: {Path.GetFileName(resultZipPath)}");

            using (var zRes = ZipFile.OpenRead(resultZipPath))
            {
                if (zRes.Entries.Count != 3 || zRes.GetEntry("resultado.enc") == null)
                    throw new Exception("El paquete result v2.0 no contiene exactamente resultado.enc, certificado.pem y manifest.json.");
            }
            var parsedRes = PacketZipService.ReadPacketZip(resultZipPath, enforceStrictSignature: true);
            if (!parsedRes.SignatureValid || parsedRes.Manifest.PacketType != "result")
                throw new Exception("Falló la lectura del paquete result v2.0.");

            // 8. Verificar Sección 9.6: RepackageForForwarding
            forwardedZipPath = PacketZipService.RepackageForForwarding(packageZipPath);
            var parsedFwd = PacketZipService.ReadPacketZip(forwardedZipPath, enforceStrictSignature: true);
            if (!parsedFwd.SignatureValid ||
                parsedFwd.Manifest.PacketId == parsedPkg.Manifest.PacketId ||
                parsedFwd.Manifest.ProducerNode != parsedPkg.Manifest.ProducerNode ||
                parsedFwd.Manifest.SourceNode != "EQ01" ||
                parsedFwd.Manifest.EncryptedSha256 != parsedPkg.Manifest.EncryptedSha256)
            {
                throw new Exception("RepackageForForwarding (Sección 9.6) no conservó los campos del productor o no generó nuevo packetId.");
            }

            // 9. Verificar soporte multipart (part-01.bin, part-02.bin)
            byte[] multiBytes = PacketZipService.CreateMultipartInnerZip(new[]
            {
                Encoding.UTF8.GetBytes("Fragmento-Shamir-01"),
                Encoding.UTF8.GetBytes("Fragmento-Shamir-02"),
                Encoding.UTF8.GetBytes("Fragmento-Shamir-03")
            }, out var multiParts);
            multipartZipPath = PacketZipService.CreatePacketZip(rec, multiBytes, multipartParts: multiParts);
            var parsedMulti = PacketZipService.ReadPacketZip(multipartZipPath, enforceStrictSignature: true);
            if (parsedMulti.Manifest.PayloadMode != "multipart" || parsedMulti.Manifest.Parts?.Count != 3)
                throw new Exception("Falló validación de paquete multipart v2.0.");

            // 10. Verificar rechazo E-ZIP-STRUCTURE ante .zip con 4 archivos o subcarpeta
            invalidZipPath = Path.Combine(Path.GetTempPath(), $"InvalidV2_{Guid.NewGuid():N}.zip");
            File.Copy(packageZipPath, invalidZipPath, true);
            using (var zInv = ZipFile.Open(invalidZipPath, ZipArchiveMode.Update))
            {
                var extra = zInv.CreateEntry("extra.txt");
                using var sw = new StreamWriter(extra.Open());
                sw.Write("prohibido");
            }

            bool rejectedStructure = false;
            try
            {
                PacketZipService.ReadPacketZip(invalidZipPath, enforceStrictSignature: true);
            }
            catch (PacketValidationException pve) when (pve.ErrorCode == "E-ZIP-STRUCTURE" && pve.HttpStatusCode == 400)
            {
                rejectedStructure = true;
            }
            if (!rejectedStructure)
                throw new Exception("El validador no rechazó un .zip con 4 archivos con 400 E-ZIP-STRUCTURE.");

            Console.WriteLine($"SELFTEST_OK: Standard=v2.0, Node={NodeRuntimeState.CurrentNodeId}:{NodeRuntimeState.ApiPort}, X509_365d_RSAPSS=OK, UDP5099_Beacon=OK, Strict3FileZIP=OK, Canonical11FieldSig=OK, Forwarding9_6=OK, Multipart=OK, ZipSecurity=OK, Algorithms={passed}/21");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"SELFTEST_FAIL: {ex}");
            return 1;
        }
        finally
        {
            TryDeleteFile(tempDbPath);
            TryDeleteFile(tempDbPath + "-shm");
            TryDeleteFile(tempDbPath + "-wal");
            TryDeleteFile(packageZipPath);
            TryDeleteFile(resultZipPath);
            TryDeleteFile(forwardedZipPath);
            TryDeleteFile(multipartZipPath);
            TryDeleteFile(invalidZipPath);
        }
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

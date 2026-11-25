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
using System.Windows.Forms;

namespace ModuloCrypto;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
            return RunSelfTest();

        int apiPort = ParsePortArg(args, defaultPort: 5000);
        NodeRuntimeState.ApiPort = apiPort;
        var localPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == "NODO-01");
        if (localPeer != null) localPeer.Port = apiPort;

        ApplicationConfiguration.Initialize();

        // 1. Inicializar SQLite (ModuloCrypto.db) con EnsureCreated() (sin usuarios precreados)
        try
        {
            AppDbContext.InitializeDatabase();
            NodeRuntimeState.SqliteConnected = true;
        }
        catch (Exception ex)
        {
            NodeRuntimeState.SqliteConnected = false;
            MessageBox.Show(
                $"Error al inicializar la base de datos SQLite:\n{ex.Message}",
                "ModuloCrypto — SQLite",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        // 2. Inicializar Certificado X.509 del Nodo (protegido con Windows DPAPI)
        try
        {
            NodeCertificateService.Initialize();
        }
        catch
        {
            NodeRuntimeState.CertificateActive = false;
        }

        // 3. Arrancar servidor ASP.NET Core Minimal API embebido en http://0.0.0.0:<apiPort>
        var apiHost = new ApiHostService();
        apiHost.StartAsync(apiPort).GetAwaiter().GetResult();

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
            apiHost.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        return 0;
    }

    private static int ParsePortArg(string[] args, int defaultPort)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--port", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(args[i + 1], out int p) && p > 0 && p < 65536)
            {
                return p;
            }
        }
        return defaultPort;
    }

    private static int RunSelfTest()
    {
        string tempDbPath = Path.Combine(Path.GetTempPath(), $"ModuloCrypto_SelfTest_{Guid.NewGuid():N}.db");
        string? hybridZipPath = null;
        string? centroZipPath = null;
        string? unsignedZipPath = null;
        string? autoDownloadedBinaryPath = null;

        try
        {
            // 1. Test de Seguridad (Bloque A): BD nueva vacía (Count == 0) + PBKDF2-SHA256
            AppDbContext.InitializeDatabase(tempDbPath);
            using (var checkDb = new AppDbContext(tempDbPath))
            {
                int initialUsers = checkDb.Usuarios.Count();
                if (initialUsers != 0)
                    throw new Exception($"La BD nueva no inició vacía: contenía {initialUsers} usuario(s).");
            }

            var reg = AuthService.Register(
                "Operador Autoprueba",
                "op_selftest",
                "ClaveSegura!2026",
                "NODO-01",
                "Operador Tor",
                tempDbPath);

            if (!reg.Success || reg.User == null)
                throw new Exception($"Fallo registro PBKDF2: {reg.Message}");

            if (!reg.User.PasswordHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
                throw new Exception("El hash de contraseña no utiliza el formato PBKDF2$<salt>$<hash>.");

            var authOk = AuthService.Authenticate("op_selftest", "ClaveSegura!2026", tempDbPath)
                ?? throw new Exception("Fallo autenticación con credenciales PBKDF2 válidas.");

            var authBad = AuthService.Authenticate("op_selftest", "ClaveIncorrecta", tempDbPath);
            if (authBad != null)
                throw new Exception("La autenticación aceptó una contraseña incorrecta.");

            // 2. Identidad NODO-01 y Certificado X.509 con DPAPI
            if (NodeRuntimeState.CurrentNodeId != "NODO-01")
                throw new Exception($"CurrentNodeId esperado NODO-01, actual: {NodeRuntimeState.CurrentNodeId}");

            NodeCertificateService.Initialize();
            string pem = NodeCertificateService.ExportPublicCertPem();
            if (!pem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                throw new Exception("ExportPublicCertPem no generó formato PEM válido.");

            // 3. Los 21 Algoritmos Oficiales
            byte[] sample = Encoding.UTF8.GetBytes("ModuloCrypto-SelfTest-Payload-2026-TorMesh-DualProtocol!");
            int passed = 0;

            foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            {
                var strat = CryptoCatalog.GetStrategy(alg.Code);
                var enc = strat.Encrypt(sample, "clave-prueba");
                var dec = strat.Decrypt(enc.OutputBytes, enc.SecretKeyBase64, enc.PublicParametersJson);
                if (alg.IsReversible && !sample.SequenceEqual(dec.OutputBytes))
                    throw new Exception($"Round-trip falló para {alg.Code}");
                passed++;
            }

            // 4. Empaquetado .ZIP Híbrido Universal (5 archivos internos)
            var aesRes = CryptoCatalog.GetStrategy("AESGCM").Encrypt(sample);
            var rec = new RegistroCifrado
            {
                UsuarioId = authOk.Id,
                PacketId = Guid.NewGuid().ToString(),
                NombreArchivo = "test_hibrido.txt",
                Extension = ".txt",
                BytesCifrados = Convert.ToBase64String(aesRes.OutputBytes),
                AlgoritmoCodigo = "AESGCM",
                ParametrosPublicosJson = aesRes.PublicParametersJson,
                LlaveSecretaBase64 = aesRes.SecretKeyBase64,
                LinkDescifradoRemoto = NodeRuntimeState.BuildRemoteDecryptUrl("test"),
                NodoRaiz = "NODO-01",
                FirmaRaizBase64 = NodeCertificateService.SignDataPss(aesRes.OutputBytes),
                RutaSaltosJson = "[\"NODO-01\"]",
                Origen = "Local"
            };

            hybridZipPath = PacketZipService.CreatePacketZip(rec, aesRes.OutputBytes);
            using (var zipCheck = ZipFile.OpenRead(hybridZipPath))
            {
                string[] requiredEntries = { "manifest.json", "datos.enc", "payload.bin", "certificado.pem", "root_cert.cer" };
                foreach (string reqEntry in requiredEntries)
                {
                    if (zipCheck.GetEntry(reqEntry) == null)
                        throw new Exception($"El .zip híbrido no contiene la entrada requerida '{reqEntry}'.");
                }
            }

            var parsedHybrid = PacketZipService.ReadPacketZip(hybridZipPath);
            if (!parsedHybrid.SignatureValid || !parsedHybrid.IntegrityValid || parsedHybrid.Manifest.NodoRaiz != "NODO-01")
                throw new Exception("Verificación X.509 / SHA-256 del paquete .zip híbrido falló.");

            // 5. Simulación de paquete estricto de CentroCiberseguridad.Web (solo datos.enc, certificado.pem, manifest.json con RSA-PSS)
            // y payload AES-GCM empaquetado [12B nonce][16B tag][ciphertext]
            string extPass = "clave-aes-256-segura";
            byte[] extKey = SHA256.HashData(Encoding.UTF8.GetBytes(extPass));
            byte[] extNonce = RandomNumberGenerator.GetBytes(12);
            byte[] extCipher = new byte[sample.Length];
            byte[] extTag = new byte[16];
            using (var aesExt = new AesGcm(extKey, 16))
                aesExt.Encrypt(extNonce, sample, extCipher, extTag);

            byte[] packedDatosEnc = new byte[12 + 16 + extCipher.Length];
            Buffer.BlockCopy(extNonce, 0, packedDatosEnc, 0, 12);
            Buffer.BlockCopy(extTag, 0, packedDatosEnc, 12, 16);
            Buffer.BlockCopy(extCipher, 0, packedDatosEnc, 28, extCipher.Length);

            string extPacketId = Guid.NewGuid().ToString();
            string extSha = Convert.ToHexString(SHA256.HashData(packedDatosEnc));
            string extCanonical = $"{extPacketId}|AESGCM|{extSha}";
            string extSigPss = NodeCertificateService.SignDataPss(Encoding.UTF8.GetBytes(extCanonical));

            centroZipPath = Path.Combine(Path.GetTempPath(), $"CentroSim_{Guid.NewGuid():N}.zip");
            using (var zc = ZipFile.Open(centroZipPath, ZipArchiveMode.Create))
            {
                var mEntry = zc.CreateEntry("manifest.json");
                using (var sw = new StreamWriter(mEntry.Open(), new UTF8Encoding(false)))
                {
                    sw.Write(JsonSerializer.Serialize(new
                    {
                        version = "1.0",
                        packetId = extPacketId,
                        sourceNode = "NODO-02",
                        algorithmCode = "AESGCM",
                        originalFileName = "externo.txt",
                        originalExtension = ".txt",
                        encryptedSha256 = extSha,
                        signatureAlgorithm = "RSA-PSS-SHA256",
                        manifestSignatureBase64 = extSigPss
                    }));
                }

                var dEntry = zc.CreateEntry("datos.enc");
                using (var ds = dEntry.Open())
                    ds.Write(packedDatosEnc, 0, packedDatosEnc.Length);

                var pEntry = zc.CreateEntry("certificado.pem");
                using (var swP = new StreamWriter(pEntry.Open(), new UTF8Encoding(false)))
                    swP.Write(pem);
            }

            var parsedCentro = PacketZipService.ReadPacketZip(centroZipPath);
            if (!parsedCentro.SignatureValid || !parsedCentro.IntegrityValid || parsedCentro.Manifest.NodoRaiz != "NODO-02")
                throw new Exception("Falló la lectura o verificación RSA-PSS del paquete simulado CentroCiberseguridad.Web.");

            var decCentro = CryptoCatalog.GetStrategy("AESGCM").Decrypt(parsedCentro.PayloadBytes, extPass, "{}");
            if (!sample.SequenceEqual(decCentro.OutputBytes))
                throw new Exception("Falló el descifrado fallback de datos.enc empaquetado de CentroCiberseguridad.Web.");

            // 6. Modo Tolerante sin Firma X.509
            unsignedZipPath = Path.Combine(Path.GetTempPath(), $"UnsignedSim_{Guid.NewGuid():N}.zip");
            using (var zu = ZipFile.Open(unsignedZipPath, ZipArchiveMode.Create))
            {
                var mEntry = zu.CreateEntry("manifest.json");
                using (var sw = new StreamWriter(mEntry.Open(), new UTF8Encoding(false)))
                {
                    sw.Write(JsonSerializer.Serialize(new
                    {
                        packetId = Guid.NewGuid().ToString(),
                        algorithmCode = "AESGCM",
                        originalFileName = "sin_firma.txt"
                    }));
                }
                var dEntry = zu.CreateEntry("datos.enc");
                using (var ds = dEntry.Open())
                    ds.Write(packedDatosEnc, 0, packedDatosEnc.Length);
            }

            var parsedUnsigned = PacketZipService.ReadPacketZip(unsignedZipPath);
            if (parsedUnsigned.HasSignature || parsedUnsigned.SignatureValid || !parsedUnsigned.IntegrityValid)
                throw new Exception("El modo tolerante sin firma X.509 no reportó el estado esperado.");

            // 7. Descarga Automática de Archivos Binarios/Multimedia
            byte[] fakePdf = new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37, 0x0A };
            autoDownloadedBinaryPath = FormDashboard.SaveDecryptedBinaryAutomatically(fakePdf, "documento_prueba.pdf", ".pdf");
            if (!File.Exists(autoDownloadedBinaryPath) || !fakePdf.SequenceEqual(File.ReadAllBytes(autoDownloadedBinaryPath)))
                throw new Exception("Falló la descarga automática de archivos binarios/multimedia.");

            Console.WriteLine($"SELFTEST_OK: Node={NodeRuntimeState.CurrentNodeId}, EmptyDB=OK, PBKDF2=OK, DPAPI_X509=OK, HybridZIP=OK, CentroCompat=OK, TolerantUnsigned=OK, AutoDownloadBinary=OK, Algorithms={passed}/21");
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
            TryDeleteFile(hybridZipPath);
            TryDeleteFile(centroZipPath);
            TryDeleteFile(unsignedZipPath);
            TryDeleteFile(autoDownloadedBinaryPath);
        }
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

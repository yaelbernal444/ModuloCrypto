using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Forms;
using System.Text;
using System.Windows.Forms;

namespace ModuloCrypto;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
            return RunSelfTest();

        ApplicationConfiguration.Initialize();

        // 1. Inicializar SQLite (ModuloCrypto.db) con EnsureCreated()
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

        // 2. Inicializar Certificado X.509 del Nodo
        try
        {
            NodeCertificateService.Initialize();
        }
        catch
        {
            NodeRuntimeState.CertificateActive = false;
        }

        // 3. Arrancar servidor ASP.NET Core Minimal API embebido en http://0.0.0.0:5000
        var apiHost = new ApiHostService();
        apiHost.StartAsync(5000).GetAwaiter().GetResult();

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

    private static int RunSelfTest()
    {
        try
        {
            AppDbContext.InitializeDatabase();
            var admin = AuthService.Authenticate("admin", "admin123")
                ?? throw new Exception("Fallo autenticación admin en SQLite.");

            NodeCertificateService.Initialize();
            byte[] sample = Encoding.UTF8.GetBytes("ModuloCrypto-SelfTest-Payload-2026-TorMesh!");
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

            // Verificar empaquetado .ZIP + firma X.509 + ciclo bidireccional (Inicio -> Intermedio -> Final)
            var aesRes = CryptoCatalog.GetStrategy("AESGCM").Encrypt(sample);
            string origHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(aesRes.OutputBytes));
            string rootSig = NodeCertificateService.SignPayload(Encoding.ASCII.GetBytes(origHash));
            string rootCert = NodeCertificateService.ExportPublicCertBase64();

            var rec = new RegistroCifrado
            {
                UsuarioId = admin.Id,
                PacketId = Guid.NewGuid().ToString(),
                NombreArchivo = "test.txt",
                Extension = ".txt",
                BytesCifrados = Convert.ToBase64String(aesRes.OutputBytes),
                AlgoritmoCodigo = "AESGCM",
                ParametrosPublicosJson = aesRes.PublicParametersJson,
                LlaveSecretaBase64 = aesRes.SecretKeyBase64,
                LinkDescifradoRemoto = NodeRuntimeState.BuildRemoteDecryptUrl("test"),
                NodoRaiz = "NODO-01",
                FirmaRaizBase64 = rootSig,
                RutaSaltosJson = "[\"NODO-01\"]",
                Origen = "Local"
            };
            string zip = PacketZipService.CreatePacketZip(rec, aesRes.OutputBytes, preservedRootCertBase64: rootCert, preservedOriginalHashHex: origHash);
            var parsed = PacketZipService.ReadPacketZip(zip);
            if (!parsed.SignatureValid || !parsed.IntegrityValid || parsed.Manifest.NodoRaiz != "NODO-01")
                throw new Exception("Verificación X.509 / SHA-256 de paquete .zip falló.");
            File.Delete(zip);

            Console.WriteLine($"SELFTEST_OK: Node={NodeRuntimeState.CurrentNodeId}, User={admin.NombreCompleto}, SQLite=OK, X509=OK, ZIP=OK, Algorithms={passed}/21");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"SELFTEST_FAIL: {ex}");
            return 1;
        }
    }
}

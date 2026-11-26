using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.V1;

/// <summary>
/// Empaquetado híbrido de 5 archivos de la Versión 1.0:
/// manifest.json, datos.enc, payload.bin, certificado.pem y root_cert.cer.
/// Soporta lectura tolerante sin firma y verificación dual RSA-PSS / PKCS#1.
/// </summary>
public static class V1PacketZipService
{
    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions ReadJsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static string CreatePacketZip(
        RegistroCifrado registro,
        byte[] cipherBytes,
        List<string> hopRoute,
        string? rootSignatureOverride = null,
        string? rootCertBase64Override = null,
        string? destinationPath = null)
    {
        string outDir = Path.Combine(AppContext.BaseDirectory, "OutgoingPackets");
        Directory.CreateDirectory(outDir);

        string sha256Upper = Convert.ToHexString(SHA256.HashData(cipherBytes));
        string sha256Lower = sha256Upper.ToLowerInvariant();
        string sha8 = sha256Upper.Length >= 8 ? sha256Upper[..8] : sha256Upper;
        string timestampFile = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");

        string defaultFileName = $"{NodeRuntimeState.CurrentNodeId}_{registro.AlgoritmoCodigo}_{timestampFile}_{sha8}.zip";
        string zipPath = destinationPath ?? Path.Combine(outDir, defaultFileName);

        string certBase64 = rootCertBase64Override ?? V1CertificateService.ExportPublicCertBase64();
        string certPem = V1CertificateService.ExportPublicCertPem();
        string certThumb = V1CertificateService.GetThumbprintSha256Hex();
        string signaturePkcs1 = rootSignatureOverride ?? registro.FirmaRaizBase64;
        if (string.IsNullOrEmpty(signaturePkcs1))
            signaturePkcs1 = V1CertificateService.SignPayload(cipherBytes);

        string canonicalString = $"{registro.PacketId}|{registro.AlgoritmoCodigo}|{sha256Lower}";
        string manifestSigPss = V1CertificateService.SignDataPss(Encoding.UTF8.GetBytes(canonicalString));

        JsonElement? pubElement = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(registro.ParametrosPublicosJson))
            {
                using var doc = JsonDocument.Parse(registro.ParametrosPublicosJson);
                pubElement = doc.RootElement.Clone();
            }
        }
        catch { }

        string algName = CryptoCatalog.IsOfficialCode(registro.AlgoritmoCodigo)
            ? CryptoCatalog.GetStrategy(registro.AlgoritmoCodigo).Info.DisplayName
            : registro.AlgoritmoCodigo;

        var manifest = new V1PacketManifest
        {
            Version = "1.0",
            PacketId = registro.PacketId,
            AlgoritmoCodigo = registro.AlgoritmoCodigo,
            AlgorithmName = algName,
            NombreArchivo = registro.NombreArchivo,
            Extension = registro.Extension,
            OriginalSizeBytes = cipherBytes.Length,
            PayloadMode = DetectPayloadMode(registro.Extension),
            ParametrosPublicosJson = registro.ParametrosPublicosJson,
            PublicParameters = pubElement,
            LinkDescifradoRemoto = registro.LinkDescifradoRemoto,
            NodoRaiz = registro.NodoRaiz,
            SourceIp = NodeRuntimeState.LocalIpAddress,
            FirmaRaizBase64 = signaturePkcs1,
            CertificadoRaizBase64 = certBase64,
            CertificateThumbprintSha256 = certThumb,
            SignatureAlgorithm = "RSA-PSS-SHA256",
            ManifestSignatureBase64 = manifestSigPss,
            RutaSaltos = hopRoute,
            PayloadSha256 = sha256Lower,
            OriginalHashSha256 = sha256Upper,
            TimestampUtc = DateTime.UtcNow
        };

        if (File.Exists(zipPath)) File.Delete(zipPath);

        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            // 1. manifest.json
            var manifestEntry = archive.CreateEntry("manifest.json");
            using (var sw = new StreamWriter(manifestEntry.Open(), Encoding.UTF8))
                sw.Write(JsonSerializer.Serialize(manifest, PrettyJson));

            // 2. datos.enc
            var datosEntry = archive.CreateEntry("datos.enc");
            using (var ds = datosEntry.Open())
                ds.Write(cipherBytes, 0, cipherBytes.Length);

            // 3. payload.bin
            var payloadEntry = archive.CreateEntry("payload.bin");
            using (var ps = payloadEntry.Open())
                ps.Write(cipherBytes, 0, cipherBytes.Length);

            // 4. certificado.pem
            var pemEntry = archive.CreateEntry("certificado.pem");
            using (var swPem = new StreamWriter(pemEntry.Open(), Encoding.UTF8))
                swPem.Write(certPem);

            // 5. root_cert.cer
            if (!string.IsNullOrEmpty(certBase64))
            {
                var certEntry = archive.CreateEntry("root_cert.cer");
                using var cs = certEntry.Open();
                byte[] certBytes = Convert.FromBase64String(certBase64);
                cs.Write(certBytes, 0, certBytes.Length);
            }
        }

        return zipPath;
    }

    private static string DetectPayloadMode(string? ext)
    {
        string e = (ext ?? "").ToLowerInvariant();
        if (e is ".png" or ".bmp" or ".jpg" or ".jpeg") return "image";
        if (e is ".txt" or ".json" or ".csv" or ".xml" or ".md") return "text";
        return "file";
    }

    public static V1ParsedZipPacket ReadPacketZip(string zipPath)
    {
        using var archive = ZipFile.OpenRead(zipPath);

        var manifestEntry = archive.GetEntry("manifest.json")
                            ?? archive.Entries.FirstOrDefault(e => e.Name.Equals("manifest.json", StringComparison.OrdinalIgnoreCase))
                            ?? throw new InvalidDataException("El paquete .zip no contiene manifest.json.");

        V1PacketManifest manifest;
        using (var sr = new StreamReader(manifestEntry.Open(), Encoding.UTF8))
        {
            string json = sr.ReadToEnd();
            manifest = JsonSerializer.Deserialize<V1PacketManifest>(json, ReadJsonOpts) ?? new V1PacketManifest();
        }

        var payloadEntry = archive.Entries.FirstOrDefault(e =>
                               e.FullName.Equals("datos.enc", StringComparison.OrdinalIgnoreCase) ||
                               e.FullName.Equals("payload.bin", StringComparison.OrdinalIgnoreCase) ||
                               e.FullName.Equals("resultado.enc", StringComparison.OrdinalIgnoreCase))
                           ?? archive.Entries.FirstOrDefault(e =>
                               !e.Name.Equals("manifest.json", StringComparison.OrdinalIgnoreCase) &&
                               !e.Name.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) &&
                               !e.Name.EndsWith(".cer", StringComparison.OrdinalIgnoreCase) &&
                               !e.Name.EndsWith(".crt", StringComparison.OrdinalIgnoreCase))
                           ?? throw new InvalidDataException("El paquete .zip no contiene datos.enc ni payload.bin.");

        byte[] payload;
        using (var ms = new MemoryStream())
        {
            using var es = payloadEntry.Open();
            es.CopyTo(ms);
            payload = ms.ToArray();
        }

        if ((string.IsNullOrWhiteSpace(manifest.ParametrosPublicosJson) || manifest.ParametrosPublicosJson == "{}") &&
            manifest.PublicParameters.HasValue &&
            manifest.PublicParameters.Value.ValueKind is JsonValueKind.Object or JsonValueKind.String)
        {
            manifest.ParametrosPublicosJson = manifest.PublicParameters.Value.ValueKind == JsonValueKind.String
                ? (manifest.PublicParameters.Value.GetString() ?? "{}")
                : manifest.PublicParameters.Value.GetRawText();
        }

        if (string.IsNullOrWhiteSpace(manifest.FirmaRaizBase64) && !string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64))
            manifest.FirmaRaizBase64 = manifest.ManifestSignatureBase64;

        if (manifest.RutaSaltos == null || manifest.RutaSaltos.Count == 0)
            manifest.RutaSaltos = new List<string> { manifest.NodoRaiz };

        string certSource = manifest.CertificadoRaizBase64 ?? string.Empty;
        var pemEntry = archive.Entries.FirstOrDefault(e => e.Name.Equals("certificado.pem", StringComparison.OrdinalIgnoreCase));
        if (pemEntry != null)
        {
            using var sr = new StreamReader(pemEntry.Open(), Encoding.UTF8);
            string pemText = sr.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(pemText))
            {
                certSource = pemText;
                try
                {
                    using var cert = V1CertificateService.LoadCertificateFromPemOrBase64(pemText);
                    manifest.CertificadoRaizBase64 = Convert.ToBase64String(cert.Export(
                        System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
                }
                catch { }
            }
        }
        else if (string.IsNullOrWhiteSpace(certSource))
        {
            var cerEntry = archive.Entries.FirstOrDefault(e => e.Name.Equals("root_cert.cer", StringComparison.OrdinalIgnoreCase));
            if (cerEntry != null)
            {
                using var ms = new MemoryStream();
                using var cs = cerEntry.Open();
                cs.CopyTo(ms);
                certSource = Convert.ToBase64String(ms.ToArray());
                manifest.CertificadoRaizBase64 = certSource;
            }
        }

        string computedSha256 = Convert.ToHexString(SHA256.HashData(payload));
        string declaredSha = !string.IsNullOrWhiteSpace(manifest.PayloadSha256) ? manifest.PayloadSha256 : computedSha256;
        bool hashValid = string.Equals(declaredSha, computedSha256, StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(manifest.PayloadSha256))
            manifest.PayloadSha256 = computedSha256;

        bool hasSignature = !string.IsNullOrWhiteSpace(certSource) &&
                            (!string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64) ||
                             !string.IsNullOrWhiteSpace(manifest.FirmaRaizBase64));

        bool sigValid = false;
        if (hasSignature)
        {
            if (!string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64))
            {
                string canonicalUpper = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha.ToUpperInvariant()}";
                string canonicalLower = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha.ToLowerInvariant()}";
                string canonicalRaw = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha}";

                sigValid =
                    V1CertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalRaw), manifest.ManifestSignatureBase64, certSource) ||
                    V1CertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalUpper), manifest.ManifestSignatureBase64, certSource) ||
                    V1CertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalLower), manifest.ManifestSignatureBase64, certSource) ||
                    V1CertificateService.VerifyWithPem(payload, manifest.ManifestSignatureBase64, certSource);
            }

            if (!sigValid && !string.IsNullOrWhiteSpace(manifest.FirmaRaizBase64))
            {
                sigValid = V1CertificateService.VerifyWithPem(payload, manifest.FirmaRaizBase64, certSource);

                if (!sigValid && !string.IsNullOrWhiteSpace(manifest.OriginalHashSha256))
                {
                    sigValid = V1CertificateService.VerifyWithPem(
                        Encoding.ASCII.GetBytes(manifest.OriginalHashSha256),
                        manifest.FirmaRaizBase64,
                        certSource);
                }
            }
        }

        return new V1ParsedZipPacket
        {
            Manifest = manifest,
            PayloadBytes = payload,
            HasSignature = hasSignature,
            SignatureValid = sigValid,
            IntegrityValid = hashValid
        };
    }

    public static List<string> TryDeserializeHops(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
}

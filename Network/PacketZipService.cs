using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network;

public sealed class ParsedZipPacket
{
    public PacketManifest Manifest { get; init; } = new();
    public byte[] PayloadBytes { get; init; } = Array.Empty<byte>();
    public bool HasSignature { get; init; }
    public bool SignatureValid { get; init; }
    public bool IntegrityValid { get; init; }
}

/// <summary>
/// Empaqueta y desempaqueta archivos .zip en Formato Híbrido Universal compatible con ModuloCrypto y CentroCiberseguridad.Web.
/// Incluye manifest.json, datos.enc, payload.bin, certificado.pem y root_cert.cer. Soporta modo tolerante sin firma X.509.
/// </summary>
public static class PacketZipService
{
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    public static string CreatePacketZip(
        RegistroCifrado registro,
        byte[] cipherBytes,
        List<string>? customHops = null,
        string? destinationPath = null,
        string? preservedRootCertBase64 = null,
        string? preservedOriginalHashHex = null)
    {
        string outDir = Path.Combine(AppContext.BaseDirectory, "OutgoingPackets");
        Directory.CreateDirectory(outDir);

        string sha256Hex = Convert.ToHexString(SHA256.HashData(cipherBytes));
        string sha8 = sha256Hex.Length >= 8 ? sha256Hex[..8] : sha256Hex;
        string cleanNode = (string.IsNullOrWhiteSpace(registro.NodoRaiz) ? NodeRuntimeState.CurrentNodeId : registro.NodoRaiz)
            .Replace("-", "")
            .ToUpperInvariant();
        string cleanAlg = registro.AlgoritmoCodigo.Trim().ToUpperInvariant();

        string defaultFileName = $"{cleanNode}_{cleanAlg}_{DateTime.Now:yyyyMMdd_HHmmss}_{sha8}.zip";
        string zipPath = destinationPath ?? Path.Combine(outDir, defaultFileName);

        var hops = customHops ?? TryDeserializeHops(registro.RutaSaltosJson);
        if (hops.Count == 0) hops.Add(registro.NodoRaiz);

        string originalHashHex = string.IsNullOrWhiteSpace(preservedOriginalHashHex)
            ? sha256Hex
            : preservedOriginalHashHex;

        string certBase64 = string.IsNullOrWhiteSpace(preservedRootCertBase64)
            ? NodeCertificateService.ExportPublicCertBase64()
            : preservedRootCertBase64;

        string certPem;
        try
        {
            using var certObj = NodeCertificateService.LoadCertificateFromPemOrBase64(certBase64);
            certPem = certObj.ExportCertificatePem();
        }
        catch
        {
            certPem = NodeCertificateService.ExportPublicCertPem();
        }

        // Firma canónica de manifiesto para CentroCiberseguridad.Web: "{PacketId}|{AlgoritmoCodigo}|{sha256Hex}"
        string canonicalManifest = $"{registro.PacketId}|{cleanAlg}|{sha256Hex}";
        string manifestSignaturePss = NodeCertificateService.SignDataPss(Encoding.UTF8.GetBytes(canonicalManifest));

        // Firma de payload (RSA-PSS-SHA256)
        string rootSignature = string.IsNullOrWhiteSpace(registro.FirmaRaizBase64)
            ? NodeCertificateService.SignDataPss(cipherBytes)
            : registro.FirmaRaizBase64;

        string algDisplayName = CryptoCatalog.IsOfficialCode(cleanAlg)
            ? CryptoCatalog.GetStrategy(cleanAlg).Info.DisplayName
            : cleanAlg;

        JsonElement? pubParamsElem = null;
        if (!string.IsNullOrWhiteSpace(registro.ParametrosPublicosJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(registro.ParametrosPublicosJson);
                pubParamsElem = doc.RootElement.Clone();
            }
            catch { }
        }

        var manifest = new PacketManifest
        {
            Version = "1.0",
            PacketId = registro.PacketId,
            AlgoritmoCodigo = cleanAlg,
            AlgorithmCode = cleanAlg,
            AlgorithmName = algDisplayName,
            NombreArchivo = registro.NombreArchivo,
            OriginalFileName = registro.NombreArchivo,
            Extension = registro.Extension,
            OriginalExtension = registro.Extension,
            OriginalSizeBytes = cipherBytes.Length,
            PayloadMode = "file",
            ParametrosPublicosJson = string.IsNullOrWhiteSpace(registro.ParametrosPublicosJson) ? "{}" : registro.ParametrosPublicosJson,
            PublicParameters = pubParamsElem,
            LinkDescifradoRemoto = registro.LinkDescifradoRemoto,
            NodoRaiz = registro.NodoRaiz,
            SourceNode = registro.NodoRaiz,
            SourceIp = NodeRuntimeState.LocalIpAddress,
            FirmaRaizBase64 = rootSignature,
            CertificadoRaizBase64 = certBase64,
            CertificateThumbprintSha256 = NodeCertificateService.GetThumbprintSha256Hex(),
            SignatureAlgorithm = "RSA-PSS-SHA256",
            ManifestSignatureBase64 = manifestSignaturePss,
            RutaSaltos = hops,
            PayloadSha256 = sha256Hex,
            EncryptedSha256 = sha256Hex,
            OriginalHashSha256 = originalHashHex,
            TimestampUtc = DateTime.UtcNow
        };

        if (File.Exists(zipPath)) File.Delete(zipPath);

        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);

        // 1. manifest.json
        var manifestEntry = archive.CreateEntry("manifest.json");
        using (var sw = new StreamWriter(manifestEntry.Open(), new UTF8Encoding(false)))
            sw.Write(JsonSerializer.Serialize(manifest, PrettyJson));

        // 2. datos.enc (CentroCiberseguridad.Web)
        var datosEntry = archive.CreateEntry("datos.enc");
        using (var ds = datosEntry.Open())
            ds.Write(cipherBytes, 0, cipherBytes.Length);

        // 3. payload.bin (ModuloCrypto)
        var payloadEntry = archive.CreateEntry("payload.bin");
        using (var ps = payloadEntry.Open())
            ps.Write(cipherBytes, 0, cipherBytes.Length);

        // 4. certificado.pem (CentroCiberseguridad.Web)
        var pemEntry = archive.CreateEntry("certificado.pem");
        using (var swPem = new StreamWriter(pemEntry.Open(), new UTF8Encoding(false)))
            swPem.Write(certPem);

        // 5. root_cert.cer (ModuloCrypto)
        var certEntry = archive.CreateEntry("root_cert.cer");
        using (var cs = certEntry.Open())
        {
            byte[] certBytes = Convert.FromBase64String(certBase64);
            cs.Write(certBytes, 0, certBytes.Length);
        }

        return zipPath;
    }

    public static ParsedZipPacket ReadPacketZip(string zipPath)
    {
        using var archive = ZipFile.OpenRead(zipPath);

        var manifestEntry = archive.Entries.FirstOrDefault(e =>
            e.FullName.Equals("manifest.json", StringComparison.OrdinalIgnoreCase));

        var payloadEntry = archive.Entries.FirstOrDefault(e =>
            e.FullName.Equals("datos.enc", StringComparison.OrdinalIgnoreCase) ||
            e.FullName.Equals("payload.bin", StringComparison.OrdinalIgnoreCase))
            ?? archive.Entries.FirstOrDefault(e =>
                !e.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("El paquete .zip no contiene datos.enc ni payload.bin.");

        PacketManifest manifest;
        if (manifestEntry != null)
        {
            using var sr = new StreamReader(manifestEntry.Open(), Encoding.UTF8);
            string json = sr.ReadToEnd();
            manifest = JsonSerializer.Deserialize<PacketManifest>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new PacketManifest();
        }
        else
        {
            manifest = new PacketManifest
            {
                PacketId = Guid.NewGuid().ToString(),
                AlgoritmoCodigo = "AESGCM",
                NombreArchivo = payloadEntry.Name,
                Extension = Path.GetExtension(payloadEntry.Name),
                NodoRaiz = "NODO-EXT"
            };
        }

        byte[] payload;
        using (var ms = new MemoryStream())
        {
            payloadEntry.Open().CopyTo(ms);
            payload = ms.ToArray();
        }

        // Normalización de campos entre CentroCiberseguridad.Web y ModuloCrypto
        if (string.IsNullOrWhiteSpace(manifest.NodoRaiz))
            manifest.NodoRaiz = "NODO-EXT";

        if (string.IsNullOrWhiteSpace(manifest.NombreArchivo))
            manifest.NombreArchivo = "datos.enc";

        if (string.IsNullOrWhiteSpace(manifest.Extension))
            manifest.Extension = Path.GetExtension(manifest.NombreArchivo);
        if (string.IsNullOrWhiteSpace(manifest.Extension))
            manifest.Extension = ".bin";

        if ((string.IsNullOrWhiteSpace(manifest.ParametrosPublicosJson) || manifest.ParametrosPublicosJson == "{}")
            && manifest.PublicParameters.HasValue
            && manifest.PublicParameters.Value.ValueKind != JsonValueKind.Undefined
            && manifest.PublicParameters.Value.ValueKind != JsonValueKind.Null)
        {
            manifest.ParametrosPublicosJson = manifest.PublicParameters.Value.GetRawText();
        }

        if (string.IsNullOrWhiteSpace(manifest.FirmaRaizBase64) && !string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64))
            manifest.FirmaRaizBase64 = manifest.ManifestSignatureBase64;

        if (manifest.RutaSaltos == null || manifest.RutaSaltos.Count == 0)
            manifest.RutaSaltos = new List<string> { manifest.NodoRaiz };

        // Lectura tolerante de certificado desde certificado.pem, root_cert.cer o CertificadoRaizBase64
        string certSource = manifest.CertificadoRaizBase64 ?? string.Empty;
        var pemEntry = archive.Entries.FirstOrDefault(e => e.FullName.Equals("certificado.pem", StringComparison.OrdinalIgnoreCase));
        if (pemEntry != null)
        {
            using var sr = new StreamReader(pemEntry.Open(), Encoding.UTF8);
            string pemText = sr.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(pemText))
            {
                certSource = pemText;
                try
                {
                    using var cert = NodeCertificateService.LoadCertificateFromPemOrBase64(pemText);
                    manifest.CertificadoRaizBase64 = Convert.ToBase64String(cert.Export(
                        System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
                }
                catch { }
            }
        }
        else if (string.IsNullOrWhiteSpace(certSource))
        {
            var cerEntry = archive.Entries.FirstOrDefault(e => e.FullName.Equals("root_cert.cer", StringComparison.OrdinalIgnoreCase));
            if (cerEntry != null)
            {
                using var ms = new MemoryStream();
                cerEntry.Open().CopyTo(ms);
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

        // Modo Tolerante: si no hay certificado o firma, no lanza excepción; simplemente marca SignatureValid = false
        bool sigValid = false;
        if (hasSignature)
        {
            if (!string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64))
            {
                string canonicalUpper = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha.ToUpperInvariant()}";
                string canonicalLower = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha.ToLowerInvariant()}";
                string canonicalRaw = $"{manifest.PacketId}|{manifest.AlgoritmoCodigo}|{declaredSha}";

                sigValid =
                    NodeCertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalRaw), manifest.ManifestSignatureBase64, certSource) ||
                    NodeCertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalUpper), manifest.ManifestSignatureBase64, certSource) ||
                    NodeCertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonicalLower), manifest.ManifestSignatureBase64, certSource) ||
                    NodeCertificateService.VerifyWithPem(payload, manifest.ManifestSignatureBase64, certSource);
            }

            if (!sigValid && !string.IsNullOrWhiteSpace(manifest.FirmaRaizBase64))
            {
                sigValid = NodeCertificateService.VerifyWithPem(payload, manifest.FirmaRaizBase64, certSource);

                if (!sigValid && !string.IsNullOrWhiteSpace(manifest.OriginalHashSha256))
                {
                    sigValid = NodeCertificateService.VerifyWithPem(
                        Encoding.ASCII.GetBytes(manifest.OriginalHashSha256),
                        manifest.FirmaRaizBase64,
                        certSource);
                }
            }
        }

        return new ParsedZipPacket
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

using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ModuloCrypto.Network;

public sealed class ParsedZipPacket
{
    public PacketManifest Manifest { get; init; } = new();
    public byte[] PayloadBytes { get; init; } = Array.Empty<byte>();
    public string CertificatePem { get; init; } = string.Empty;
    public bool SignatureValid { get; init; }
    public bool IntegrityValid { get; init; }
}

/// <summary>
/// Empaqueta, valida y reempaqueta archivos .zip cumpliendo estrictamente el Estándar v2.0 (Sección 7, 8 y 9):
/// - Exactamente 3 archivos planos en raíz: (datos.enc | resultado.enc), certificado.pem, manifest.json
/// - Protección Anti-ZIP-Bomb (50 MB comprimido -> 413 E-SIZE, 200 MB descomprimido / ratio 100:1 -> 400 E-ZIP-BOMB)
/// - Firma canónica de 11 campos con RSA-PSS-SHA256
/// - Soporte multipart (part-01.bin..part-64.bin) y RepackageForForwarding (Sección 9.6).
/// </summary>
public static class PacketZipService
{
    public const long MaxCompressedZipBytes = 50L * 1024L * 1024L;     // 50 MB
    public const long MaxUncompressedTotalBytes = 200L * 1024L * 1024L; // 200 MB
    public const double MaxCompressionRatio = 100.0;                    // 100:1
    public const int MaxMultipartEntries = 64;

    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly JsonSerializerOptions ReadJsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static string CreatePacketZip(
        RegistroCifrado registro,
        byte[] cipherBytes,
        string packetType = "package",
        string operation = "forward",
        string? requestId = null,
        string? producerNode = null,
        string? destinationPath = null,
        List<ManifestPartInfo>? multipartParts = null)
    {
        string outDir = Path.Combine(AppContext.BaseDirectory, "OutgoingPackets");
        Directory.CreateDirectory(outDir);

        bool isResult = string.Equals(packetType, "result", StringComparison.OrdinalIgnoreCase);
        string normalizedPacketType = isResult ? "result" : "package";
        string payloadEntryName = isResult ? "resultado.enc" : "datos.enc";

        DateTime utcNow = DateTime.UtcNow;
        string timestampIso = utcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string timestampFile = utcNow.ToString("yyyyMMdd_HHmmss");

        string sha256FullLower = Convert.ToHexString(SHA256.HashData(cipherBytes)).ToLowerInvariant();
        string sha8Upper = sha256FullLower[..8].ToUpperInvariant();

        string sourceNode = NodeRuntimeState.CurrentNodeId;
        string actualProducer = !string.IsNullOrWhiteSpace(producerNode)
            ? producerNode
            : (!string.IsNullOrWhiteSpace(registro.NodoRaiz) && NodeRuntimeState.IsValidNodeId(registro.NodoRaiz)
                ? registro.NodoRaiz
                : sourceNode);

        string cleanAlg = registro.AlgoritmoCodigo.Trim().ToUpperInvariant();
        string prefix = isResult ? $"RES_{sourceNode}" : sourceNode;
        string defaultFileName = $"{prefix}_{cleanAlg}_{timestampFile}_{sha8Upper}.zip";
        string zipPath = destinationPath ?? Path.Combine(outDir, defaultFileName);

        string packetId = Guid.TryParse(registro.PacketId, out Guid parsedGuid)
            ? parsedGuid.ToString("D").ToLowerInvariant()
            : Guid.NewGuid().ToString("D").ToLowerInvariant();

        var publicParamsDict = ParseFlatPublicParameters(registro.ParametrosPublicosJson);
        string pubParamsSha256Lower = PacketManifest.ComputePublicParametersSha256(publicParamsDict);

        string certPem = NodeCertificateService.ExportPublicCertPem();
        string certThumbUpper = NodeCertificateService.GetThumbprintSha256Hex();

        int algId = CryptoCatalog.GetAlgorithmId(cleanAlg);
        string algName = CryptoCatalog.IsOfficialCode(cleanAlg)
            ? CryptoCatalog.GetStrategy(cleanAlg).Info.DisplayName
            : cleanAlg;

        string payloadMode = multipartParts is { Count: > 0 }
            ? "multipart"
            : DetectPayloadMode(registro.Extension);

        var manifest = new PacketManifest
        {
            Version = "2.0",
            PacketType = normalizedPacketType,
            PacketId = packetId,
            RequestId = string.IsNullOrWhiteSpace(requestId) ? null : requestId.Trim().ToLowerInvariant(),
            SourceNode = sourceNode,
            SourceTeam = NodeRuntimeState.TeamNumber,
            SourceIp = NodeRuntimeState.SourceEndpoint,
            ProducerNode = actualProducer,
            TimestampUtc = timestampIso,
            AlgorithmId = algId,
            AlgorithmCode = cleanAlg,
            AlgorithmName = algName,
            Operation = string.Equals(operation, "inverse", StringComparison.OrdinalIgnoreCase) ? "inverse" : "forward",
            OperationName = string.Equals(operation, "inverse", StringComparison.OrdinalIgnoreCase) ? "Descifrado" : "Cifrado",
            PayloadMode = payloadMode,
            OriginalFileName = string.IsNullOrWhiteSpace(registro.NombreArchivo) ? "archivo.bin" : registro.NombreArchivo,
            OriginalExtension = string.IsNullOrWhiteSpace(registro.Extension) ? ".bin" : registro.Extension,
            OriginalSizeBytes = cipherBytes.Length,
            ContentType = GuessContentType(registro.Extension),
            EncryptedSha256 = sha256FullLower,
            EncryptedSizeBytes = cipherBytes.Length,
            Parts = multipartParts,
            KeyRef = new ManifestKeyRef
            {
                KeyId = packetId,
                OwnerNode = actualProducer
            },
            PublicParameters = publicParamsDict,
            PublicParametersSha256 = pubParamsSha256Lower,
            Verification = isResult ? new ManifestVerification { Valid = true, Detail = "OK" } : null,
            ResultEnvelope = isResult
                ? new CcEnvelope
                {
                    AlgorithmCode = cleanAlg,
                    Operation = operation,
                    ProducerNode = actualProducer,
                    KeyRef = new ManifestKeyRef { KeyId = packetId, OwnerNode = actualProducer },
                    PublicParameters = publicParamsDict
                }
                : null,
            CertificateThumbprintSha256 = certThumbUpper,
            SignatureAlgorithm = "RSA-PSS-SHA256"
        };

        // Firma canónica de 11 campos con RSA-PSS-SHA256
        string canonical11 = manifest.BuildCanonicalSigningString();
        manifest.ManifestSignatureBase64 = NodeCertificateService.SignDataPss(Encoding.UTF8.GetBytes(canonical11));

        WriteStrictThreeFileZip(zipPath, payloadEntryName, cipherBytes, certPem, manifest);
        return zipPath;
    }

    /// <summary>
    /// Sección 9.6: Reempaquetado para Reenvío (Forwarding).
    /// Conserva intactos datos.enc, publicParameters, keyRef, producerNode y algorithmCode;
    /// genera nuevo packetId (UUID v4 minúsculas) y timestampUtc; coloca sourceNode = EQ01,
    /// certificado.pem propio y re-firma los 11 campos del manifiesto.
    /// </summary>
    public static string RepackageForForwarding(string sourceZipPath, string? destinationPath = null)
    {
        var parsed = ReadPacketZip(sourceZipPath);
        var orig = parsed.Manifest;

        if (!string.Equals(orig.PacketType, "package", StringComparison.OrdinalIgnoreCase))
            throw new PacketValidationException("E-ZIP-STRUCTURE", 400, "Solo se pueden reenviar paquetes de tipo 'package' (datos.enc).");

        DateTime utcNow = DateTime.UtcNow;
        string timestampIso = utcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string timestampFile = utcNow.ToString("yyyyMMdd_HHmmss");

        string sha256Lower = Convert.ToHexString(SHA256.HashData(parsed.PayloadBytes)).ToLowerInvariant();
        string sha8Upper = sha256Lower[..8].ToUpperInvariant();

        string sourceNode = NodeRuntimeState.CurrentNodeId;
        string cleanAlg = orig.AlgorithmCode.Trim().ToUpperInvariant();

        string outDir = Path.Combine(AppContext.BaseDirectory, "OutgoingPackets");
        Directory.CreateDirectory(outDir);
        string zipPath = destinationPath ?? Path.Combine(outDir, $"{sourceNode}_{cleanAlg}_{timestampFile}_{sha8Upper}.zip");

        string certPem = NodeCertificateService.ExportPublicCertPem();
        string certThumbUpper = NodeCertificateService.GetThumbprintSha256Hex();
        string pubParamsSha256Lower = PacketManifest.ComputePublicParametersSha256(orig.PublicParameters);

        var forwardedManifest = new PacketManifest
        {
            Version = "2.0",
            PacketType = "package",
            PacketId = Guid.NewGuid().ToString("D").ToLowerInvariant(),
            RequestId = orig.RequestId,
            SourceNode = sourceNode,
            SourceTeam = NodeRuntimeState.TeamNumber,
            SourceIp = NodeRuntimeState.SourceEndpoint,
            ProducerNode = orig.ProducerNode,
            TimestampUtc = timestampIso,
            AlgorithmId = orig.AlgorithmId,
            AlgorithmCode = cleanAlg,
            AlgorithmName = orig.AlgorithmName,
            Operation = orig.Operation,
            OperationName = orig.OperationName,
            PayloadMode = orig.PayloadMode,
            OriginalFileName = orig.OriginalFileName,
            OriginalExtension = orig.OriginalExtension,
            OriginalSizeBytes = orig.OriginalSizeBytes,
            ContentType = orig.ContentType,
            EncryptedSha256 = sha256Lower,
            EncryptedSizeBytes = parsed.PayloadBytes.Length,
            Parts = orig.Parts,
            KeyRef = orig.KeyRef,
            PublicParameters = new Dictionary<string, string>(orig.PublicParameters, StringComparer.Ordinal),
            PublicParametersSha256 = pubParamsSha256Lower,
            Verification = orig.Verification,
            ResultEnvelope = orig.ResultEnvelope,
            CertificateThumbprintSha256 = certThumbUpper,
            SignatureAlgorithm = "RSA-PSS-SHA256"
        };

        string canonical11 = forwardedManifest.BuildCanonicalSigningString();
        forwardedManifest.ManifestSignatureBase64 = NodeCertificateService.SignDataPss(Encoding.UTF8.GetBytes(canonical11));

        WriteStrictThreeFileZip(zipPath, "datos.enc", parsed.PayloadBytes, certPem, forwardedManifest);
        return zipPath;
    }

    private static void WriteStrictThreeFileZip(
        string zipPath,
        string payloadEntryName,
        byte[] payloadBytes,
        string certPem,
        PacketManifest manifest)
    {
        if (File.Exists(zipPath)) File.Delete(zipPath);

        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);

        // 1. datos.enc o resultado.enc
        var dataEntry = archive.CreateEntry(payloadEntryName);
        using (var ds = dataEntry.Open())
            ds.Write(payloadBytes, 0, payloadBytes.Length);

        // 2. certificado.pem
        var pemEntry = archive.CreateEntry("certificado.pem");
        using (var swPem = new StreamWriter(pemEntry.Open(), new UTF8Encoding(false)))
            swPem.Write(certPem);

        // 3. manifest.json
        var manifestEntry = archive.CreateEntry("manifest.json");
        using (var swMan = new StreamWriter(manifestEntry.Open(), new UTF8Encoding(false)))
            swMan.Write(JsonSerializer.Serialize(manifest, PrettyJson));
    }

    /// <summary>
    /// Valida y lee un paquete .zip bajo las reglas estrictas del Estándar v2.0.
    /// Lanza PacketValidationException con el código y estatus HTTP oficial ante violaciones.
    /// </summary>
    public static ParsedZipPacket ReadPacketZip(string zipPath, bool enforceStrictSignature = true)
    {
        var fileInfo = new FileInfo(zipPath);
        if (!fileInfo.Exists)
            throw new PacketValidationException("E-ZIP-STRUCTURE", 400, "El archivo .zip no existe.");

        if (fileInfo.Length > MaxCompressedZipBytes)
            throw new PacketValidationException("E-SIZE", 413, $"El archivo .zip supera el máximo comprimido de 50 MB ({fileInfo.Length:N0} bytes).");

        using var archive = ZipFile.OpenRead(zipPath);

        // Regla estricta: exactamente 3 entradas planas en raíz
        if (archive.Entries.Count != 3)
        {
            throw new PacketValidationException(
                "E-ZIP-STRUCTURE",
                400,
                $"Estructura ZIP inválida: se requieren exactamente 3 archivos planos en raíz, pero el archivo contiene {archive.Entries.Count}.");
        }

        long totalUncompressed = 0;
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrWhiteSpace(entry.FullName) ||
                entry.FullName.Contains('/') ||
                entry.FullName.Contains('\\') ||
                entry.FullName.Contains("..") ||
                entry.FullName.StartsWith('.'))
            {
                throw new PacketValidationException(
                    "E-ZIP-STRUCTURE",
                    400,
                    $"Entrada ZIP prohibida o con subcarpeta/ruta inválida: '{entry.FullName}'.");
            }

            if (entry.Length < 0 || entry.Length > MaxUncompressedTotalBytes)
                throw new PacketValidationException("E-ZIP-BOMB", 400, $"Tamaño descomprimido excesivo en '{entry.FullName}'.");

            totalUncompressed += entry.Length;
            if (totalUncompressed > MaxUncompressedTotalBytes)
                throw new PacketValidationException("E-ZIP-BOMB", 400, "El tamaño total descomprimido supera el límite de 200 MB.");

            if (entry.CompressedLength > 0)
            {
                double ratio = (double)entry.Length / entry.CompressedLength;
                if (ratio > MaxCompressionRatio && entry.Length > 65536)
                {
                    throw new PacketValidationException(
                        "E-ZIP-BOMB",
                        400,
                        $"Razón de compresión sospechosa ({ratio:F1}:1 > 100:1) en '{entry.FullName}'.");
                }
            }
        }

        var manifestEntry = archive.GetEntry("manifest.json");
        var pemEntry = archive.GetEntry("certificado.pem");
        var datosEntry = archive.GetEntry("datos.enc");
        var resultadoEntry = archive.GetEntry("resultado.enc");

        if (manifestEntry == null || pemEntry == null || (datosEntry == null && resultadoEntry == null) || (datosEntry != null && resultadoEntry != null))
        {
            throw new PacketValidationException(
                "E-ZIP-STRUCTURE",
                400,
                "El paquete .zip debe contener exclusivamente { datos.enc | resultado.enc }, certificado.pem y manifest.json en la raíz.");
        }

        var payloadEntry = datosEntry ?? resultadoEntry!;
        string expectedPacketType = datosEntry != null ? "package" : "result";

        PacketManifest manifest;
        using (var sr = new StreamReader(manifestEntry.Open(), Encoding.UTF8))
        {
            string json = sr.ReadToEnd();
            manifest = JsonSerializer.Deserialize<PacketManifest>(json, ReadJsonOpts)
                ?? throw new PacketValidationException("E-MANIFEST-INVALID", 400, "No se pudo deserializar manifest.json.");
        }

        if (!string.Equals(manifest.PacketType, expectedPacketType, StringComparison.OrdinalIgnoreCase))
        {
            throw new PacketValidationException(
                "E-ZIP-STRUCTURE",
                400,
                $"Inconsistencia entre archivo '{payloadEntry.FullName}' y packetType='{manifest.PacketType}'.");
        }

        string certPem;
        using (var srPem = new StreamReader(pemEntry.Open(), Encoding.UTF8))
            certPem = srPem.ReadToEnd();

        if (string.IsNullOrWhiteSpace(certPem) || !certPem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            throw new PacketValidationException("E-CERT-INVALID", 400, "El archivo certificado.pem no contiene un certificado PEM válido.");

        byte[] payload = ReadStreamBounded(payloadEntry.Open(), MaxUncompressedTotalBytes);

        // Validar SHA-256 del payload en minúsculas con comparación en tiempo constante
        string computedPayloadSha256Lower = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        bool payloadHashOk = NodeCertificateService.FixedTimeEqualsHex(computedPayloadSha256Lower, manifest.EncryptedSha256);
        if (!payloadHashOk && enforceStrictSignature)
        {
            throw new PacketValidationException(
                "E-HASH-MISMATCH",
                400,
                "El hash SHA-256 de los datos cifrados no coincide con encryptedSha256 del manifiesto.");
        }

        // Validar SHA-256 canónico de publicParameters
        string computedPubParamsSha256Lower = PacketManifest.ComputePublicParametersSha256(manifest.PublicParameters);
        bool pubParamsHashOk = NodeCertificateService.FixedTimeEqualsHex(computedPubParamsSha256Lower, manifest.PublicParametersSha256);
        if (!pubParamsHashOk && enforceStrictSignature)
        {
            throw new PacketValidationException(
                "E-HASH-MISMATCH",
                400,
                "El hash canónico publicParametersSha256 no coincide con publicParameters.");
        }

        // Si es multipart, validar zip interno part-01.bin .. part-NN.bin
        if (string.Equals(manifest.PayloadMode, "multipart", StringComparison.OrdinalIgnoreCase))
        {
            ValidateMultipartInnerZip(payload, manifest.Parts);
        }

        // Validar certificado X.509 y firma RSA-PSS-SHA256 sobre los 11 campos canónicos
        using var cert = NodeCertificateService.LoadCertificateFromPemOrBase64(certPem);
        if (!NodeCertificateService.ValidateCertificateMetadata(
                cert,
                manifest.SourceNode,
                manifest.CertificateThumbprintSha256,
                out string certErr))
        {
            if (enforceStrictSignature)
                throw new PacketValidationException("E-CERT-INVALID", 400, certErr);
        }

        string canonical11 = manifest.BuildCanonicalSigningString();
        bool sigValid = string.Equals(manifest.SignatureAlgorithm, "RSA-PSS-SHA256", StringComparison.Ordinal) &&
                        NodeCertificateService.VerifyWithPem(Encoding.UTF8.GetBytes(canonical11), manifest.ManifestSignatureBase64, certPem);

        if (!sigValid && enforceStrictSignature)
        {
            throw new PacketValidationException(
                "E-SIGNATURE",
                400,
                "Firma digital RSA-PSS-SHA256 inválida sobre la cadena canónica de 11 campos.");
        }

        return new ParsedZipPacket
        {
            Manifest = manifest,
            PayloadBytes = payload,
            CertificatePem = certPem,
            SignatureValid = sigValid,
            IntegrityValid = payloadHashOk && pubParamsHashOk
        };
    }

    public static byte[] CreateMultipartInnerZip(IReadOnlyList<byte[]> parts, out List<ManifestPartInfo> manifestParts)
    {
        if (parts.Count == 0 || parts.Count > MaxMultipartEntries)
            throw new ArgumentOutOfRangeException(nameof(parts), $"El modo multipart requiere entre 1 y {MaxMultipartEntries} partes.");

        manifestParts = new List<ManifestPartInfo>(parts.Count);
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (int i = 0; i < parts.Count; i++)
            {
                string partName = $"part-{(i + 1):D2}.bin";
                byte[] partBytes = parts[i];
                string partSha = Convert.ToHexString(SHA256.HashData(partBytes)).ToLowerInvariant();

                var entry = archive.CreateEntry(partName);
                using (var es = entry.Open())
                    es.Write(partBytes, 0, partBytes.Length);

                manifestParts.Add(new ManifestPartInfo
                {
                    Name = partName,
                    SizeBytes = partBytes.Length,
                    Sha256 = partSha
                });
            }
        }
        return ms.ToArray();
    }

    private static void ValidateMultipartInnerZip(byte[] innerZipBytes, List<ManifestPartInfo>? declaredParts)
    {
        if (declaredParts == null || declaredParts.Count == 0 || declaredParts.Count > MaxMultipartEntries)
            throw new PacketValidationException("E-ZIP-STRUCTURE", 400, "El manifiesto multipart debe declarar entre 1 y 64 partes.");

        using var ms = new MemoryStream(innerZipBytes);
        using var innerArchive = new ZipArchive(ms, ZipArchiveMode.Read);

        if (innerArchive.Entries.Count != declaredParts.Count || innerArchive.Entries.Count > MaxMultipartEntries)
            throw new PacketValidationException("E-ZIP-STRUCTURE", 400, "El número de entradas en datos.enc multipart no coincide con manifest.parts.");

        long totalInner = 0;
        for (int i = 0; i < declaredParts.Count; i++)
        {
            string expectedName = $"part-{(i + 1):D2}.bin";
            var decl = declaredParts[i];
            if (!string.Equals(decl.Name, expectedName, StringComparison.Ordinal))
                throw new PacketValidationException("E-ZIP-STRUCTURE", 400, $"Nombre de parte multipart inválido: '{decl.Name}' (se esperaba '{expectedName}').");

            var entry = innerArchive.GetEntry(expectedName)
                ?? throw new PacketValidationException("E-ZIP-STRUCTURE", 400, $"Falta la entrada '{expectedName}' dentro de datos.enc multipart.");

            totalInner += entry.Length;
            if (totalInner > MaxUncompressedTotalBytes)
                throw new PacketValidationException("E-ZIP-BOMB", 400, "El contenido multipart descomprimido supera los 200 MB.");

            byte[] partBytes = ReadStreamBounded(entry.Open(), MaxUncompressedTotalBytes);
            if (partBytes.Length != decl.SizeBytes)
                throw new PacketValidationException("E-HASH-MISMATCH", 400, $"El tamaño de '{expectedName}' no coincide con manifest.parts.");

            string actualSha = Convert.ToHexString(SHA256.HashData(partBytes)).ToLowerInvariant();
            if (!NodeCertificateService.FixedTimeEqualsHex(actualSha, decl.Sha256))
                throw new PacketValidationException("E-HASH-MISMATCH", 400, $"El SHA-256 de '{expectedName}' no coincide con manifest.parts.");
        }
    }

    private static byte[] ReadStreamBounded(Stream stream, long maxBytes)
    {
        using (stream)
        using (var ms = new MemoryStream())
        {
            byte[] buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    throw new PacketValidationException("E-ZIP-BOMB", 400, "Flujo descomprimido excede el límite de seguridad de 200 MB.");
                ms.Write(buffer, 0, read);
            }
            return ms.ToArray();
        }
    }

    public static Dictionary<string, string> ParseFlatPublicParameters(string? json)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json)) return dict;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return dict;

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                string val = prop.Value.ValueKind switch
                {
                    JsonValueKind.String => prop.Value.GetString() ?? string.Empty,
                    JsonValueKind.Number => prop.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Null => string.Empty,
                    _ => prop.Value.GetRawText()
                };
                dict[prop.Name] = val;
            }
        }
        catch { }

        return dict;
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

    private static string DetectPayloadMode(string? ext)
    {
        string e = (ext ?? "").ToLowerInvariant();
        if (e is ".png" or ".bmp" or ".jpg" or ".jpeg") return "image";
        if (e is ".txt" or ".json" or ".csv" or ".xml" or ".md") return "text";
        return "file";
    }

    private static string GuessContentType(string? ext) => (ext ?? "").ToLowerInvariant() switch
    {
        ".txt" => "text/plain",
        ".json" => "application/json",
        ".png" => "image/png",
        ".bmp" => "image/bmp",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".pdf" => "application/pdf",
        ".mp4" => "video/mp4",
        _ => "application/octet-stream"
    };
}

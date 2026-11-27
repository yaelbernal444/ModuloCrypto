using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ModuloCrypto.Core.Contracts;

/// <summary>
/// Excepción tipada con código y estatus HTTP oficial del Estándar de Comunicación v2.0 (Anexo B).
/// </summary>
public sealed class PacketValidationException : Exception
{
    public string ErrorCode { get; }
    public int HttpStatusCode { get; }

    public PacketValidationException(string errorCode, int httpStatusCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
        HttpStatusCode = httpStatusCode;
    }
}

public static class V2FormatValidators
{
    private static readonly Regex NodeIdRegex = new("^EQ[0-9]{2}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex UuidV4LowerRegex = new("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex KeyIdRegex = new("^EQ[0-9]{2}-KEY-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex TimestampUtcRegex = new(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ThumbprintUpperRegex = new("^[0-9A-F]{64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Sha256LowerRegex = new("^[0-9a-f]{64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static bool IsValidNodeId(string? value) => !string.IsNullOrEmpty(value) && NodeIdRegex.IsMatch(value);
    public static bool IsValidUuidV4Lower(string? value) => !string.IsNullOrEmpty(value) && UuidV4LowerRegex.IsMatch(value);
    public static bool IsValidKeyId(string? value) => !string.IsNullOrEmpty(value) && KeyIdRegex.IsMatch(value);
    public static bool IsValidTimestampUtc(string? value) => !string.IsNullOrEmpty(value) && TimestampUtcRegex.IsMatch(value);
    public static bool IsValidThumbprintUpper(string? value) => !string.IsNullOrEmpty(value) && ThumbprintUpperRegex.IsMatch(value);
    public static bool IsValidSha256Lower(string? value) => !string.IsNullOrEmpty(value) && Sha256LowerRegex.IsMatch(value);

    public static string BuildKeyId(string ownerNode, string? uuidLower = null)
    {
        string node = IsValidNodeId(ownerNode) ? ownerNode : "EQ01";
        string uuid = IsValidUuidV4Lower(uuidLower)
            ? uuidLower!
            : Guid.NewGuid().ToString("D").ToLowerInvariant();
        return $"{node}-KEY-{uuid}";
    }
}

public sealed class ManifestPartInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("sizeBytes")]
    public long SizeBytes { get; set; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;
}

public sealed class ManifestKeyRef
{
    [JsonPropertyName("keyId")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("ownerNode")]
    public string OwnerNode { get; set; } = "EQ01";
}

public sealed class ManifestVerification
{
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    [JsonPropertyName("detail")]
    public string Detail { get; set; } = string.Empty;
}

/// <summary>
/// Sobre híbrido estandarizado CC-ENV-1 (Sección 8.3):
/// - CEK aleatoria de 32 bytes envuelta con RSA-OAEP-SHA256 (wrappedKeyBase64 = 256 bytes para RSA-2048)
/// - AES-256-GCM con nonceBase64 (12 bytes) y tagBase64 (16 bytes)
/// - En resultEnvelope dentro de manifest.json, ciphertextBase64 es null (no se serializa) porque el cifrado viaja en resultado.enc.
/// </summary>
public sealed class CcHybridEnvelope
{
    [JsonPropertyName("envelope")]
    public string Envelope { get; set; } = "CC-ENV-1";

    [JsonIgnore]
    public string Version
    {
        get => Envelope;
        set { if (!string.IsNullOrWhiteSpace(value)) Envelope = value; }
    }

    [JsonPropertyName("recipientNode")]
    public string RecipientNode { get; set; } = "EQ01";

    [JsonPropertyName("recipientThumbprintSha256")]
    public string RecipientThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("keyWrapAlgorithm")]
    public string KeyWrapAlgorithm { get; set; } = "RSA-OAEP-SHA256";

    [JsonPropertyName("contentEncryptionAlgorithm")]
    public string ContentEncryptionAlgorithm { get; set; } = "AES-256-GCM";

    [JsonPropertyName("wrappedKeyBase64")]
    public string WrappedKeyBase64 { get; set; } = string.Empty;

    [JsonIgnore]
    public string EncryptedKeyBase64
    {
        get => WrappedKeyBase64;
        set { if (!string.IsNullOrWhiteSpace(value)) WrappedKeyBase64 = value; }
    }

    [JsonPropertyName("nonceBase64")]
    public string NonceBase64 { get; set; } = string.Empty;

    [JsonPropertyName("tagBase64")]
    public string TagBase64 { get; set; } = string.Empty;

    [JsonPropertyName("ciphertextBase64")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CiphertextBase64 { get; set; }

    [JsonExtensionData]
    public Dictionary<string, System.Text.Json.JsonElement>? ExtensionData { get; set; }

    public string ResolveWrappedKeyBase64()
    {
        if (!string.IsNullOrWhiteSpace(WrappedKeyBase64))
            return WrappedKeyBase64;
        if (ExtensionData != null &&
            ExtensionData.TryGetValue("encryptedKeyBase64", out var el) &&
            el.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            return el.GetString() ?? string.Empty;
        }
        return string.Empty;
    }

    public string ResolveEnvelopeVersion()
    {
        if (!string.IsNullOrWhiteSpace(Envelope))
            return Envelope;
        if (ExtensionData != null &&
            ExtensionData.TryGetValue("version", out var el) &&
            el.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            return el.GetString() ?? string.Empty;
        }
        return string.Empty;
    }
}

/// <summary>
/// Contrato JSON oficial de manifest.json conforme al Estándar de Comunicación entre Nodos v2.0 (Sección 9.5 — 29 campos exactos).
/// </summary>
public sealed class PacketManifest
{
    public const string EmptySha256Lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "2.0";

    [JsonPropertyName("packetType")]
    public string PacketType { get; set; } = "package";

    [JsonPropertyName("packetId")]
    public string PacketId { get; set; } = Guid.NewGuid().ToString("D").ToLowerInvariant();

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    [JsonPropertyName("sourceNode")]
    public string SourceNode { get; set; } = "EQ01";

    [JsonPropertyName("sourceTeam")]
    public int SourceTeam { get; set; } = 1;

    [JsonPropertyName("sourceIp")]
    public string SourceIp { get; set; } = "127.0.0.1:5001";

    [JsonPropertyName("producerNode")]
    public string ProducerNode { get; set; } = "EQ01";

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    [JsonPropertyName("algorithmId")]
    public int AlgorithmId { get; set; } = 1;

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("algorithmName")]
    public string AlgorithmName { get; set; } = "AES-256-GCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "forward";

    [JsonPropertyName("operationName")]
    public string OperationName { get; set; } = "Cifrado";

    [JsonPropertyName("payloadMode")]
    public string PayloadMode { get; set; } = "file";

    [JsonPropertyName("originalFileName")]
    public string OriginalFileName { get; set; } = "mensaje.txt";

    [JsonPropertyName("originalExtension")]
    public string OriginalExtension { get; set; } = ".txt";

    [JsonPropertyName("originalSizeBytes")]
    public long OriginalSizeBytes { get; set; }

    [JsonPropertyName("contentType")]
    public string ContentType { get; set; } = "application/octet-stream";

    [JsonPropertyName("encryptedSha256")]
    public string EncryptedSha256 { get; set; } = string.Empty;

    [JsonPropertyName("encryptedSizeBytes")]
    public long EncryptedSizeBytes { get; set; }

    [JsonPropertyName("parts")]
    public List<ManifestPartInfo>? Parts { get; set; }

    [JsonPropertyName("keyRef")]
    public ManifestKeyRef? KeyRef { get; set; }

    [JsonPropertyName("publicParameters")]
    public Dictionary<string, string> PublicParameters { get; set; } = new(StringComparer.Ordinal);

    [JsonPropertyName("publicParametersSha256")]
    public string PublicParametersSha256 { get; set; } = EmptySha256Lower;

    [JsonPropertyName("verification")]
    public ManifestVerification? Verification { get; set; }

    [JsonPropertyName("resultEnvelope")]
    public CcHybridEnvelope? ResultEnvelope { get; set; }

    [JsonPropertyName("certificateThumbprintSha256")]
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; set; } = "RSA-PSS-SHA256";

    [JsonPropertyName("manifestSignatureBase64")]
    public string ManifestSignatureBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Sección 8.5: Ordena llaves con StringComparer.Ordinal, forma "llave=valor" unidos con '\n' (LF, sin salto final)
    /// y calcula SHA-256 en hex minúsculas. Si está vacío devuelve SHA-256("").
    /// </summary>
    public static string ComputePublicParametersSha256(IDictionary<string, string>? parameters)
    {
        if (parameters == null || parameters.Count == 0)
            return EmptySha256Lower;

        var orderedKeys = parameters.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var sb = new StringBuilder();
        for (int i = 0; i < orderedKeys.Count; i++)
        {
            if (i > 0) sb.Append('\n');
            string k = orderedKeys[i];
            string v = parameters[k] ?? string.Empty;
            sb.Append(k).Append('=').Append(v);
        }

        byte[] utf8 = Encoding.UTF8.GetBytes(sb.ToString());
        return Convert.ToHexString(SHA256.HashData(utf8)).ToLowerInvariant();
    }

    /// <summary>
    /// Sección 8.4: Cadena canónica única de 11 campos separados por '|'.
    /// version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256
    /// </summary>
    public string BuildCanonicalSigningString()
    {
        return string.Join("|",
            Version,
            PacketType,
            PacketId,
            SourceNode,
            ProducerNode,
            AlgorithmCode,
            Operation,
            TimestampUtc,
            EncryptedSha256,
            PublicParametersSha256,
            CertificateThumbprintSha256);
    }
}

/// <summary>
/// Mensaje UDP de autodescubrimiento en el puerto 5099 (Sección 5).
/// </summary>
public sealed class CcBeaconMessage
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "CC-BEACON";

    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = "2.0";

    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = "EQ01";

    [JsonPropertyName("teamNumber")]
    public int TeamNumber { get; set; } = 1;

    [JsonPropertyName("ip")]
    public string Ip { get; set; } = "127.0.0.1";

    [JsonPropertyName("httpPort")]
    public int HttpPort { get; set; } = 5001;

    [JsonPropertyName("httpsPort")]
    public int? HttpsPort { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "online";

    [JsonPropertyName("algorithms")]
    public List<string> Algorithms { get; set; } = new() { "AESGCM", "DES" };

    [JsonPropertyName("certificateThumbprintSha256")]
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

public sealed class PeerStatusResponse
{
    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = "EQ01";

    [JsonPropertyName("teamNumber")]
    public int TeamNumber { get; set; } = 1;

    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = "2.0";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "online";

    [JsonPropertyName("acceptingPackages")]
    public bool AcceptingPackages { get; set; } = true;

    [JsonPropertyName("httpPort")]
    public int HttpPort { get; set; } = 5001;

    [JsonPropertyName("httpsPort")]
    public int? HttpsPort { get; set; }

    [JsonPropertyName("algorithms")]
    public List<string> Algorithms { get; set; } = new() { "AESGCM", "DES" };

    [JsonPropertyName("certificateThumbprintSha256")]
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

public sealed class PeerCertificateResponse
{
    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = "EQ01";

    [JsonPropertyName("certificatePem")]
    public string CertificatePem { get; set; } = string.Empty;

    [JsonPropertyName("certificateThumbprintSha256")]
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("subject")]
    public string Subject { get; set; } = string.Empty;

    [JsonPropertyName("notBeforeUtc")]
    public string NotBeforeUtc { get; set; } = string.Empty;

    [JsonPropertyName("notAfterUtc")]
    public string NotAfterUtc { get; set; } = string.Empty;
}

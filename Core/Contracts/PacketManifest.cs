using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace ModuloCrypto.Core.Contracts;

/// <summary>
/// Excepción tipada con código oficial del Estándar de Comunicación v2.0 (ej. E-ZIP-STRUCTURE, E-ZIP-BOMB, E-SIZE, E-SIGNATURE).
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

public sealed class CcEnvelope
{
    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "forward";

    [JsonPropertyName("producerNode")]
    public string ProducerNode { get; set; } = "EQ01";

    [JsonPropertyName("keyRef")]
    public ManifestKeyRef? KeyRef { get; set; }

    [JsonPropertyName("publicParameters")]
    public Dictionary<string, string> PublicParameters { get; set; } = new();
}

/// <summary>
/// Contrato JSON oficial de manifest.json conforme al Estándar de Comunicación entre Nodos v2.0 (Sección 8).
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
    public Dictionary<string, string> PublicParameters { get; set; } = new();

    [JsonPropertyName("publicParametersSha256")]
    public string PublicParametersSha256 { get; set; } = EmptySha256Lower;

    [JsonPropertyName("verification")]
    public ManifestVerification? Verification { get; set; }

    [JsonPropertyName("resultEnvelope")]
    public CcEnvelope? ResultEnvelope { get; set; }

    [JsonPropertyName("certificateThumbprintSha256")]
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("signatureAlgorithm")]
    public string SignatureAlgorithm { get; set; } = "RSA-PSS-SHA256";

    [JsonPropertyName("manifestSignatureBase64")]
    public string ManifestSignatureBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Sección 8.5: Ordena llaves con StringComparer.Ordinal, forma "llave=valor" unidos con '\n' (LF, sin salto final)
    /// y calcula SHA-256 en hex minúsculas.
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
/// Mensaje UDP de autodescubrimiento en el puerto 5099 (Sección 5 / Punto 2).
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

public sealed class StandardErrorResponse
{
    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = "EQ01";

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

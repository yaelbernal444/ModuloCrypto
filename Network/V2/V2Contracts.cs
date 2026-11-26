using ModuloCrypto.Core.Contracts;
using System.Text.Json.Serialization;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Sobre híbrido estandarizado CC-ENV-1 (RSA-OAEP-SHA256 + AES-256-GCM con AAD = requestId o packetId).
/// </summary>
public sealed class CcHybridEnvelope
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "CC-ENV-1";

    [JsonPropertyName("recipientNode")]
    public string RecipientNode { get; set; } = "EQ01";

    [JsonPropertyName("recipientThumbprintSha256")]
    public string RecipientThumbprintSha256 { get; set; } = string.Empty;

    [JsonPropertyName("keyWrapAlgorithm")]
    public string KeyWrapAlgorithm { get; set; } = "RSA-OAEP-SHA256";

    [JsonPropertyName("contentEncryptionAlgorithm")]
    public string ContentEncryptionAlgorithm { get; set; } = "AES-256-GCM";

    [JsonPropertyName("aadContext")]
    public string AadContext { get; set; } = string.Empty;

    [JsonPropertyName("encryptedKeyBase64")]
    public string EncryptedKeyBase64 { get; set; } = string.Empty;

    [JsonPropertyName("nonceBase64")]
    public string NonceBase64 { get; set; } = string.Empty;

    [JsonPropertyName("ciphertextBase64")]
    public string CiphertextBase64 { get; set; } = string.Empty;

    [JsonPropertyName("tagBase64")]
    public string TagBase64 { get; set; } = string.Empty;
}

/// <summary>
/// Parte JSON 'request' enviada en POST /api/crypto/forward (firmada en 'requestSignature' sobre los bytes crudos exactos).
/// </summary>
public sealed class V2CryptoForwardRequest
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = Guid.NewGuid().ToString("D").ToLowerInvariant();

    [JsonPropertyName("packetId")]
    public string PacketId { get; set; } = Guid.NewGuid().ToString("D").ToLowerInvariant();

    [JsonPropertyName("requesterNode")]
    public string RequesterNode { get; set; } = "EQ01";

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "forward";

    [JsonPropertyName("originalFileName")]
    public string OriginalFileName { get; set; } = "payload.bin";

    [JsonPropertyName("originalExtension")]
    public string OriginalExtension { get; set; } = ".bin";

    [JsonPropertyName("keySizeBits")]
    public int KeySizeBits { get; set; } = 256;

    [JsonPropertyName("secretEnvelope")]
    public CcHybridEnvelope? SecretEnvelope { get; set; }

    [JsonPropertyName("parameters")]
    public Dictionary<string, string> Parameters { get; set; } = new();

    [JsonPropertyName("forceAsync")]
    public bool ForceAsync { get; set; }

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

/// <summary>
/// Respuesta de POST /api/crypto/forward en el proveedor (ej. EQ01 para AESGCM y DES).
/// </summary>
public sealed class V2CryptoForwardResponse
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("packetId")]
    public string PacketId { get; set; } = string.Empty;

    [JsonPropertyName("producerNode")]
    public string ProducerNode { get; set; } = "EQ01";

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "forward";

    [JsonPropertyName("ciphertextBase64")]
    public string CiphertextBase64 { get; set; } = string.Empty;

    [JsonPropertyName("encryptedSha256")]
    public string EncryptedSha256 { get; set; } = string.Empty;

    [JsonPropertyName("publicParameters")]
    public Dictionary<string, string> PublicParameters { get; set; } = new();

    [JsonPropertyName("publicParametersSha256")]
    public string PublicParametersSha256 { get; set; } = PacketManifest.EmptySha256Lower;

    [JsonPropertyName("keyRef")]
    public ManifestKeyRef KeyRef { get; set; } = new();

    [JsonPropertyName("secretKeyEnvelope")]
    public CcHybridEnvelope? SecretKeyEnvelope { get; set; }

    [JsonPropertyName("packageZipBase64")]
    public string PackageZipBase64 { get; set; } = string.Empty;

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

/// <summary>
/// Parte JSON 'request' enviada en POST /api/crypto/inverse.
/// </summary>
public sealed class V2CryptoInverseRequest
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = Guid.NewGuid().ToString("D").ToLowerInvariant();

    [JsonPropertyName("packetId")]
    public string PacketId { get; set; } = string.Empty;

    [JsonPropertyName("requesterNode")]
    public string RequesterNode { get; set; } = "EQ01";

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "inverse";

    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }

    [JsonPropertyName("secretEnvelope")]
    public CcHybridEnvelope? SecretEnvelope { get; set; }

    [JsonPropertyName("publicParameters")]
    public Dictionary<string, string> PublicParameters { get; set; } = new();

    [JsonPropertyName("forceAsync")]
    public bool ForceAsync { get; set; }

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

public sealed class V2JobAcceptedResponse
{
    [JsonPropertyName("jobId")]
    public string JobId { get; set; } = string.Empty;

    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "running";

    [JsonPropertyName("statusUrl")]
    public string StatusUrl { get; set; } = string.Empty;

    [JsonPropertyName("resultUrl")]
    public string ResultUrl { get; set; } = string.Empty;

    [JsonPropertyName("retryAfterSeconds")]
    public int RetryAfterSeconds { get; set; } = 5;

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
}

public sealed class V2JobStatusResponse
{
    [JsonPropertyName("jobId")]
    public string JobId { get; set; } = string.Empty;

    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("requesterNode")]
    public string RequesterNode { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "running";

    [JsonPropertyName("resultUrl")]
    public string? ResultUrl { get; set; }

    [JsonPropertyName("errorCode")]
    public string? ErrorCode { get; set; }

    [JsonPropertyName("errorDetail")]
    public string? ErrorDetail { get; set; }

    [JsonPropertyName("createdAtUtc")]
    public string CreatedAtUtc { get; set; } = string.Empty;

    [JsonPropertyName("completedAtUtc")]
    public string? CompletedAtUtc { get; set; }
}

public sealed class V2AlgorithmProfileDto
{
    [JsonPropertyName("algorithmId")]
    public int AlgorithmId { get; set; }

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = string.Empty;

    [JsonPropertyName("algorithmName")]
    public string AlgorithmName { get; set; } = string.Empty;

    [JsonPropertyName("ownerNode")]
    public string OwnerNode { get; set; } = "EQ01";

    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("operations")]
    public List<string> Operations { get; set; } = new() { "forward", "inverse" };

    [JsonPropertyName("requiresKeyEnvelope")]
    public bool RequiresKeyEnvelope { get; set; } = true;

    [JsonPropertyName("publicParametersSchema")]
    public List<string> PublicParametersSchema { get; set; } = new();

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
}

public sealed class V2PublicKeyResponseDto
{
    [JsonPropertyName("keyId")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = string.Empty;

    [JsonPropertyName("ownerNode")]
    public string OwnerNode { get; set; } = "EQ01";

    [JsonPropertyName("publicKeyPem")]
    public string PublicKeyPem { get; set; } = string.Empty;

    [JsonPropertyName("parameters")]
    public Dictionary<string, string> Parameters { get; set; } = new();

    [JsonPropertyName("createdAtUtc")]
    public string CreatedAtUtc { get; set; } = string.Empty;
}

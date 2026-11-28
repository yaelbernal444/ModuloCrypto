using ModuloCrypto.Core.Contracts;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModuloCrypto.Network.V2;

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

    [JsonPropertyName("targetNode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetNode { get; set; }

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "forward";

    [JsonPropertyName("originalFileName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OriginalFileName { get; set; }

    [JsonPropertyName("originalExtension")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OriginalExtension { get; set; }

    [JsonPropertyName("keySizeBits")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? KeySizeBits { get; set; }

    [JsonPropertyName("secrets")]
    public CcHybridEnvelope? Secrets { get; set; }

    [JsonPropertyName("secretEnvelope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CcHybridEnvelope? SecretEnvelope
    {
        get => null;
        set { if (value != null) Secrets = value; }
    }

    [JsonPropertyName("options")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Options { get; set; }

    [JsonPropertyName("parameters")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Parameters { get; set; }

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
    public Dictionary<string, string> PublicParameters { get; set; } = new(StringComparer.Ordinal);

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

    [JsonPropertyName("targetNode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetNode { get; set; }

    [JsonPropertyName("algorithmCode")]
    public string AlgorithmCode { get; set; } = "AESGCM";

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = "inverse";

    [JsonPropertyName("keyId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyId { get; set; }

    [JsonPropertyName("secrets")]
    public CcHybridEnvelope? Secrets { get; set; }

    [JsonPropertyName("secretEnvelope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CcHybridEnvelope? SecretEnvelope
    {
        get => null;
        set { if (value != null) Secrets = value; }
    }

    [JsonPropertyName("options")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Options { get; set; }

    [JsonPropertyName("publicParameters")]
    public Dictionary<string, string> PublicParameters { get; set; } = new(StringComparer.Ordinal);

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

    [JsonPropertyName("requiresSecret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequiresSecret { get; set; }

    [JsonPropertyName("requiresSecretOnInverse")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequiresSecretOnInverse { get; set; }

    [JsonPropertyName("secretFields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? SecretFields { get; set; }

    [JsonPropertyName("optionsSchema")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? OptionsSchema { get; set; }

    [JsonPropertyName("publicParametersSchema")]
    public List<string> PublicParametersSchema { get; set; } = new();

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }

    public List<string> ResolveSecretFieldNames()
    {
        if (SecretFields is { Count: > 0 })
            return SecretFields.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();

        if (ExtensionData != null)
        {
            foreach (string key in new[] { "secretsSchema", "secretSchema", "requiredSecrets", "secretParameters" })
            {
                if (ExtensionData.TryGetValue(key, out var el) && el.ValueKind == JsonValueKind.Array)
                {
                    var extracted = new List<string>();
                    foreach (var item in el.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            string? s = item.GetString();
                            if (!string.IsNullOrWhiteSpace(s)) extracted.Add(s);
                        }
                        else if (item.ValueKind == JsonValueKind.Object)
                        {
                            if (item.TryGetProperty("name", out var nEl) && nEl.ValueKind == JsonValueKind.String && nEl.GetString() is { } nm)
                                extracted.Add(nm);
                            else if (item.TryGetProperty("field", out var fEl) && fEl.ValueKind == JsonValueKind.String && fEl.GetString() is { } fl)
                                extracted.Add(fl);
                        }
                    }
                    if (extracted.Count > 0) return extracted;
                }
            }
        }

        return new List<string>();
    }
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

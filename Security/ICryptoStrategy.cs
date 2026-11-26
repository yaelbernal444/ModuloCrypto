namespace ModuloCrypto.Security;

public sealed class CryptoAlgorithmInfo
{
    public int AlgorithmId { get; set; } = 1;
    public string Code { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string OwnerNode { get; set; } = "EQ01";
    public bool IsReversible { get; init; } = true;

    public override string ToString() => $"{Code} — {DisplayName}";
}

public sealed class CryptoOperationResult
{
    public bool Success { get; init; } = true;
    public string AlgorithmCode { get; init; } = string.Empty;
    public byte[] OutputBytes { get; init; } = Array.Empty<byte>();
    public string SecretKeyBase64 { get; init; } = string.Empty;
    public string PublicParametersJson { get; init; } = "{}";
    public string OutputExtensionOverride { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
}

public interface ICryptoStrategy
{
    CryptoAlgorithmInfo Info { get; }

    CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null);

    CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson);
}

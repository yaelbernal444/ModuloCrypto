using System.ComponentModel.DataAnnotations;

namespace ModuloCrypto.Core.Models;

/// <summary>
/// Almacén persistente en SQLite para pares de llaves asimétricas v2.0 (GET /api/keys/{keyId}).
/// La llave privada se almacena cifrada con Windows DPAPI (CurrentUser).
/// </summary>
public class AsymmetricKeyEntity
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(64)]
    public string KeyId { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string AlgorithmCode { get; set; } = "RSA";

    [Required]
    [MaxLength(16)]
    public string OwnerNode { get; set; } = "EQ01";

    public string PublicKeyPem { get; set; } = string.Empty;

    public string ProtectedPrivateKeyBase64 { get; set; } = string.Empty;

    public string ParametersJson { get; set; } = "{}";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

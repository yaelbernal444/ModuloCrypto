using System.ComponentModel.DataAnnotations;

namespace ModuloCrypto.Core.Models;

/// <summary>
/// Entidad persistente en SQLite para el directorio de nodos y validación TOFU (Trust On First Use) v2.0.
/// </summary>
public class PeerNode
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(16)]
    public string NodeId { get; set; } = string.Empty;

    public int TeamNumber { get; set; }

    [Required]
    [MaxLength(64)]
    public string IpAddress { get; set; } = "127.0.0.1";

    public int Port { get; set; } = 5001;

    public int? HttpsPort { get; set; }

    [MaxLength(64)]
    public string RoleLabel { get; set; } = "Nodo Cripto v2.0";

    [MaxLength(32)]
    public string ProtocolType { get; set; } = "v2.0";

    /// <summary>
    /// Origen del descubrimiento: "beacon", "scan", "manual" o "local".
    /// </summary>
    [MaxLength(24)]
    public string Source { get; set; } = "manual";

    /// <summary>
    /// Estado actual: "online", "offline" o "blocked".
    /// </summary>
    [MaxLength(24)]
    public string Status { get; set; } = "offline";

    public bool IsOnline
    {
        get => string.Equals(Status, "online", StringComparison.OrdinalIgnoreCase);
        set => Status = value ? "online" : (Status == "blocked" ? "blocked" : "offline");
    }

    [MaxLength(32)]
    public string LastLatency { get; set; } = "--";

    /// <summary>
    /// Huella SHA-256 (64 HEX MAYÚSCULAS) anunciada por el nodo en el último beacon o /api/status.
    /// </summary>
    [MaxLength(64)]
    public string CertThumbprint { get; set; } = string.Empty;

    /// <summary>
    /// Huella SHA-256 (64 HEX MAYÚSCULAS) fijada por el usuario mediante confirmación TOFU.
    /// </summary>
    [MaxLength(64)]
    public string PinnedThumbprintSha256 { get; set; } = string.Empty;

    public string CertificatePem { get; set; } = string.Empty;

    /// <summary>
    /// Arreglo JSON de algoritmos de los que el nodo es dueño oficial (ej. ["AESGCM","DES"]).
    /// </summary>
    [MaxLength(256)]
    public string AlgorithmsJson { get; set; } = "[]";

    public bool IsConfirmed { get; set; }

    public bool HasThumbprintMismatch { get; set; }

    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    public string BaseUrl => $"http://{IpAddress}:{Port}";
}

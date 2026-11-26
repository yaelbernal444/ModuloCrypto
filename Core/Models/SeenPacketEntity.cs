using System.ComponentModel.DataAnnotations;

namespace ModuloCrypto.Core.Models;

/// <summary>
/// Registro persistente de paquetes procesados para protección Anti-Replay (Sección 8 / Estándar v2.0).
/// </summary>
public class SeenPacketEntity
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(64)]
    public string PacketId { get; set; } = string.Empty;

    [Required]
    [MaxLength(16)]
    public string SourceNode { get; set; } = string.Empty;

    public DateTime PacketTimestampUtc { get; set; }

    public DateTime ReceivedAtUtc { get; set; } = DateTime.UtcNow;
}

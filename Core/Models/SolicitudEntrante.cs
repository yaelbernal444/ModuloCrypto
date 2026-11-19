using System.ComponentModel.DataAnnotations;

namespace ModuloCrypto.Core.Models;

public class SolicitudEntrante
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(64)]
    public string PacketId { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string NodoOrigen { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string IpOrigen { get; set; } = string.Empty;

    [Required]
    [MaxLength(260)]
    public string NombreZip { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string AlgoritmoCodigo { get; set; } = string.Empty;

    public bool FirmaX509Valida { get; set; }

    [Required]
    [MaxLength(512)]
    public string RutaZipTemporal { get; set; } = string.Empty;

    /// <summary>
    /// "Pendiente", "Aceptada", "Rechazada".
    /// </summary>
    [Required]
    [MaxLength(24)]
    public string Estado { get; set; } = "Pendiente";

    public DateTime FechaRecepcion { get; set; } = DateTime.Now;
}

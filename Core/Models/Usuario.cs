using System.ComponentModel.DataAnnotations;

namespace ModuloCrypto.Core.Models;

public class Usuario
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(120)]
    public string NombreCompleto { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string NombreUsuario { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string PasswordHash { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string NodoAsignado { get; set; } = "EQ01";

    [Required]
    [MaxLength(32)]
    public string Rol { get; set; } = "Operador EQ01";

    public DateTime FechaRegistro { get; set; } = DateTime.Now;

    public List<RegistroCifrado> RegistrosCifrados { get; set; } = new();
}

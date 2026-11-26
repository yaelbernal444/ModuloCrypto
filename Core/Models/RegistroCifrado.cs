using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModuloCrypto.Core.Models;

public class RegistroCifrado
{
    [Key]
    public int Id { get; set; }

    public int UsuarioId { get; set; }

    [ForeignKey(nameof(UsuarioId))]
    public Usuario? Usuario { get; set; }

    [Required]
    [MaxLength(64)]
    public string PacketId { get; set; } = Guid.NewGuid().ToString("D").ToLowerInvariant();

    [Required]
    [MaxLength(260)]
    public string NombreArchivo { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Extension { get; set; } = ".txt";

    /// <summary>
    /// Base64 de los bytes cifrados para operación local.
    /// </summary>
    [Required]
    public string BytesCifrados { get; set; } = string.Empty;

    /// <summary>
    /// Código corto oficial en MAYÚSCULAS (uno de los 21 del catálogo).
    /// </summary>
    [Required]
    [MaxLength(32)]
    public string AlgoritmoCodigo { get; set; } = "AESGCM";

    /// <summary>
    /// JSON plano con parámetros públicos (IV, Nonce, Tag GCM, etc.).
    /// </summary>
    public string ParametrosPublicosJson { get; set; } = "{}";

    /// <summary>
    /// Llave secreta en Base64 custodiada localmente en SQLite (nunca se envía en manifest.json; se referencia vía keyRef).
    /// </summary>
    public string LlaveSecretaBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Identificador de referencia de llave (keyRef.keyId) en el estándar v2.0.
    /// </summary>
    [MaxLength(128)]
    public string LinkDescifradoRemoto { get; set; } = string.Empty;

    [MaxLength(32)]
    public string NodoRaiz { get; set; } = "EQ01";

    public string FirmaRaizBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Arreglo JSON con los nodos recorridos (trazabilidad).
    /// </summary>
    public string RutaSaltosJson { get; set; } = "[\"EQ01\"]";

    /// <summary>
    /// "Local", "Relay" o "Recibido".
    /// </summary>
    [Required]
    [MaxLength(24)]
    public string Origen { get; set; } = "Local";

    public DateTime FechaOperacion { get; set; } = DateTime.Now;
}

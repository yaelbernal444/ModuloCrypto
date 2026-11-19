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
    public string PacketId { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [MaxLength(260)]
    public string NombreArchivo { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Extension { get; set; } = ".txt";

    /// <summary>
    /// Base64 de los bytes cifrados o ruta local del archivo cifrado.
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
    /// JSON con parámetros públicos (IV, Nonce, Tag GCM, Salt, parámetros modulares, etc.).
    /// </summary>
    public string ParametrosPublicosJson { get; set; } = "{}";

    /// <summary>
    /// Llave secreta en Base64 para responder a peticiones de descifrado remoto.
    /// </summary>
    public string LlaveSecretaBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Endpoint HTTP del nodo emisor para solicitar descifrado remoto.
    /// </summary>
    [MaxLength(512)]
    public string LinkDescifradoRemoto { get; set; } = string.Empty;

    [MaxLength(32)]
    public string NodoRaiz { get; set; } = "NODO-04";

    public string FirmaRaizBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Arreglo JSON con los nodos recorridos en la ruta tipo Tor.
    /// </summary>
    public string RutaSaltosJson { get; set; } = "[]";

    /// <summary>
    /// "Local" o "Recibido".
    /// </summary>
    [Required]
    [MaxLength(24)]
    public string Origen { get; set; } = "Local";

    public DateTime FechaOperacion { get; set; } = DateTime.Now;
}

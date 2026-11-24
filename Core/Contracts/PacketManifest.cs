using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModuloCrypto.Core.Contracts;

/// <summary>
/// Contrato JSON oficial híbrido de manifest.json compatible con ModuloCrypto y CentroCiberseguridad.Web.
/// Soporta ciclo bidireccional completo (Nodo Raíz -> Nodo Intermedio -> Nodo Final).
/// </summary>
public class PacketManifest
{
    public string Version { get; set; } = "1.0";
    public string PacketId { get; set; } = Guid.NewGuid().ToString();

    public string AlgoritmoCodigo { get; set; } = "AESGCM";

    public string AlgorithmCode
    {
        get => AlgoritmoCodigo;
        set { if (!string.IsNullOrWhiteSpace(value)) AlgoritmoCodigo = value.Trim().ToUpperInvariant(); }
    }

    public string AlgorithmName { get; set; } = "AES-256-GCM";

    public string NombreArchivo { get; set; } = "mensaje.txt";

    public string OriginalFileName
    {
        get => NombreArchivo;
        set { if (!string.IsNullOrWhiteSpace(value)) NombreArchivo = value; }
    }

    public string Extension { get; set; } = ".txt";

    public string OriginalExtension
    {
        get => Extension;
        set { if (!string.IsNullOrWhiteSpace(value)) Extension = value; }
    }

    public long OriginalSizeBytes { get; set; }
    public string PayloadMode { get; set; } = "file";

    public string ParametrosPublicosJson { get; set; } = "{}";
    public JsonElement? PublicParameters { get; set; }

    public string LinkDescifradoRemoto { get; set; } = string.Empty;

    public string NodoRaiz { get; set; } = "NODO-01";

    public string SourceNode
    {
        get => NodoRaiz;
        set { if (!string.IsNullOrWhiteSpace(value)) NodoRaiz = value; }
    }

    public string SourceIp { get; set; } = "127.0.0.1";

    [JsonPropertyName("rootOrigin")]
    public string RootOrigin
    {
        get => NodoRaiz;
        set { if (!string.IsNullOrWhiteSpace(value)) NodoRaiz = value; }
    }

    public string FirmaRaizBase64 { get; set; } = string.Empty;
    public string CertificadoRaizBase64 { get; set; } = string.Empty;
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = "RSA-PSS-SHA256";
    public string ManifestSignatureBase64 { get; set; } = string.Empty;

    public List<string> RutaSaltos { get; set; } = new() { "NODO-01" };

    [JsonPropertyName("hopHistory")]
    public List<string> HopHistory
    {
        get => RutaSaltos;
        set { if (value is { Count: > 0 }) RutaSaltos = value; }
    }

    public string PayloadSha256 { get; set; } = string.Empty;

    public string EncryptedSha256
    {
        get => PayloadSha256;
        set { if (!string.IsNullOrWhiteSpace(value)) PayloadSha256 = value; }
    }

    public string OriginalHashSha256 { get; set; } = string.Empty;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
}

public class RemoteDecryptResponse
{
    public bool Success { get; set; }
    public string PacketId { get; set; } = string.Empty;
    public string AlgoritmoCodigo { get; set; } = string.Empty;
    public string LlaveSecretaBase64 { get; set; } = string.Empty;
    public string ParametrosPublicosJson { get; set; } = "{}";
    public string NodoRaiz { get; set; } = "NODO-01";
    public string FirmaRaizBase64 { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class NodeHealthResponse
{
    public string Status { get; set; } = "Online";
    public string NodeId { get; set; } = "NODO-01";
    public int Port { get; set; } = 5000;
    public string X509Subject { get; set; } = string.Empty;
    public string X509Thumbprint { get; set; } = string.Empty;
    public int SupportedAlgorithms { get; set; } = 21;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
}

public class PeerStatusResponse
{
    public string NodeId { get; set; } = "NODO-01";
    public string ProtocolVersion { get; set; } = "1.0";
    public string Status { get; set; } = "online";
    public bool AcceptingPackages { get; set; } = true;
    public string CertificateThumbprint { get; set; } = string.Empty;
}

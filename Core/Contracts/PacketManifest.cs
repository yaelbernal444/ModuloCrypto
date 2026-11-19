using System.Text.Json.Serialization;

namespace ModuloCrypto.Core.Contracts;

/// <summary>
/// Contrato JSON oficial de manifest.json incluido dentro de cada paquete .zip intercambiado en la red de 8 nodos.
/// Soporta ciclo bidireccional completo (Nodo Raíz -> Nodo Intermedio -> Nodo Final).
/// </summary>
public class PacketManifest
{
    public string PacketId { get; set; } = Guid.NewGuid().ToString();
    public string AlgoritmoCodigo { get; set; } = "AESGCM";
    public string NombreArchivo { get; set; } = "mensaje.txt";
    public string Extension { get; set; } = ".txt";
    public string ParametrosPublicosJson { get; set; } = "{}";
    public string LinkDescifradoRemoto { get; set; } = string.Empty;

    public string NodoRaiz { get; set; } = "NODO-01";

    [JsonPropertyName("rootOrigin")]
    public string RootOrigin
    {
        get => NodoRaiz;
        set { if (!string.IsNullOrWhiteSpace(value)) NodoRaiz = value; }
    }

    public string FirmaRaizBase64 { get; set; } = string.Empty;
    public string CertificadoRaizBase64 { get; set; } = string.Empty;

    public List<string> RutaSaltos { get; set; } = new() { "NODO-01" };

    [JsonPropertyName("hopHistory")]
    public List<string> HopHistory
    {
        get => RutaSaltos;
        set { if (value is { Count: > 0 }) RutaSaltos = value; }
    }

    public string PayloadSha256 { get; set; } = string.Empty;
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

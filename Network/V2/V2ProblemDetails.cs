using Microsoft.AspNetCore.Http;
using ModuloCrypto.Core.Services;
using System.Text.Json.Serialization;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Respuesta de error estandarizada conforme a RFC 9457 (application/problem+json) y Anexo B del Estándar v2.0.
/// </summary>
public sealed class V2ProblemDetails
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "urn:cc:error:E-INTERNAL";

    [JsonPropertyName("title")]
    public string Title { get; set; } = "Error de validación del protocolo v2.0";

    [JsonPropertyName("status")]
    public int Status { get; set; } = 400;

    [JsonPropertyName("detail")]
    public string Detail { get; set; } = string.Empty;

    [JsonPropertyName("instance")]
    public string Instance { get; set; } = "/api/v2";

    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; set; } = "E-INTERNAL";

    [JsonPropertyName("nodeId")]
    public string NodeId { get; set; } = "EQ01";

    [JsonPropertyName("timestampUtc")]
    public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    public static IResult ToResult(string errorCode, int statusCode, string detail, string? instance = null)
    {
        var problem = new V2ProblemDetails
        {
            Type = $"urn:cc:error:{errorCode}",
            Title = ResolveTitle(errorCode),
            Status = statusCode,
            Detail = detail,
            Instance = string.IsNullOrWhiteSpace(instance) ? "/api/v2" : instance,
            ErrorCode = errorCode,
            NodeId = NodeRuntimeState.CurrentNodeId,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        return Results.Json(
            problem,
            statusCode: statusCode,
            contentType: "application/problem+json");
    }

    public static string ResolveTitle(string errorCode) => errorCode switch
    {
        "E-SIZE" => "Tamaño máximo de paquete excedido (50 MB)",
        "E-ZIP-INVALID" => "Archivo ZIP corrupto o ilegible",
        "E-ZIP-STRUCTURE" => "Estructura de paquete ZIP inválida (se requieren exactamente 3 archivos planos)",
        "E-ZIP-BOMB" => "Protección Anti-ZIP-Bomb activada (>200 MB o ratio >100:1)",
        "E-MANIFEST" => "Manifiesto JSON ausente o malformado",
        "E-VERSION" => "Versión de protocolo incompatible (se requiere 2.0)",
        "E-ALGORITHM" => "Código de algoritmo no reconocido o no soportado",
        "E-HASH" => "El hash SHA-256 de los datos cifrados no coincide con encryptedSha256",
        "E-PARAMS-HASH" => "El hash canónico publicParametersSha256 no coincide con publicParameters",
        "E-CERT" => "Certificado X.509 inválido, vencido o CN no coincide con el nodo emisor",
        "E-CERT-THUMBPRINT" => "La huella SHA-256 del certificado no coincide con certificateThumbprintSha256",
        "E-CERT-UNTRUSTED" => "Certificado X.509 bloqueado por cambio de huella TOFU",
        "E-SIGNATURE" => "Firma digital RSA-PSS-SHA256 inválida",
        "E-TIMESTAMP" => "Timestamp UTC fuera de la ventana temporal permitida (±10 min)",
        "E-DUPLICATE" => "Paquete duplicado detectado (Anti-Replay)",
        "E-ENV-RECIPIENT" => "El sobre híbrido CC-ENV-1 no está dirigido a la huella de este nodo",
        "E-ENV-DECRYPT" => "No fue posible abrir o autenticar el sobre híbrido CC-ENV-1",
        "E-BUSY" => "Límite de 10 operaciones criptográficas concurrentes alcanzado",
        "E-FORBIDDEN" => "Acceso denegado al recurso solicitado",
        "E-NOT-FOUND" => "Recurso, llave o trabajo no encontrado",
        _ => "Error de procesamiento en nodo v2.0"
    };
}

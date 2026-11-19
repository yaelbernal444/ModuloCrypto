using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Models;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network;

public sealed class ParsedZipPacket
{
    public PacketManifest Manifest { get; init; } = new();
    public byte[] PayloadBytes { get; init; } = Array.Empty<byte>();
    public bool SignatureValid { get; init; }
    public bool IntegrityValid { get; init; }
}

/// <summary>
/// Empaqueta y desempaqueta archivos .zip compatibles con la red de 8 nodos (manifest.json + payload.bin + root_cert.cer).
/// Soporta NODO-01 como Nodo Raíz (inicio), Nodo Intermedio (re-cifrado + hopHistory) y Nodo Final.
/// </summary>
public static class PacketZipService
{
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    public static string CreatePacketZip(
        RegistroCifrado registro,
        byte[] cipherBytes,
        List<string>? customHops = null,
        string? destinationPath = null,
        string? preservedRootCertBase64 = null,
        string? preservedOriginalHashHex = null)
    {
        string outDir = Path.Combine(AppContext.BaseDirectory, "OutgoingPackets");
        Directory.CreateDirectory(outDir);

        string zipPath = destinationPath ?? Path.Combine(
            outDir,
            $"{registro.NodoRaiz}_{registro.AlgoritmoCodigo}_{registro.PacketId[..8]}.zip");

        var hops = customHops ?? TryDeserializeHops(registro.RutaSaltosJson);
        if (hops.Count == 0) hops.Add(registro.NodoRaiz);

        string payloadHashHex = Convert.ToHexString(SHA256.HashData(cipherBytes));
        string originalHashHex = string.IsNullOrWhiteSpace(preservedOriginalHashHex)
            ? payloadHashHex
            : preservedOriginalHashHex;

        string certBase64 = string.IsNullOrWhiteSpace(preservedRootCertBase64)
            ? NodeCertificateService.ExportPublicCertBase64()
            : preservedRootCertBase64;

        string signature = string.IsNullOrWhiteSpace(registro.FirmaRaizBase64)
            ? NodeCertificateService.SignPayload(Encoding.ASCII.GetBytes(originalHashHex))
            : registro.FirmaRaizBase64;

        var manifest = new PacketManifest
        {
            PacketId = registro.PacketId,
            AlgoritmoCodigo = registro.AlgoritmoCodigo,
            NombreArchivo = registro.NombreArchivo,
            Extension = registro.Extension,
            ParametrosPublicosJson = registro.ParametrosPublicosJson,
            LinkDescifradoRemoto = registro.LinkDescifradoRemoto,
            NodoRaiz = registro.NodoRaiz,
            FirmaRaizBase64 = signature,
            CertificadoRaizBase64 = certBase64,
            RutaSaltos = hops,
            PayloadSha256 = payloadHashHex,
            OriginalHashSha256 = originalHashHex,
            TimestampUtc = DateTime.UtcNow
        };

        if (File.Exists(zipPath)) File.Delete(zipPath);

        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);

        var manifestEntry = archive.CreateEntry("manifest.json");
        using (var sw = new StreamWriter(manifestEntry.Open(), Encoding.UTF8))
            sw.Write(JsonSerializer.Serialize(manifest, PrettyJson));

        var payloadEntry = archive.CreateEntry("payload.bin");
        using (var ps = payloadEntry.Open())
            ps.Write(cipherBytes, 0, cipherBytes.Length);

        var certEntry = archive.CreateEntry("root_cert.cer");
        using (var cs = certEntry.Open())
        {
            byte[] certBytes = Convert.FromBase64String(certBase64);
            cs.Write(certBytes, 0, certBytes.Length);
        }

        return zipPath;
    }

    public static ParsedZipPacket ReadPacketZip(string zipPath)
    {
        using var archive = ZipFile.OpenRead(zipPath);

        var manifestEntry = archive.GetEntry("manifest.json")
            ?? throw new InvalidDataException("El paquete .zip no contiene manifest.json.");
        var payloadEntry = archive.GetEntry("payload.bin")
            ?? throw new InvalidDataException("El paquete .zip no contiene payload.bin.");

        PacketManifest manifest;
        using (var sr = new StreamReader(manifestEntry.Open(), Encoding.UTF8))
        {
            string json = sr.ReadToEnd();
            manifest = JsonSerializer.Deserialize<PacketManifest>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? throw new InvalidDataException("manifest.json inválido.");
        }

        byte[] payload;
        using (var ms = new MemoryStream())
        {
            payloadEntry.Open().CopyTo(ms);
            payload = ms.ToArray();
        }

        string certBase64 = manifest.CertificadoRaizBase64;
        if (string.IsNullOrWhiteSpace(certBase64))
        {
            var certEntry = archive.GetEntry("root_cert.cer");
            if (certEntry != null)
            {
                using var ms = new MemoryStream();
                certEntry.Open().CopyTo(ms);
                certBase64 = Convert.ToBase64String(ms.ToArray());
            }
            manifest.CertificadoRaizBase64 = certBase64;
        }

        // Verifica firma sobre payload directo o sobre OriginalHashSha256 (cuando pasa por saltos intermedios re-cifrados)
        bool sigValid = NodeCertificateService.VerifyPayloadSignature(payload, manifest.FirmaRaizBase64, certBase64);
        if (!sigValid && !string.IsNullOrWhiteSpace(manifest.OriginalHashSha256))
        {
            sigValid = NodeCertificateService.VerifyPayloadSignature(
                Encoding.ASCII.GetBytes(manifest.OriginalHashSha256),
                manifest.FirmaRaizBase64,
                certBase64);
        }

        bool hashValid = string.IsNullOrWhiteSpace(manifest.PayloadSha256) ||
                         string.Equals(manifest.PayloadSha256, Convert.ToHexString(SHA256.HashData(payload)), StringComparison.OrdinalIgnoreCase);

        return new ParsedZipPacket
        {
            Manifest = manifest,
            PayloadBytes = payload,
            SignatureValid = sigValid,
            IntegrityValid = hashValid
        };
    }

    public static List<string> TryDeserializeHops(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
}

using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Models;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ModuloCrypto.Network;

public static class NodeNetworkClient
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static async Task<(bool Online, string Latency, NodeHealthResponse? Info)> PingNodeAsync(PeerNode node)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var resp = await Http.GetAsync($"{node.BaseUrl}/api/health");
            sw.Stop();
            if (!resp.IsSuccessStatusCode)
                return (false, "HTTP " + (int)resp.StatusCode, null);

            string body = await resp.Content.ReadAsStringAsync();
            var info = JsonSerializer.Deserialize<NodeHealthResponse>(body, JsonOpts);
            return (true, $"{sw.ElapsedMilliseconds} ms", info);
        }
        catch
        {
            sw.Stop();
            return (false, "Timeout", null);
        }
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(string targetBaseUrl, string zipPath)
    {
        try
        {
            string url = targetBaseUrl.TrimEnd('/') + "/api/packets/receive";
            using var form = new MultipartFormDataContent();
            byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
            var content = new ByteArrayContent(fileBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
            form.Add(content, "file", Path.GetFileName(zipPath));

            var resp = await Http.PostAsync(url, form);
            string body = await resp.Content.ReadAsStringAsync();
            return resp.IsSuccessStatusCode
                ? (true, $"Paquete enviado correctamente a {url}.\nRespuesta: {body}")
                : (false, $"Error HTTP {(int)resp.StatusCode}: {body}");
        }
        catch (Exception ex)
        {
            return (false, $"Error de conexión hacia {targetBaseUrl}: {ex.Message}");
        }
    }

    public static async Task<RemoteDecryptResponse> RequestRemoteKeyAsync(string remoteDecryptUrl)
    {
        try
        {
            var resp = await Http.GetAsync(remoteDecryptUrl);
            string body = await resp.Content.ReadAsStringAsync();
            var parsed = JsonSerializer.Deserialize<RemoteDecryptResponse>(body, JsonOpts);
            if (parsed != null)
                return parsed;

            return new RemoteDecryptResponse { Success = false, Message = $"Respuesta inválida: {body}" };
        }
        catch (Exception ex)
        {
            return new RemoteDecryptResponse { Success = false, Message = $"Error al contactar nodo remoto: {ex.Message}" };
        }
    }
}

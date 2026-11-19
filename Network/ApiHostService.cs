using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;

namespace ModuloCrypto.Network;

/// <summary>
/// Servidor ASP.NET Core Minimal API embebido escuchando en http://0.0.0.0:5000.
/// </summary>
public sealed class ApiHostService : IAsyncDisposable
{
    private WebApplication? _app;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(int port = 5000)
    {
        try
        {
            _cts = new CancellationTokenSource();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

            _app = builder.Build();

            // 1. Health / Descubrimiento de Nodos
            _app.MapGet("/api/health", () => Results.Ok(new NodeHealthResponse
            {
                Status = "Online",
                NodeId = NodeRuntimeState.CurrentNodeId,
                Port = port,
                X509Subject = NodeCertificateService.Subject,
                X509Thumbprint = NodeCertificateService.Thumbprint,
                SupportedAlgorithms = CryptoCatalog.OfficialAlgorithms.Count,
                TimestampUtc = DateTime.UtcNow
            }));

            // 2. Catálogo oficial de 21 algoritmos
            _app.MapGet("/api/algorithms", () => Results.Ok(CryptoCatalog.OfficialAlgorithms));

            // 3. Recepción de paquetes .zip desde otro nodo
            _app.MapPost("/api/packets/receive", async (HttpRequest request) =>
            {
                string incomingDir = Path.Combine(AppContext.BaseDirectory, "IncomingPackets");
                Directory.CreateDirectory(incomingDir);

                string fileName = $"packet_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString()[..6]}.zip";
                string zipPath = Path.Combine(incomingDir, fileName);

                if (request.HasFormContentType && request.Form.Files.Count > 0)
                {
                    var file = request.Form.Files[0];
                    if (!string.IsNullOrWhiteSpace(file.FileName))
                        fileName = Path.GetFileName(file.FileName);
                    zipPath = Path.Combine(incomingDir, $"{Guid.NewGuid().ToString()[..6]}_{fileName}");
                    await using var fs = File.Create(zipPath);
                    await file.CopyToAsync(fs);
                }
                else
                {
                    await using var fs = File.Create(zipPath);
                    await request.Body.CopyToAsync(fs);
                }

                string ipOrigen = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "desconocida";

                try
                {
                    var parsed = PacketZipService.ReadPacketZip(zipPath);

                    var solicitud = new SolicitudEntrante
                    {
                        PacketId = parsed.Manifest.PacketId,
                        NodoOrigen = parsed.Manifest.NodoRaiz,
                        IpOrigen = ipOrigen,
                        NombreZip = fileName,
                        AlgoritmoCodigo = parsed.Manifest.AlgoritmoCodigo,
                        FirmaX509Valida = parsed.SignatureValid && parsed.IntegrityValid,
                        RutaZipTemporal = zipPath,
                        Estado = "Pendiente",
                        FechaRecepcion = DateTime.Now
                    };

                    using (var db = new AppDbContext())
                    {
                        db.SolicitudesEntrantes.Add(solicitud);
                        await db.SaveChangesAsync();
                    }

                    NodeRuntimeState.NotifyPacketReceived(solicitud);

                    return Results.Ok(new
                    {
                        received = true,
                        solicitud.Id,
                        solicitud.PacketId,
                        solicitud.AlgoritmoCodigo,
                        solicitud.FirmaX509Valida,
                        nodoReceptor = NodeRuntimeState.CurrentNodeId
                    });
                }
                catch (Exception ex)
                {
                    return Results.BadRequest(new { received = false, error = ex.Message });
                }
            });

            // 4. Descifrado Remoto (responde con la llave secreta registrada en SQLite para el PacketId)
            _app.MapGet("/api/crypto/decrypt/{packetId}", (string packetId) =>
            {
                using var db = new AppDbContext();
                var registro = db.RegistrosCifrados.FirstOrDefault(r => r.PacketId == packetId);
                if (registro == null)
                {
                    return Results.NotFound(new RemoteDecryptResponse
                    {
                        Success = false,
                        PacketId = packetId,
                        Message = "PacketId no encontrado en este nodo."
                    });
                }

                return Results.Ok(new RemoteDecryptResponse
                {
                    Success = true,
                    PacketId = registro.PacketId,
                    AlgoritmoCodigo = registro.AlgoritmoCodigo,
                    LlaveSecretaBase64 = registro.LlaveSecretaBase64,
                    ParametrosPublicosJson = registro.ParametrosPublicosJson,
                    NodoRaiz = registro.NodoRaiz,
                    FirmaRaizBase64 = registro.FirmaRaizBase64,
                    Message = $"Llave entregada por {NodeRuntimeState.CurrentNodeId}."
                });
            });

            await _app.StartAsync(_cts.Token);
            NodeRuntimeState.ApiPort = port;
            NodeRuntimeState.ApiOnline = true;
        }
        catch
        {
            NodeRuntimeState.ApiOnline = false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app != null)
        {
            try
            {
                await _app.StopAsync(TimeSpan.FromSeconds(2));
                await _app.DisposeAsync();
            }
            catch { }
        }
        _cts?.Dispose();
        NodeRuntimeState.ApiOnline = false;
    }
}

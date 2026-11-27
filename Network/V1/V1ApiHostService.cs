using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;

namespace ModuloCrypto.Network.V1;

/// <summary>
/// Servidor ASP.NET Core Minimal API embebido de la Versión 1.0 (Legado ModuloCrypto + compatibilidad CentroCiberseguridad.Web v1).
/// Escucha en http://0.0.0.0:5000 (CORS habilitado, límite 100 MB).
/// </summary>
public sealed class V1ApiHostService : IAsyncDisposable
{
    private const long MaxPackageSizeBytes = 104_857_600; // 100 MB
    private WebApplication? _app;
    private CancellationTokenSource? _cts;

    public string LastStartupError { get; private set; } = string.Empty;

    public async Task<bool> StartAsync(int port = 5000)
    {
        try
        {
            LastStartupError = string.Empty;
            _cts = new CancellationTokenSource();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = MaxPackageSizeBytes;
            });

            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = MaxPackageSizeBytes;
                options.ValueLengthLimit = int.MaxValue;
            });

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                    policy.AllowAnyOrigin()
                          .AllowAnyMethod()
                          .AllowAnyHeader());
            });

            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

            _app = builder.Build();
            _app.UseCors();

            // 1. GET /api/health
            _app.MapGet("/api/health", () => Results.Ok(new V1NodeHealthResponse
            {
                Status = "Online",
                NodeId = NodeRuntimeState.CurrentNodeId,
                Port = port,
                X509Subject = V1CertificateService.Subject,
                X509Thumbprint = V1CertificateService.GetThumbprintSha256Hex(),
                SupportedAlgorithms = CryptoCatalog.OfficialAlgorithms.Count,
                TimestampUtc = DateTime.UtcNow
            }));

            // 2. GET /api/status
            _app.MapGet("/api/status", () => Results.Ok(new
            {
                nodeId = NodeRuntimeState.CurrentNodeId,
                protocolVersion = "1.0",
                status = "online",
                acceptingPackages = true,
                certificateThumbprint = V1CertificateService.GetThumbprintSha256Hex()
            }));

            // 3. GET /api/algorithms
            _app.MapGet("/api/algorithms", () => Results.Ok(CryptoCatalog.OfficialAlgorithms));

            // 4. POST /api/packets/receive
            _app.MapPost("/api/packets/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, returnAccepted202: false));

            // 5. POST /api/requests/receive
            _app.MapPost("/api/requests/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, returnAccepted202: true));

            // 6. GET /api/crypto/decrypt/{packetId}
            _app.MapGet("/api/crypto/decrypt/{packetId}", (string packetId) =>
            {
                using var db = new AppDbContext();
                var registro = db.RegistrosCifrados.FirstOrDefault(r => r.PacketId == packetId);
                if (registro == null)
                {
                    return Results.NotFound(new V1RemoteDecryptResponse
                    {
                        Success = false,
                        PacketId = packetId,
                        Message = "PacketId no encontrado en este nodo."
                    });
                }

                return Results.Ok(new V1RemoteDecryptResponse
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
            return true;
        }
        catch (Exception ex)
        {
            LastStartupError = ex.Message;
            NodeRuntimeState.ApiOnline = false;
            return false;
        }
    }

    private static async Task<IResult> ProcessIncomingZipAsync(HttpRequest request, bool returnAccepted202)
    {
        string remoteIp = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        string endpointPath = request.Path.HasValue ? request.Path.Value! : "/api/packets/receive";
        string nodeHeader = request.Headers.TryGetValue("X-CC-Node-Id", out var hNode) && !string.IsNullOrWhiteSpace(hNode)
            ? hNode.ToString()
            : "NODO-??";

        try
        {
            string incomingDir = AppDbContext.IncomingPacketsDirectory;
            Directory.CreateDirectory(incomingDir);

            string fileName = $"packet_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}.zip";
            string zipPath = Path.Combine(incomingDir, fileName);

            if (request.HasFormContentType && request.Form.Files.Count > 0)
            {
                var file = request.Form.Files.GetFile("package")
                           ?? request.Form.Files.GetFile("file")
                           ?? request.Form.Files[0];

                if (!string.IsNullOrWhiteSpace(file.FileName))
                    fileName = Path.GetFileName(file.FileName);

                zipPath = Path.Combine(incomingDir, $"{Guid.NewGuid().ToString("N")[..8]}_{fileName}");
                await using var fs = File.Create(zipPath);
                await file.CopyToAsync(fs);
            }
            else
            {
                await using var fs = File.Create(zipPath);
                await request.Body.CopyToAsync(fs);
            }

            var parsed = V1PacketZipService.ReadPacketZip(zipPath);
            string ipOrigen = request.HttpContext.Connection.RemoteIpAddress?.ToString()
                              ?? (!string.IsNullOrWhiteSpace(parsed.Manifest.SourceIp) ? parsed.Manifest.SourceIp : "127.0.0.1");

            var solicitud = new SolicitudEntrante
            {
                PacketId = parsed.Manifest.PacketId,
                NodoOrigen = parsed.Manifest.RutaSaltos.LastOrDefault() ?? parsed.Manifest.NodoRaiz,
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

            NodeRuntimeState.AddNetworkLog(
                ipOrigen,
                solicitud.NodoOrigen,
                endpointPath,
                returnAccepted202 ? 202 : 200,
                $"accepted ({solicitud.AlgoritmoCodigo}, zip={fileName})");

            NodeRuntimeState.NotifyPacketReceived(solicitud);

            if (returnAccepted202)
            {
                return Results.Accepted($"/api/requests/{solicitud.Id}", new
                {
                    requestId = solicitud.Id,
                    packetId = solicitud.PacketId,
                    status = "Pendiente",
                    zipFileName = fileName,
                    algorithmCode = solicitud.AlgoritmoCodigo,
                    signatureValid = solicitud.FirmaX509Valida,
                    receiverNode = NodeRuntimeState.CurrentNodeId
                });
            }

            return Results.Ok(new
            {
                Success = true,
                solicitud.PacketId,
                solicitud.AlgoritmoCodigo,
                SignatureValid = solicitud.FirmaX509Valida,
                ReceiverNode = NodeRuntimeState.CurrentNodeId,
                Message = "Paquete .zip recibido y registrado en Bandeja de Solicitudes."
            });
        }
        catch (Exception ex)
        {
            NodeRuntimeState.AddNetworkLog(remoteIp, nodeHeader, endpointPath, 400, $"E-BAD-REQUEST: {ex.Message}");
            return Results.BadRequest(new { Success = false, Error = ex.Message });
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
            _app = null;
        }
        _cts?.Dispose();
        _cts = null;
        NodeRuntimeState.ApiOnline = false;
    }
}

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;

namespace ModuloCrypto.Network;

/// <summary>
/// Servidor ASP.NET Core Minimal API embebido con soporte dual para ModuloCrypto y CentroCiberseguridad.Web.
/// </summary>
public sealed class ApiHostService : IAsyncDisposable
{
    private const long MaxPackageSizeBytes = 104_857_600; // 100 MB (cubre holgadamente el mínimo de 50 MB)
    private WebApplication? _app;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(int port = 5000)
    {
        try
        {
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

            // 1. Health / Descubrimiento nativo de ModuloCrypto
            _app.MapGet("/api/health", () => Results.Ok(new NodeHealthResponse
            {
                Status = "Online",
                NodeId = NodeRuntimeState.CurrentNodeId,
                Port = port,
                X509Subject = NodeCertificateService.Subject,
                X509Thumbprint = NodeCertificateService.GetThumbprintSha256Hex(),
                SupportedAlgorithms = CryptoCatalog.OfficialAlgorithms.Count,
                TimestampUtc = DateTime.UtcNow
            }));

            // 2. Status / Descubrimiento compatible con CentroCiberseguridad.Web
            _app.MapGet("/api/status", () => Results.Ok(new
            {
                nodeId = NodeRuntimeState.CurrentNodeId,
                protocolVersion = "1.0",
                status = "online",
                acceptingPackages = true,
                certificateThumbprint = NodeCertificateService.GetThumbprintSha256Hex()
            }));

            // 3. Catálogo oficial de 21 algoritmos
            _app.MapGet("/api/algorithms", () => Results.Ok(CryptoCatalog.OfficialAlgorithms));

            // 4. Recepción de paquetes .zip nativa de ModuloCrypto
            _app.MapPost("/api/packets/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, returnAccepted202: false));

            // 5. Recepción de paquetes .zip compatible con CentroCiberseguridad.Web
            _app.MapPost("/api/requests/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, returnAccepted202: true));

            // 6. Descifrado Remoto (responde con la llave secreta registrada en SQLite para el PacketId)
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

    private static async Task<IResult> ProcessIncomingZipAsync(HttpRequest request, bool returnAccepted202)
    {
        if (request.ContentLength.HasValue && request.ContentLength.Value > MaxPackageSizeBytes)
        {
            return Results.BadRequest(new
            {
                received = false,
                error = "El paquete .zip excede el límite máximo permitido."
            });
        }

        string incomingDir = Path.Combine(AppContext.BaseDirectory, "IncomingPackets");
        Directory.CreateDirectory(incomingDir);

        string headerSourceNode = request.Headers["X-Source-Node"].FirstOrDefault() ?? string.Empty;
        string headerPacketId = request.Headers["X-Packet-Id"].FirstOrDefault() ?? string.Empty;

        string fileName = $"packet_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString()[..6]}.zip";
        string zipPath = Path.Combine(incomingDir, fileName);

        try
        {
            if (request.HasFormContentType && request.Form.Files.Count > 0)
            {
                var file = request.Form.Files.GetFile("package")
                           ?? request.Form.Files.GetFile("file")
                           ?? request.Form.Files[0];

                if (file.Length > MaxPackageSizeBytes)
                {
                    return Results.BadRequest(new
                    {
                        received = false,
                        error = "El archivo adjunto excede el límite permitido."
                    });
                }

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
                if (fs.Length > MaxPackageSizeBytes)
                {
                    fs.Close();
                    File.Delete(zipPath);
                    return Results.BadRequest(new
                    {
                        received = false,
                        error = "El flujo recibido excede el límite permitido."
                    });
                }
            }

            string ipOrigen = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            var parsed = PacketZipService.ReadPacketZip(zipPath);

            string packetId = !string.IsNullOrWhiteSpace(parsed.Manifest.PacketId)
                ? parsed.Manifest.PacketId
                : (!string.IsNullOrWhiteSpace(headerPacketId) ? headerPacketId : Guid.NewGuid().ToString());

            string nodoOrigen = !string.IsNullOrWhiteSpace(parsed.Manifest.NodoRaiz) && parsed.Manifest.NodoRaiz != "NODO-EXT"
                ? parsed.Manifest.NodoRaiz
                : (!string.IsNullOrWhiteSpace(headerSourceNode) ? headerSourceNode : parsed.Manifest.NodoRaiz);

            if (string.IsNullOrWhiteSpace(nodoOrigen))
                nodoOrigen = "NODO-EXT";

            var solicitud = new SolicitudEntrante
            {
                PacketId = packetId,
                NodoOrigen = nodoOrigen,
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

            if (returnAccepted202)
            {
                return Results.Accepted($"/api/requests/{solicitud.Id}", new
                {
                    requestId = solicitud.Id,
                    status = "Pendiente",
                    zipFileName = fileName,
                    algorithmCode = solicitud.AlgoritmoCodigo,
                    signatureValid = solicitud.FirmaX509Valida
                });
            }

            return Results.Ok(new
            {
                received = true,
                requestId = solicitud.Id,
                solicitud.Id,
                solicitud.PacketId,
                status = "Pendiente",
                zipFileName = fileName,
                algorithmCode = solicitud.AlgoritmoCodigo,
                solicitud.AlgoritmoCodigo,
                signatureValid = solicitud.FirmaX509Valida,
                solicitud.FirmaX509Valida,
                nodoReceptor = NodeRuntimeState.CurrentNodeId
            });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { received = false, error = ex.Message });
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

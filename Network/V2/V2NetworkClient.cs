using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security.Strategies;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Cliente HTTP/HTTPS v2.0 con SocketsHttpHandler optimizado (UseProxy=false), pinning TLS SHA-256 TOFU con fallback HTTP,
/// cabeceras obligatorias X-CC-Node / X-CC-Protocol: 2.0 / X-CC-Request-Id, caché de perfiles GET /api/algorithms,
/// delegación criptográfica remota (/api/crypto/forward e inverse con CC-ENV-1) y escaneo de subred /24.
/// </summary>
public static class V2NetworkClient
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        UseProxy = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(3)
    })
    {
        Timeout = TimeSpan.FromSeconds(35)
    };

    private static readonly ConcurrentDictionary<string, HttpClient> PinnedHttpsClients = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, Dictionary<string, V2AlgorithmProfileDto>> PeerAlgorithmProfiles = new(StringComparer.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static DateTime _lastAutoSubnetScanUtc = DateTime.MinValue;
    public static readonly TimeSpan AutoScanCooldown = TimeSpan.FromMinutes(5);

    private static HttpClient GetOrCreatePinnedHttpsClient(PeerNode peer)
    {
        string expectedThumb = (peer.PinnedThumbprintSha256 ?? peer.CertThumbprint ?? string.Empty).Trim().ToUpperInvariant();
        string cacheKey = $"{peer.IpAddress}:{peer.HttpsPort ?? 0}:{expectedThumb}";
        return PinnedHttpsClients.GetOrAdd(cacheKey, _ =>
        {
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                ConnectTimeout = TimeSpan.FromSeconds(3)
            };
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                if (cert == null || string.IsNullOrWhiteSpace(expectedThumb))
                    return false;
                string actualThumb = Convert.ToHexString(SHA256.HashData(cert.GetRawCertData()));
                return V2CertificateService.FixedTimeEqualsHex(actualThumb, expectedThumb);
            };
            return new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(35)
            };
        });
    }

    private static bool CanUsePinnedHttps(PeerNode peer)
    {
        return peer.HttpsPort is > 0 and <= 65535 &&
               peer.IsConfirmed &&
               !string.IsNullOrWhiteSpace(peer.PinnedThumbprintSha256) &&
               !peer.HasThumbprintMismatch;
    }

    private static async Task<HttpResponseMessage> SendWithHttpsFallbackAsync(
        PeerNode peer,
        string relativePath,
        Func<string, HttpRequestMessage> requestFactory,
        CancellationToken ct = default)
    {
        string path = relativePath.StartsWith('/') ? relativePath : "/" + relativePath;

        if (CanUsePinnedHttps(peer))
        {
            string httpsBase = $"https://{peer.IpAddress}:{peer.HttpsPort!.Value}";
            try
            {
                var tlsClient = GetOrCreatePinnedHttpsClient(peer);
                using var httpsReq = requestFactory(httpsBase + path);
                return await tlsClient.SendAsync(httpsReq, ct);
            }
            catch (HttpRequestException)
            {
                // Fallback transparente a HTTP si el peer cerró el puerto TLS o el proxy local no soporta HTTPS
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
        }

        string httpBase = peer.BaseUrl.TrimEnd('/');
        using var httpReq = requestFactory(httpBase + path);
        return await Http.SendAsync(httpReq, ct);
    }

    private static void AddStandardV2Headers(HttpRequestMessage req, string? requestId = null)
    {
        string reqId = string.IsNullOrWhiteSpace(requestId)
            ? Guid.NewGuid().ToString("D").ToLowerInvariant()
            : requestId.Trim().ToLowerInvariant();

        req.Headers.TryAddWithoutValidation("X-CC-Node", NodeRuntimeState.CurrentNodeId);
        req.Headers.TryAddWithoutValidation("X-CC-Protocol", "2.0");
        req.Headers.TryAddWithoutValidation("X-CC-Request-Id", reqId);
    }

    public static bool TryGetCachedAlgorithmProfile(string? nodeId, string algorithmCode, out V2AlgorithmProfileDto? profile)
    {
        profile = null;
        if (string.IsNullOrWhiteSpace(nodeId) || string.IsNullOrWhiteSpace(algorithmCode))
            return false;

        if (!PeerAlgorithmProfiles.TryGetValue(nodeId.Trim().ToUpperInvariant(), out var byAlg))
            return false;

        return byAlg.TryGetValue(algorithmCode.Trim().ToUpperInvariant(), out profile);
    }

    public static async Task<IReadOnlyDictionary<string, V2AlgorithmProfileDto>> FetchPeerAlgorithmsAsync(
        PeerNode peer,
        int timeoutMs = 1500)
    {
        var map = new Dictionary<string, V2AlgorithmProfileDto>(StringComparer.OrdinalIgnoreCase);
        if (peer == null || string.IsNullOrWhiteSpace(peer.IpAddress))
            return map;

        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var resp = await SendWithHttpsFallbackAsync(peer, "/api/algorithms", url =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                AddStandardV2Headers(req);
                return req;
            }, cts.Token);

            if (!resp.IsSuccessStatusCode)
                return map;

            string body = await resp.Content.ReadAsStringAsync(cts.Token);
            using var doc = JsonDocument.Parse(body);

            JsonElement arrayEl = default;
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                arrayEl = doc.RootElement;
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (string.Equals(prop.Name, "algorithms", StringComparison.OrdinalIgnoreCase) &&
                        prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        arrayEl = prop.Value;
                        break;
                    }
                }
            }

            if (arrayEl.ValueKind != JsonValueKind.Array)
                return map;

            var discoveredCodes = new List<string>();
            foreach (var item in arrayEl.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                if (!KeyInputParser.TryGetJsonString(item, out string code, "algorithmCode", "code", "algorithm"))
                    continue;

                string normCode = code.Trim().ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(normCode)) continue;

                var dto = JsonSerializer.Deserialize<V2AlgorithmProfileDto>(item.GetRawText(), JsonOpts);
                if (dto == null) continue;

                map[normCode] = dto;
                discoveredCodes.Add(normCode);
            }

            if (map.Count > 0 && NodeRuntimeState.IsValidNodeId(peer.NodeId))
            {
                PeerAlgorithmProfiles[peer.NodeId.Trim().ToUpperInvariant()] = map;
                if (string.IsNullOrWhiteSpace(peer.AlgorithmsJson) || peer.AlgorithmsJson == "[]")
                {
                    peer.AlgorithmsJson = JsonSerializer.Serialize(discoveredCodes.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
                }
            }
        }
        catch
        {
        }

        return map;
    }

    public static async Task<V2AlgorithmProfileDto?> GetOrFetchPeerAlgorithmProfileAsync(
        PeerNode peer,
        string algorithmCode,
        int timeoutMs = 1500)
    {
        if (TryGetCachedAlgorithmProfile(peer.NodeId, algorithmCode, out var cached) && cached != null)
            return cached;

        var fetched = await FetchPeerAlgorithmsAsync(peer, timeoutMs);
        fetched.TryGetValue(algorithmCode.Trim().ToUpperInvariant(), out var profile);
        return profile;
    }

    public static async Task<(bool Online, string Latency, PeerStatusResponse? Info)> PingNodeAsync(
        PeerNode node,
        int? customTimeoutMs = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(customTimeoutMs ?? 1500);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{node.BaseUrl}/api/status");
            AddStandardV2Headers(req);

            var resp = await Http.SendAsync(req, cts.Token);
            sw.Stop();

            if (!resp.IsSuccessStatusCode)
                return (false, "HTTP " + (int)resp.StatusCode, null);

            string body = await resp.Content.ReadAsStringAsync(cts.Token);
            var status = JsonSerializer.Deserialize<PeerStatusResponse>(body, JsonOpts);
            if (status == null || !string.Equals(status.ProtocolVersion, "2.0", StringComparison.Ordinal))
                return (false, "Protocolo != 2.0", null);

            node.ProtocolType = "v2.0";
            node.LastSeenUtc = DateTime.UtcNow;
            node.LastLatency = $"{sw.ElapsedMilliseconds} ms";

            if (NodeRuntimeState.IsValidNodeId(status.NodeId))
                node.NodeId = status.NodeId.ToUpperInvariant();
            if (status.TeamNumber > 0)
                node.TeamNumber = status.TeamNumber;
            if (status.HttpPort is > 0 and <= 65535)
                node.Port = status.HttpPort;
            if (status.HttpsPort is > 0 and <= 65535)
                node.HttpsPort = status.HttpsPort;
            if (status.Algorithms is { Count: > 0 })
            {
                node.AlgorithmsJson = JsonSerializer.Serialize(status.Algorithms);
                node.RoleLabel = $"Equipo {node.TeamNumber:D2} ({string.Join(", ", status.Algorithms)})";
            }

            ApplyTofuThumbprintCheck(node, status.CertificateThumbprintSha256);

            if (!node.HasThumbprintMismatch)
            {
                await FetchAndValidatePeerCertificateAsync(node, customTimeoutMs ?? 1500);
                await FetchPeerAlgorithmsAsync(node, customTimeoutMs ?? 1500);
            }

            AppDbContext.UpsertTrustedPeer(node);
            return (true, node.LastLatency, status);
        }
        catch
        {
            sw.Stop();
            return (false, "Timeout", null);
        }
    }

    public static void ApplyTofuThumbprintCheck(PeerNode peer, string? advertisedThumbprint)
    {
        string cleanThumb = (advertisedThumbprint ?? "").Trim().ToUpperInvariant();
        if (string.IsNullOrWhiteSpace(cleanThumb)) return;

        peer.CertThumbprint = cleanThumb;

        if (peer.IsConfirmed &&
            !string.IsNullOrWhiteSpace(peer.PinnedThumbprintSha256) &&
            !V2CertificateService.FixedTimeEqualsHex(peer.PinnedThumbprintSha256, cleanThumb))
        {
            peer.HasThumbprintMismatch = true;
            peer.Status = "blocked";
        }
        else
        {
            peer.HasThumbprintMismatch = false;
            peer.Status = "online";
        }
    }

    public static async Task<bool> FetchAndValidatePeerCertificateAsync(PeerNode peer, int timeoutMs = 1500)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var resp = await SendWithHttpsFallbackAsync(peer, "/api/certificate", url =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                AddStandardV2Headers(req);
                return req;
            }, cts.Token);
            if (!resp.IsSuccessStatusCode) return false;

            string body = await resp.Content.ReadAsStringAsync(cts.Token);
            string pem;
            if (body.TrimStart().StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                pem = body.Trim();
            }
            else
            {
                var dto = JsonSerializer.Deserialize<PeerCertificateResponse>(body, JsonOpts);
                pem = dto?.CertificatePem ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(pem)) return false;

            using var cert = V2CertificateService.LoadCertificateFromPemOrBase64(pem);
            if (!V2CertificateService.ValidateCertificateMetadata(cert, peer.NodeId, out _))
            {
                peer.HasThumbprintMismatch = true;
                peer.Status = "blocked";
                return false;
            }

            string actualThumb = V2CertificateService.GetThumbprintSha256Hex(cert);
            if (!string.IsNullOrWhiteSpace(peer.CertThumbprint) &&
                !V2CertificateService.FixedTimeEqualsHex(actualThumb, peer.CertThumbprint))
            {
                peer.HasThumbprintMismatch = true;
                peer.Status = "blocked";
                return false;
            }

            peer.CertificatePem = pem;
            ApplyTofuThumbprintCheck(peer, actualThumb);
            return !peer.HasThumbprintMismatch;
        }
        catch
        {
            return false;
        }
    }

    public static void ConfirmPeerTofu(PeerNode peer)
    {
        if (string.IsNullOrWhiteSpace(peer.CertThumbprint)) return;
        peer.PinnedThumbprintSha256 = peer.CertThumbprint.ToUpperInvariant();
        peer.IsConfirmed = true;
        peer.HasThumbprintMismatch = false;
        peer.Status = "online";
        AppDbContext.UpsertTrustedPeer(peer);
        NodeRuntimeState.NotifyPeerChanged(peer);
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(
        PeerNode targetPeer,
        string zipPath,
        string packetId,
        string packetType = "package")
    {
        if (targetPeer.HasThumbprintMismatch || string.Equals(targetPeer.Status, "blocked", StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"BLOQUEO TOFU (E-CERT-UNTRUSTED): El nodo {targetPeer.NodeId} presentó un cambio de huella X.509. Reconfirma su huella en 'Red de Nodos' antes de enviar paquetes.");
        }

        byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
        if (fileBytes.Length > V2PacketZipService.MaxCompressedZipBytes)
        {
            return (false, "E-SIZE: El paquete .zip supera el límite máximo de 50 MB.");
        }

        string fileName = Path.GetFileName(zipPath);
        string endpointPath = string.Equals(packetType, "result", StringComparison.OrdinalIgnoreCase)
            ? "/api/results/receive"
            : "/api/requests/receive";

        try
        {
            using var resp = await SendWithHttpsFallbackAsync(targetPeer, endpointPath, url =>
            {
                var form = new MultipartFormDataContent();
                var content = new ByteArrayContent(fileBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
                form.Add(content, "package", fileName);

                var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
                AddStandardV2Headers(req, packetId);
                return req;
            });

            string body = await resp.Content.ReadAsStringAsync();

            if (resp.IsSuccessStatusCode)
            {
                targetPeer.Status = "online";
                targetPeer.LastSeenUtc = DateTime.UtcNow;
                string scheme = CanUsePinnedHttps(targetPeer) ? $"https://{targetPeer.IpAddress}:{targetPeer.HttpsPort}{endpointPath}" : targetPeer.BaseUrl.TrimEnd('/') + endpointPath;
                return (true, $"Paquete v2.0 entregado a {scheme}.\nHTTP {(int)resp.StatusCode}: {body}");
            }

            return (false, $"Rechazado por {targetPeer.NodeId} (HTTP {(int)resp.StatusCode}):\n{body}");
        }
        catch (Exception ex)
        {
            return (false, $"Error de conexión hacia {targetPeer.BaseUrl.TrimEnd('/')}{endpointPath}: {ex.Message}");
        }
    }

    /// <summary>
    /// Invoca POST /api/crypto/forward en un nodo proveedor v2.0 (firmando los bytes crudos de 'request' con RSA-PSS-SHA256)
    /// con soporte ADR 0013 para secretos sellados CC-ENV-1 y options específicas por algoritmo.
    /// </summary>
    public static async Task<(bool Success, V2CryptoForwardResponse? Response, string ErrorMessage)> CallRemoteForwardAsync(
        PeerNode providerPeer,
        string algorithmCode,
        byte[] payloadBytes,
        string fileName,
        string extension,
        int? keySizeBits = 256,
        Dictionary<string, string>? secretsDictionary = null,
        Dictionary<string, string>? options = null)
    {
        if (providerPeer.HasThumbprintMismatch)
            return (false, null, $"El nodo {providerPeer.NodeId} está bloqueado por cambio de huella TOFU.");

        string algCode = algorithmCode.Trim().ToUpperInvariant();
        string requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        string packetId = Guid.NewGuid().ToString("D").ToLowerInvariant();

        var effectiveOptions = options is { Count: > 0 }
            ? new Dictionary<string, string>(options, StringComparer.OrdinalIgnoreCase)
            : null;
        var effectiveSecrets = secretsDictionary is { Count: > 0 }
            ? new Dictionary<string, string>(secretsDictionary, StringComparer.Ordinal)
            : null;
        int? effectiveKeySizeBits = keySizeBits is > 0 ? keySizeBits : null;

        if (algCode == "HASHSHA")
        {
            effectiveSecrets = null;
            effectiveKeySizeBits = null;
            effectiveOptions ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!effectiveOptions.TryGetValue("hashAlgorithm", out var hAlg) || string.IsNullOrWhiteSpace(hAlg))
                effectiveOptions["hashAlgorithm"] = "SHA-256";
        }
        else if (algCode == "HMACSHA256")
        {
            effectiveKeySizeBits = null;
            effectiveOptions ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!effectiveOptions.TryGetValue("macAlgorithm", out var mAlg) || string.IsNullOrWhiteSpace(mAlg))
                effectiveOptions["macAlgorithm"] = "HMAC-SHA256";

            if (effectiveSecrets != null &&
                effectiveSecrets.TryGetValue("key", out var rawHmacKey) &&
                !string.IsNullOrWhiteSpace(rawHmacKey))
            {
                effectiveSecrets["key"] = KeyInputParser.NormalizeHmacKeyBase64(rawHmacKey);
            }
        }

        CcHybridEnvelope? sealedSecrets = null;
        if (effectiveSecrets is { Count: > 0 })
        {
            if (string.IsNullOrWhiteSpace(providerPeer.CertificatePem))
                await FetchAndValidatePeerCertificateAsync(providerPeer);

            if (string.IsNullOrWhiteSpace(providerPeer.CertificatePem))
                return (false, null, $"No se pudo obtener el certificado X.509 de {providerPeer.NodeId} para sellar 'secrets' CC-ENV-1.");

            using var providerCert = V2CertificateService.LoadCertificateFromPemOrBase64(providerPeer.CertificatePem);
            sealedSecrets = V2EnvelopeService.SealSecretsDictionary(
                effectiveSecrets,
                providerCert,
                providerPeer.NodeId,
                requestId);
        }

        var fwdReq = new V2CryptoForwardRequest
        {
            RequestId = requestId,
            PacketId = packetId,
            RequesterNode = NodeRuntimeState.CurrentNodeId,
            TargetNode = providerPeer.NodeId,
            AlgorithmCode = algCode,
            Operation = "forward",
            OriginalFileName = fileName,
            OriginalExtension = extension,
            KeySizeBits = effectiveKeySizeBits,
            Secrets = sealedSecrets,
            Options = effectiveOptions,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        byte[] rawRequestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fwdReq));
        string requestSigBase64 = V2CertificateService.SignDataPss(rawRequestBytes);
        string requesterCertPem = V2CertificateService.ExportPublicCertPem();
        string uploadFileName = string.IsNullOrWhiteSpace(fileName) ? "payload.bin" : fileName;

        using var resp = await SendWithHttpsFallbackAsync(providerPeer, "/api/crypto/forward", url =>
        {
            var form = new MultipartFormDataContent();
            var reqContent = new ByteArrayContent(rawRequestBytes);
            reqContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            form.Add(reqContent, "request", "request.json");
            form.Add(new StringContent(requestSigBase64, Encoding.UTF8), "requestSignature");
            form.Add(new StringContent(requesterCertPem, Encoding.UTF8), "requesterCertificate");

            var payloadContent = new ByteArrayContent(payloadBytes);
            payloadContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            form.Add(payloadContent, "payload", uploadFileName);

            var httpReq = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
            AddStandardV2Headers(httpReq, requestId);
            return httpReq;
        });

        string body = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
            return (false, null, $"HTTP {(int)resp.StatusCode}: {body}");

        var parsed = JsonSerializer.Deserialize<V2CryptoForwardResponse>(body, JsonOpts);
        return (parsed != null, parsed, parsed != null ? "OK" : "Respuesta vacía");
    }

    /// <summary>
    /// Invoca POST /api/crypto/inverse en un nodo proveedor v2.0 (soportando respuesta directa .zip o job 202 Accepted)
    /// y abre el sobre CC-ENV-1 de resultado.enc + manifest.resultEnvelope (con AAD = packetId).
    /// </summary>
    public static async Task<(bool Success, byte[]? DecryptedPlainBytes, V2ParsedZipPacket? ResultZip, string ErrorMessage)> CallRemoteInverseAsync(
        PeerNode providerPeer,
        string algorithmCode,
        string packetId,
        byte[] cipherOrPackageBytes,
        Dictionary<string, string> publicParameters,
        CcHybridEnvelope? secretEnvelope = null,
        string? keyId = null,
        byte[]? rawSecretBytesToSeal = null,
        Dictionary<string, string>? secretsDictionary = null,
        Dictionary<string, string>? options = null)
    {
        if (providerPeer.HasThumbprintMismatch)
            return (false, null, null, $"El nodo {providerPeer.NodeId} está bloqueado por cambio de huella TOFU.");

        string algCode = algorithmCode.Trim().ToUpperInvariant();
        string requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();

        var effectiveOptions = options is { Count: > 0 }
            ? new Dictionary<string, string>(options, StringComparer.OrdinalIgnoreCase)
            : null;
        var effectiveSecrets = secretsDictionary is { Count: > 0 }
            ? new Dictionary<string, string>(secretsDictionary, StringComparer.Ordinal)
            : null;

        if (algCode == "HASHSHA")
        {
            effectiveSecrets = null;
            secretEnvelope = null;
            rawSecretBytesToSeal = null;
            effectiveOptions ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!effectiveOptions.TryGetValue("hashAlgorithm", out var hAlg) || string.IsNullOrWhiteSpace(hAlg))
            {
                effectiveOptions["hashAlgorithm"] =
                    publicParameters.TryGetValue("hashAlgorithm", out var pubH) && !string.IsNullOrWhiteSpace(pubH)
                        ? pubH
                        : "SHA-256";
            }
        }
        else if (algCode == "HMACSHA256")
        {
            effectiveOptions ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!effectiveOptions.TryGetValue("macAlgorithm", out var mAlg) || string.IsNullOrWhiteSpace(mAlg))
            {
                effectiveOptions["macAlgorithm"] =
                    publicParameters.TryGetValue("macAlgorithm", out var pubM) && !string.IsNullOrWhiteSpace(pubM)
                        ? pubM
                        : "HMAC-SHA256";
            }

            if (effectiveSecrets != null &&
                effectiveSecrets.TryGetValue("key", out var rawHmacKey) &&
                !string.IsNullOrWhiteSpace(rawHmacKey))
            {
                effectiveSecrets["key"] = KeyInputParser.NormalizeHmacKeyBase64(rawHmacKey);
            }
            else if (rawSecretBytesToSeal is { Length: > 0 and < 32 })
            {
                rawSecretBytesToSeal = SHA256.HashData(rawSecretBytesToSeal);
            }
        }

        bool needsProviderCertToSeal =
            effectiveSecrets is { Count: > 0 } ||
            rawSecretBytesToSeal is { Length: > 0 } ||
            (secretEnvelope != null && string.Equals(providerPeer.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(providerPeer.CertificatePem))
            await FetchAndValidatePeerCertificateAsync(providerPeer);

        if (needsProviderCertToSeal && string.IsNullOrWhiteSpace(providerPeer.CertificatePem))
            return (false, null, null, $"No se pudo obtener el certificado X.509 de {providerPeer.NodeId} para sellar el sobre CC-ENV-1.");

        if (!string.IsNullOrWhiteSpace(providerPeer.CertificatePem))
        {
            using var providerCert = V2CertificateService.LoadCertificateFromPemOrBase64(providerPeer.CertificatePem);

            if (effectiveSecrets is { Count: > 0 })
            {
                secretEnvelope = V2EnvelopeService.SealSecretsDictionary(
                    effectiveSecrets,
                    providerCert,
                    providerPeer.NodeId,
                    requestId);
            }
            else if (rawSecretBytesToSeal is { Length: > 0 })
            {
                string keyB64 = Convert.ToBase64String(rawSecretBytesToSeal);
                secretEnvelope = V2EnvelopeService.SealSecretsDictionary(
                    new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = keyB64 },
                    providerCert,
                    providerPeer.NodeId,
                    requestId);
            }
            else if (secretEnvelope != null &&
                     string.Equals(providerPeer.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var openedDict = V2EnvelopeService.OpenSecretsDictionary(secretEnvelope, string.Empty, packetId);
                    secretEnvelope = V2EnvelopeService.SealSecretsDictionary(openedDict, providerCert, providerPeer.NodeId, requestId);
                }
                catch { }
            }
        }

        var invReq = new V2CryptoInverseRequest
        {
            RequestId = requestId,
            PacketId = packetId,
            RequesterNode = NodeRuntimeState.CurrentNodeId,
            TargetNode = providerPeer.NodeId,
            AlgorithmCode = algCode,
            Operation = "inverse",
            KeyId = string.IsNullOrWhiteSpace(keyId) ? null : keyId.Trim(),
            Secrets = secretEnvelope,
            PublicParameters = publicParameters,
            Options = effectiveOptions,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        byte[] rawRequestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(invReq));
        string requestSigBase64 = V2CertificateService.SignDataPss(rawRequestBytes);
        string requesterCertPem = V2CertificateService.ExportPublicCertPem();
        bool isZipPackage = cipherOrPackageBytes.Length >= 4 &&
                            cipherOrPackageBytes[0] == 0x50 &&
                            cipherOrPackageBytes[1] == 0x4B &&
                            cipherOrPackageBytes[2] == 0x03 &&
                            cipherOrPackageBytes[3] == 0x04;

        using var resp = await SendWithHttpsFallbackAsync(providerPeer, "/api/crypto/inverse", url =>
        {
            var form = new MultipartFormDataContent();
            var reqContent = new ByteArrayContent(rawRequestBytes);
            reqContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            form.Add(reqContent, "request", "request.json");
            form.Add(new StringContent(requestSigBase64, Encoding.UTF8), "requestSignature");
            form.Add(new StringContent(requesterCertPem, Encoding.UTF8), "requesterCertificate");

            var payloadContent = new ByteArrayContent(cipherOrPackageBytes);
            if (isZipPackage)
            {
                payloadContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
                form.Add(payloadContent, "package", "package.zip");
            }
            else
            {
                payloadContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                form.Add(payloadContent, "payload", "datos.enc");
            }

            var httpReq = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
            AddStandardV2Headers(httpReq, requestId);
            return httpReq;
        });

        if (!resp.IsSuccessStatusCode)
        {
            string errBody = await resp.Content.ReadAsStringAsync();
            return (false, null, null, $"HTTP {(int)resp.StatusCode}: {errBody}");
        }

        byte[] resultZipBytes;
        if ((int)resp.StatusCode == 202)
        {
            string jobJson = await resp.Content.ReadAsStringAsync();
            var jobAccepted = JsonSerializer.Deserialize<V2JobAcceptedResponse>(jobJson, JsonOpts);
            if (jobAccepted == null || string.IsNullOrWhiteSpace(jobAccepted.JobId))
                return (false, null, null, "El proveedor devolvió 202 Accepted sin jobId válido.");

            var (pollOk, polledBytes, pollErr) = await PollJobResultZipAsync(providerPeer, jobAccepted.JobId, requestId);
            if (!pollOk || polledBytes == null)
                return (false, null, null, pollErr);

            resultZipBytes = polledBytes;
        }
        else
        {
            resultZipBytes = await resp.Content.ReadAsByteArrayAsync();
        }

        string tempResZip = Path.Combine(Path.GetTempPath(), $"RES_recv_{Guid.NewGuid():N}.zip");
        try
        {
            await File.WriteAllBytesAsync(tempResZip, resultZipBytes);
            var parsedRes = V2PacketZipService.ReadPacketZip(tempResZip, enforceStrictSignature: true);

            byte[] plainBytes;
            if (parsedRes.Manifest.ResultEnvelope != null)
            {
                // Estándar v2.0 (Sección 8.3): el cifrado va en resultado.enc y los metadatos CC-ENV-1 (sin ciphertextBase64) en manifest.resultEnvelope con AAD = packetId
                plainBytes = V2EnvelopeService.Open(
                    parsedRes.Manifest.ResultEnvelope,
                    expectedAadContext: parsedRes.Manifest.PacketId,
                    detachedCiphertext: parsedRes.PayloadBytes,
                    fallbackAadContext: requestId);
            }
            else
            {
                // Alias tolerante por si un nodo tercero serializó el sobre JSON dentro de resultado.enc
                string envJson = Encoding.UTF8.GetString(parsedRes.PayloadBytes);
                var inlineEnv = JsonSerializer.Deserialize<CcHybridEnvelope>(envJson, JsonOpts)
                    ?? throw new PacketValidationException("E-ENV-DECRYPT", 401, "El paquete result no contiene resultEnvelope en manifest.json ni en resultado.enc.");
                plainBytes = V2EnvelopeService.Open(
                    inlineEnv,
                    expectedAadContext: parsedRes.Manifest.PacketId,
                    fallbackAadContext: requestId);
            }

            return (true, plainBytes, parsedRes, "OK");
        }
        finally
        {
            try { if (File.Exists(tempResZip)) File.Delete(tempResZip); } catch { }
        }
    }

    private static async Task<(bool Success, byte[]? ResultBytes, string ErrorMessage)> PollJobResultZipAsync(
        PeerNode providerPeer,
        string jobId,
        string requestId)
    {
        string statusPath = $"/api/jobs/{jobId}";
        string resultPath = $"/api/jobs/{jobId}/result";

        for (int attempt = 0; attempt < 15; attempt++)
        {
            await Task.Delay(1500);

            using var statusResp = await SendWithHttpsFallbackAsync(providerPeer, statusPath, url =>
            {
                var statusReq = new HttpRequestMessage(HttpMethod.Get, url);
                AddStandardV2Headers(statusReq, requestId);
                return statusReq;
            });

            if (!statusResp.IsSuccessStatusCode)
            {
                string err = await statusResp.Content.ReadAsStringAsync();
                return (false, null, $"Error consultando estado del job {jobId}: {err}");
            }

            string body = await statusResp.Content.ReadAsStringAsync();
            var statusDto = JsonSerializer.Deserialize<V2JobStatusResponse>(body, JsonOpts);
            if (statusDto == null) continue;

            if (string.Equals(statusDto.Status, "failed", StringComparison.OrdinalIgnoreCase))
                return (false, null, $"El trabajo asíncrono {jobId} falló ({statusDto.ErrorCode}): {statusDto.ErrorDetail}");

            if (string.Equals(statusDto.Status, "completed", StringComparison.OrdinalIgnoreCase))
            {
                using var resResp = await SendWithHttpsFallbackAsync(providerPeer, resultPath, url =>
                {
                    var resReq = new HttpRequestMessage(HttpMethod.Get, url);
                    AddStandardV2Headers(resReq, requestId);
                    return resReq;
                });

                if (!resResp.IsSuccessStatusCode)
                {
                    string err = await resResp.Content.ReadAsStringAsync();
                    return (false, null, $"Error descargando resultado del job {jobId}: {err}");
                }
                return (true, await resResp.Content.ReadAsByteArrayAsync(), "OK");
            }
        }

        return (false, null, $"Tiempo de espera agotado sondeando el trabajo asíncrono {jobId}.");
    }

    public static async Task<List<PeerNode>> ScanLocalhostPortsAsync(int startPort = 5001, int endPort = 5020)
    {
        var found = new ConcurrentBag<PeerNode>();
        var ports = Enumerable.Range(startPort, Math.Max(1, endPort - startPort + 1));

        await Parallel.ForEachAsync(ports, async (port, _) =>
        {
            var probe = new PeerNode
            {
                NodeId = $"EQ{Math.Clamp(port - 5000, 1, 99):D2}",
                TeamNumber = Math.Clamp(port - 5000, 1, 99),
                IpAddress = "127.0.0.1",
                Port = port,
                Source = "scan",
                ProtocolType = "v2.0"
            };

            var (online, _, _) = await PingNodeAsync(probe, customTimeoutMs: 500);
            if (online)
            {
                found.Add(probe);
            }
        });

        return found.OrderBy(p => p.Port).ToList();
    }

    public static async Task<(List<PeerNode> Found, bool SkippedByCooldown)> ScanLanSubnetAsync(
        string localIp,
        int startPort = 5001,
        int endPort = 5020,
        bool isAutomaticTrigger = false)
    {
        if (isAutomaticTrigger && (DateTime.UtcNow - _lastAutoSubnetScanUtc) < AutoScanCooldown)
        {
            return (new List<PeerNode>(), true);
        }

        _lastAutoSubnetScanUtc = DateTime.UtcNow;
        var found = new ConcurrentBag<PeerNode>();

        string prefix = "192.168.1.";
        var parts = (localIp ?? "").Split('.');
        if (parts.Length == 4 && parts[0] != "127")
            prefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";

        var targets = new List<(string Ip, int Port)>();
        for (int host = 1; host <= 254; host++)
        {
            string ip = $"{prefix}{host}";
            for (int port = startPort; port <= endPort; port++)
                targets.Add((ip, port));
        }

        using var sem = new SemaphoreSlim(64, 64);
        var tasks = targets.Select(async target =>
        {
            await sem.WaitAsync();
            try
            {
                var probe = new PeerNode
                {
                    NodeId = $"EQ{Math.Clamp(target.Port - 5000, 1, 99):D2}",
                    TeamNumber = Math.Clamp(target.Port - 5000, 1, 99),
                    IpAddress = target.Ip,
                    Port = target.Port,
                    Source = "scan",
                    ProtocolType = "v2.0"
                };

                var (online, _, _) = await PingNodeAsync(probe, customTimeoutMs: 500);
                if (online)
                {
                    found.Add(probe);
                }
            }
            finally
            {
                sem.Release();
            }
        });

        await Task.WhenAll(tasks);
        return (found.OrderBy(p => p.IpAddress).ThenBy(p => p.Port).ToList(), false);
    }
}

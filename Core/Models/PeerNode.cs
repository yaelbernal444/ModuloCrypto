namespace ModuloCrypto.Core.Models;

public class PeerNode
{
    public string NodeId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 5000;
    public string RoleLabel { get; set; } = "Relay Tor";
    public bool IsOnline { get; set; }
    public string LastLatency { get; set; } = "--";
    public string CertThumbprint { get; set; } = "Sin verificar";

    public string BaseUrl => $"http://{IpAddress}:{Port}";
}

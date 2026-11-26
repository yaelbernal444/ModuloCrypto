using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Text;

namespace ModuloCrypto.Core.Data;

public class AppDbContext : DbContext
{
    public static readonly string DatabasePath = Path.Combine(AppContext.BaseDirectory, "ModuloCrypto.db");

    private readonly string _connectionDbPath;

    public AppDbContext()
    {
        _connectionDbPath = DatabasePath;
    }

    public AppDbContext(string customDatabasePath)
    {
        _connectionDbPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;
    }

    public DbSet<Usuario> Usuarios => Set<Usuario>();
    public DbSet<RegistroCifrado> RegistrosCifrados => Set<RegistroCifrado>();
    public DbSet<SolicitudEntrante> SolicitudesEntrantes => Set<SolicitudEntrante>();
    public DbSet<PeerNode> TrustedPeers => Set<PeerNode>();
    public DbSet<SeenPacketEntity> SeenPackets => Set<SeenPacketEntity>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite($"Data Source={_connectionDbPath}");
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.ToTable("Usuarios");
            entity.HasIndex(u => u.NombreUsuario).IsUnique();
        });

        modelBuilder.Entity<RegistroCifrado>(entity =>
        {
            entity.ToTable("RegistrosCifrados");
            entity.HasIndex(r => r.PacketId);
            entity.HasOne(r => r.Usuario)
                  .WithMany(u => u.RegistrosCifrados)
                  .HasForeignKey(r => r.UsuarioId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SolicitudEntrante>(entity =>
        {
            entity.ToTable("SolicitudesEntrantes");
            entity.HasIndex(s => s.PacketId);
            entity.HasIndex(s => s.Estado);
        });

        modelBuilder.Entity<PeerNode>(entity =>
        {
            entity.ToTable("TrustedPeers");
            entity.HasIndex(p => p.NodeId).IsUnique();
        });

        modelBuilder.Entity<SeenPacketEntity>(entity =>
        {
            entity.ToTable("SeenPackets");
            entity.HasIndex(p => p.PacketId).IsUnique();
        });
    }

    /// <summary>
    /// Inicializa el esquema SQLite v2.0 (sin sembrar usuarios por defecto) y asegura las tablas TrustedPeers y SeenPackets.
    /// </summary>
    public static void InitializeDatabase(string? customDatabasePath = null)
    {
        using var db = new AppDbContext(customDatabasePath ?? DatabasePath);
        db.Database.EnsureCreated();

        try
        {
            db.Database.ExecuteSqlRaw("ALTER TABLE Usuarios ADD COLUMN NombreCompleto TEXT NOT NULL DEFAULT '';");
        }
        catch { }

        // Crear tablas nuevas v2.0 si la base de datos ya existía de una versión previa
        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS TrustedPeers (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                NodeId TEXT NOT NULL UNIQUE,
                TeamNumber INTEGER NOT NULL DEFAULT 0,
                IpAddress TEXT NOT NULL DEFAULT '127.0.0.1',
                Port INTEGER NOT NULL DEFAULT 5001,
                HttpsPort INTEGER NULL,
                RoleLabel TEXT NOT NULL DEFAULT '',
                ProtocolType TEXT NOT NULL DEFAULT 'v2.0',
                Source TEXT NOT NULL DEFAULT 'manual',
                Status TEXT NOT NULL DEFAULT 'offline',
                LastLatency TEXT NOT NULL DEFAULT '--',
                CertThumbprint TEXT NOT NULL DEFAULT '',
                PinnedThumbprintSha256 TEXT NOT NULL DEFAULT '',
                CertificatePem TEXT NOT NULL DEFAULT '',
                AlgorithmsJson TEXT NOT NULL DEFAULT '[]',
                IsConfirmed INTEGER NOT NULL DEFAULT 0,
                HasThumbprintMismatch INTEGER NOT NULL DEFAULT 0,
                LastSeenUtc TEXT NOT NULL DEFAULT ''
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS SeenPackets (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                PacketId TEXT NOT NULL UNIQUE,
                SourceNode TEXT NOT NULL DEFAULT '',
                PacketTimestampUtc TEXT NOT NULL DEFAULT '',
                ReceivedAtUtc TEXT NOT NULL DEFAULT ''
            );");

        // Migrar nodo asignado de usuarios existentes al formato EQ01
        if (db.Usuarios.Any())
        {
            bool changed = false;
            foreach (var u in db.Usuarios.ToList())
            {
                if (!NodeRuntimeState.IsValidNodeId(u.NodoAsignado))
                {
                    u.NodoAsignado = NodeRuntimeState.CurrentNodeId;
                    changed = true;
                }
                if (string.IsNullOrWhiteSpace(u.NombreCompleto))
                {
                    u.NombreCompleto = u.NombreUsuario;
                    changed = true;
                }
            }
            if (changed) db.SaveChanges();
        }

        // Cargar nodos persistidos (TOFU) en memoria si estamos en la BD principal
        if (customDatabasePath == null)
        {
            LoadPersistedPeersIntoRuntime(db);
        }
    }

    public static void LoadPersistedPeersIntoRuntime(AppDbContext db)
    {
        var savedPeers = db.TrustedPeers.ToList();
        foreach (var saved in savedPeers)
        {
            var match = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                p.NodeId.Equals(saved.NodeId, StringComparison.OrdinalIgnoreCase));

            if (match != null)
            {
                if (saved.NodeId != NodeRuntimeState.CurrentNodeId)
                {
                    match.IpAddress = saved.IpAddress;
                    match.Port = saved.Port;
                    match.HttpsPort = saved.HttpsPort;
                    match.Source = saved.Source;
                    match.Status = saved.HasThumbprintMismatch ? "blocked" : saved.Status;
                }
                match.PinnedThumbprintSha256 = saved.PinnedThumbprintSha256;
                match.CertThumbprint = saved.CertThumbprint;
                match.CertificatePem = saved.CertificatePem;
                match.IsConfirmed = saved.IsConfirmed;
                match.HasThumbprintMismatch = saved.HasThumbprintMismatch;
                match.LastSeenUtc = saved.LastSeenUtc;
            }
            else
            {
                NodeRuntimeState.NetworkPeers.Add(saved);
            }
        }
    }

    public static void UpsertTrustedPeer(PeerNode peer, string? customDatabasePath = null)
    {
        using var db = new AppDbContext(customDatabasePath ?? DatabasePath);
        var entity = db.TrustedPeers.FirstOrDefault(p => p.NodeId == peer.NodeId);
        if (entity == null)
        {
            db.TrustedPeers.Add(new PeerNode
            {
                NodeId = peer.NodeId,
                TeamNumber = peer.TeamNumber,
                IpAddress = peer.IpAddress,
                Port = peer.Port,
                HttpsPort = peer.HttpsPort,
                RoleLabel = peer.RoleLabel,
                ProtocolType = peer.ProtocolType,
                Source = peer.Source,
                Status = peer.Status,
                LastLatency = peer.LastLatency,
                CertThumbprint = peer.CertThumbprint,
                PinnedThumbprintSha256 = peer.PinnedThumbprintSha256,
                CertificatePem = peer.CertificatePem,
                AlgorithmsJson = peer.AlgorithmsJson,
                IsConfirmed = peer.IsConfirmed,
                HasThumbprintMismatch = peer.HasThumbprintMismatch,
                LastSeenUtc = peer.LastSeenUtc
            });
        }
        else
        {
            entity.TeamNumber = peer.TeamNumber;
            entity.IpAddress = peer.IpAddress;
            entity.Port = peer.Port;
            entity.HttpsPort = peer.HttpsPort;
            entity.RoleLabel = peer.RoleLabel;
            entity.ProtocolType = peer.ProtocolType;
            entity.Source = peer.Source;
            entity.Status = peer.Status;
            entity.LastLatency = peer.LastLatency;
            entity.CertThumbprint = peer.CertThumbprint;
            entity.PinnedThumbprintSha256 = peer.PinnedThumbprintSha256;
            entity.CertificatePem = peer.CertificatePem;
            entity.AlgorithmsJson = peer.AlgorithmsJson;
            entity.IsConfirmed = peer.IsConfirmed;
            entity.HasThumbprintMismatch = peer.HasThumbprintMismatch;
            entity.LastSeenUtc = peer.LastSeenUtc;
        }
        db.SaveChanges();
    }

    public static string ComputeSha256(string input)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}

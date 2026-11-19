using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Models;
using System.Security.Cryptography;
using System.Text;

namespace ModuloCrypto.Core.Data;

public class AppDbContext : DbContext
{
    public static readonly string DatabasePath = Path.Combine(AppContext.BaseDirectory, "ModuloCrypto.db");

    public DbSet<Usuario> Usuarios => Set<Usuario>();
    public DbSet<RegistroCifrado> RegistrosCifrados => Set<RegistroCifrado>();
    public DbSet<SolicitudEntrante> SolicitudesEntrantes => Set<SolicitudEntrante>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite($"Data Source={DatabasePath}");
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
    }

    public static void InitializeDatabase()
    {
        using var db = new AppDbContext();
        db.Database.EnsureCreated();

        if (!db.Usuarios.Any())
        {
            db.Usuarios.AddRange(
                new Usuario
                {
                    NombreUsuario = "admin",
                    PasswordHash = ComputeSha256("admin123"),
                    NodoAsignado = "NODO-04",
                    Rol = "Arquitecto Seguridad",
                    FechaRegistro = DateTime.Now
                },
                new Usuario
                {
                    NombreUsuario = "operador",
                    PasswordHash = ComputeSha256("crypto2026"),
                    NodoAsignado = "NODO-04",
                    Rol = "Operador Tor",
                    FechaRegistro = DateTime.Now
                }
            );
            db.SaveChanges();
        }
    }

    public static string ComputeSha256(string input)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}

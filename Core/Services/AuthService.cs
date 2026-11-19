using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;

namespace ModuloCrypto.Core.Services;

public static class AuthService
{
    public static Usuario? Authenticate(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;

        string normalized = username.Trim();
        string hash = AppDbContext.ComputeSha256(password);

        using var db = new AppDbContext();
        return db.Usuarios.FirstOrDefault(u =>
            u.NombreUsuario.ToLower() == normalized.ToLower() &&
            u.PasswordHash == hash);
    }

    public static (bool Success, string Message, Usuario? User) Register(
        string nombreCompleto,
        string username,
        string password,
        string nodoAsignado = "NODO-01",
        string rol = "Operador Tor")
    {
        if (string.IsNullOrWhiteSpace(nombreCompleto) || nombreCompleto.Trim().Length < 3)
            return (false, "Ingresa tu nombre completo (mínimo 3 caracteres).", null);

        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length < 3)
            return (false, "El nombre de usuario debe tener al menos 3 caracteres.", null);

        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
            return (false, "La contraseña debe tener al menos 4 caracteres.", null);

        string normalizedUser = username.Trim();
        string normalizedName = nombreCompleto.Trim();

        using var db = new AppDbContext();

        if (db.Usuarios.Any(u => u.NombreUsuario.ToLower() == normalizedUser.ToLower()))
            return (false, "Ese nombre de usuario ya está registrado.", null);

        var user = new Usuario
        {
            NombreCompleto = normalizedName,
            NombreUsuario = normalizedUser,
            PasswordHash = AppDbContext.ComputeSha256(password),
            NodoAsignado = string.IsNullOrWhiteSpace(nodoAsignado) ? "NODO-01" : nodoAsignado.Trim().ToUpperInvariant(),
            Rol = string.IsNullOrWhiteSpace(rol) ? "Operador Tor" : rol.Trim(),
            FechaRegistro = DateTime.Now
        };

        db.Usuarios.Add(user);
        db.SaveChanges();

        return (true, "Integrante registrado correctamente.", user);
    }
}

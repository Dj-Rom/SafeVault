namespace SafeVault.Models;

public record LoginRequest(string? Username, string? Password);

public record RegisterRequest(string? Username, string? Email, string? Password);

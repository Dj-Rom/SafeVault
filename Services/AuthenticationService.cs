using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public record JwtSettings(string Key, string Issuer, string Audience);

public enum LoginStatus { Success, InvalidCredentials, LockedOut }

public record LoginResult(LoginStatus Status, string? Token = null);

public record RegisterResult(List<string> Errors, bool Conflict)
{
    public bool Created => Errors.Count == 0 && !Conflict;
}

public class AuthenticationService
{
    // Verified when the user does not exist, so response time does not reveal valid usernames.
    private static readonly string DummyHash = PasswordService.Hash("dummy-password-for-timing-1");

    private readonly UserRepository _users;
    private readonly AuthRepository _attempts;
    private readonly JwtSettings _jwt;

    public AuthenticationService(UserRepository users, AuthRepository attempts, JwtSettings jwt)
    {
        _users = users;
        _attempts = attempts;
        _jwt = jwt;
    }

    public RegisterResult Register(string? username, string? email, string? password)
    {
        var errors = new List<string>();
        if (!InputSanitizer.IsValidUsername(username))
            errors.Add("Username must be 3-30 characters: letters, digits and underscore only.");
        if (!InputSanitizer.IsValidEmail(email))
            errors.Add("Email is not valid.");
        if (!InputSanitizer.IsValidPassword(password))
            errors.Add("Password must be 8-72 characters and contain a letter and a digit.");

        if (errors.Count > 0) return new RegisterResult(errors, false);

        // New users ALWAYS get the User role. The client cannot choose a role.
        var created = _users.CreateUser(new User
        {
            Username = username!,
            Email = email!,
            PasswordHash = PasswordService.Hash(password!),
            Role = Roles.User
        });

        return new RegisterResult(new List<string>(), !created);
    }

    public LoginResult Login(string? username, string? password)
    {
        if (!InputSanitizer.IsValidUsername(username)
            || string.IsNullOrEmpty(password) || password.Length > 72)
        {
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        if (_attempts.IsLockedOut(username!))
            return new LoginResult(LoginStatus.LockedOut);

        var user = _users.GetByUsername(username!);
        var passwordOk = PasswordService.Verify(password, user?.PasswordHash ?? DummyHash);

        if (user is null || !passwordOk)
        {
            _attempts.RecordFailure(username!);
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        _attempts.Reset(username!);
        return new LoginResult(LoginStatus.Success, CreateToken(user));
    }

    private string CreateToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
        var token = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

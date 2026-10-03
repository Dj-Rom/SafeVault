using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests;

public class AuthenticationTests : IDisposable
{
    private const string Password = "Str0ngPassw0rd";

    private readonly TestDb _db = new();
    private readonly UserRepository _users;
    private readonly AuthenticationService _auth;

    public AuthenticationTests()
    {
        _users = new UserRepository(_db.ConnectionString);
        var attempts = new AuthRepository(_db.ConnectionString);
        var jwt = new JwtSettings("unit-test-signing-key-with-more-than-32-bytes", "SafeVault", "SafeVaultUsers");
        _auth = new AuthenticationService(_users, attempts, jwt);
    }

    public void Dispose() => _db.Dispose();

    private void RegisterAlice()
    {
        var result = _auth.Register("alice", "alice@example.com", Password);
        Assert.True(result.Created);
    }

    [Fact]
    public void Valid_registration_succeeds()
    {
        var result = _auth.Register("alice", "alice@example.com", Password);

        Assert.True(result.Created);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Registration_rejects_bad_input()
    {
        var result = _auth.Register("bad name'--", "not-an-email", "short");

        Assert.False(result.Created);
        Assert.Equal(3, result.Errors.Count);
    }

    [Fact]
    public void Duplicate_registration_is_a_conflict()
    {
        RegisterAlice();

        var result = _auth.Register("alice", "other@example.com", Password);

        Assert.True(result.Conflict);
    }

    [Fact]
    public void New_users_always_get_the_User_role()
    {
        RegisterAlice();

        Assert.Equal(Roles.User, _users.GetByUsername("alice")!.Role);
    }

    [Fact]
    public void Password_is_stored_as_a_bcrypt_hash()
    {
        RegisterAlice();

        var stored = _users.GetByUsername("alice")!.PasswordHash;

        Assert.NotEqual(Password, stored);
        Assert.StartsWith("$2", stored);
    }

    [Fact]
    public void Valid_login_returns_a_token()
    {
        RegisterAlice();

        var result = _auth.Login("alice", Password);

        Assert.Equal(LoginStatus.Success, result.Status);
        Assert.False(string.IsNullOrWhiteSpace(result.Token));
    }

    [Fact]
    public void Wrong_password_is_rejected()
    {
        RegisterAlice();

        Assert.Equal(LoginStatus.InvalidCredentials, _auth.Login("alice", "Wr0ngPassword").Status);
    }

    [Fact]
    public void Unknown_user_is_rejected() =>
        Assert.Equal(LoginStatus.InvalidCredentials, _auth.Login("nobody", Password).Status);

    [Theory]
    [InlineData("alice' OR '1'='1", "' OR '1'='1")]
    [InlineData("' OR 1=1 --", "x")]
    [InlineData("", "")]
    [InlineData(null, null)]
    public void Login_injection_and_empty_input_is_rejected(string? username, string? password)
    {
        RegisterAlice();

        Assert.Equal(LoginStatus.InvalidCredentials, _auth.Login(username, password).Status);
    }

    [Fact]
    public void Account_is_locked_after_too_many_failed_attempts()
    {
        RegisterAlice();

        for (var i = 0; i < AuthRepository.MaxFailedAttempts; i++)
            Assert.Equal(LoginStatus.InvalidCredentials, _auth.Login("alice", "Wr0ngPassword").Status);

        // Even the correct password is refused while the account is locked.
        Assert.Equal(LoginStatus.LockedOut, _auth.Login("alice", Password).Status);
    }

    [Fact]
    public void Successful_login_resets_failed_attempts()
    {
        RegisterAlice();

        for (var i = 0; i < AuthRepository.MaxFailedAttempts - 1; i++)
            _auth.Login("alice", "Wr0ngPassword");

        Assert.Equal(LoginStatus.Success, _auth.Login("alice", Password).Status);
        Assert.Equal(LoginStatus.InvalidCredentials, _auth.Login("alice", "Wr0ngPassword").Status);
    }

    [Fact]
    public void Password_service_verifies_correctly()
    {
        var hash = PasswordService.Hash(Password);

        Assert.True(PasswordService.Verify(Password, hash));
        Assert.False(PasswordService.Verify("Wr0ngPassword", hash));
        Assert.False(PasswordService.Verify(Password, "garbage"));
        Assert.NotEqual(PasswordService.Hash(Password), PasswordService.Hash(Password)); // random salt
    }
}

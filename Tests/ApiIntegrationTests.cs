using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SafeVault.Tests;

/// <summary>Starts the real app with a temporary database for the test run.</summary>
public class SafeVaultFactory : WebApplicationFactory<Program>
{
    public const string AdminPassword = "Adm1n!TestPassw0rd";
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"safevault-it-{Guid.NewGuid():N}.db");

    public SafeVaultFactory()
    {
        // Environment variables are read when the host starts (after this constructor).
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", $"Data Source={_dbPath};Pooling=False");
        Environment.SetEnvironmentVariable("Seed__AdminPassword", AdminPassword);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { File.Delete(_dbPath); } catch (IOException) { /* ignore */ }
    }
}

public class ApiIntegrationTests : IClassFixture<SafeVaultFactory>
{
    private record LoginResponse(string Token);
    private record ProfileResponse(string Username, string Role);

    private readonly SafeVaultFactory _factory;

    public ApiIntegrationTests(SafeVaultFactory factory) => _factory = factory;

    private static string NewUsername() => "user_" + Guid.NewGuid().ToString("N")[..8];

    private async Task<(string Username, string Password)> RegisterUserAsync()
    {
        var username = NewUsername();
        const string password = "Str0ngPassw0rd";
        var response = await _factory.CreateClient().PostAsJsonAsync("/register",
            new { username, email = $"{username}@example.com", password });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (username, password);
    }

    private async Task<string> LoginAsync(string username, string password)
    {
        var response = await _factory.CreateClient().PostAsJsonAsync("/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
        return body!.Token;
    }

    private HttpClient ClientWithToken(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    // ---------- Input validation ----------

    [Theory]
    [InlineData("admin'--")]
    [InlineData("alice' OR '1'='1")]
    [InlineData("<script>alert(1)</script>")]
    public async Task Register_rejects_malicious_username(string username)
    {
        var response = await _factory.CreateClient().PostAsJsonAsync("/register",
            new { username, email = "x@example.com", password = "Str0ngPassw0rd" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_rejects_malicious_email()
    {
        var response = await _factory.CreateClient().PostAsJsonAsync("/register",
            new { username = NewUsername(), email = "<script>alert(1)</script>@example.com", password = "Str0ngPassw0rd" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---------- Authentication ----------

    [Fact]
    public async Task Login_with_correct_password_returns_token()
    {
        var (username, password) = await RegisterUserAsync();

        var token = await LoginAsync(username, password);

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task Login_with_wrong_password_returns_401()
    {
        var (username, _) = await RegisterUserAsync();

        var response = await _factory.CreateClient().PostAsJsonAsync("/login",
            new { username, password = "Wr0ngPassword" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_sql_injection_attempt_returns_401()
    {
        var response = await _factory.CreateClient().PostAsJsonAsync("/login",
            new { username = "admin' OR '1'='1", password = "' OR '1'='1" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Profile_requires_a_token()
    {
        var response = await _factory.CreateClient().GetAsync("/profile");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Profile_returns_user_with_User_role()
    {
        var (username, password) = await RegisterUserAsync();
        var token = await LoginAsync(username, password);

        var response = await ClientWithToken(token).GetAsync("/profile");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var profile = await response.Content.ReadFromJsonAsync<ProfileResponse>();
        Assert.Equal(username, profile!.Username);
        Assert.Equal("User", profile.Role);
    }

    [Fact]
    public async Task Tampered_token_is_rejected()
    {
        var (username, password) = await RegisterUserAsync();
        var token = await LoginAsync(username, password);
        var parts = token.Split('.');
        var tampered = $"{parts[0]}.{parts[1]}.{new string('A', parts[2].Length)}";

        var response = await ClientWithToken(tampered).GetAsync("/profile");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---------- Authorization (RBAC) ----------

    [Fact]
    public async Task Admin_page_without_token_returns_401()
    {
        var response = await _factory.CreateClient().GetAsync("/admin/dashboard");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Admin_page_with_normal_user_returns_403()
    {
        var (username, password) = await RegisterUserAsync();
        var token = await LoginAsync(username, password);

        var response = await ClientWithToken(token).GetAsync("/admin/dashboard");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task User_area_is_open_for_normal_users()
    {
        var (username, password) = await RegisterUserAsync();
        var token = await LoginAsync(username, password);

        var response = await ClientWithToken(token).GetAsync("/user/area");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task User_cannot_make_themselves_admin_during_registration()
    {
        var username = NewUsername();
        var register = await _factory.CreateClient().PostAsJsonAsync("/register",
            new { username, email = $"{username}@example.com", password = "Str0ngPassw0rd", role = "Admin" });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var token = await LoginAsync(username, "Str0ngPassw0rd");
        var response = await ClientWithToken(token).GetAsync("/admin/dashboard");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Admin_page_with_admin_token_returns_200()
    {
        var token = await LoginAsync("admin", SafeVaultFactory.AdminPassword);

        var response = await ClientWithToken(token).GetAsync("/admin/dashboard");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---------- XSS and SQL injection on the admin search ----------

    [Fact]
    public async Task Admin_search_encodes_script_tags_in_output()
    {
        var token = await LoginAsync("admin", SafeVaultFactory.AdminPassword);
        const string payload = "<script>alert(1)</script>";

        var response = await ClientWithToken(token)
            .GetAsync("/admin/dashboard?search=" + Uri.EscapeDataString(payload));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain(payload, html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
    }

    [Fact]
    public async Task Admin_search_sql_injection_does_not_list_users()
    {
        var token = await LoginAsync("admin", SafeVaultFactory.AdminPassword);

        var response = await ClientWithToken(token)
            .GetAsync("/admin/dashboard?search=" + Uri.EscapeDataString("' OR '1'='1"));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("admin@safevault.local", html);
    }

    [Fact]
    public async Task Responses_have_security_headers()
    {
        var response = await _factory.CreateClient().GetAsync("/profile");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }
}

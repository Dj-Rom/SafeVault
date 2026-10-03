using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default") ?? "Data Source=safevault.db";
var jwt = new JwtSettings(
    builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured."),
    builder.Configuration["Jwt:Issuer"] ?? "SafeVault",
    builder.Configuration["Jwt:Audience"] ?? "SafeVaultUsers");

if (Encoding.UTF8.GetByteCount(jwt.Key) < 32)
    throw new InvalidOperationException("Jwt:Key must be at least 32 bytes.");

builder.Services.AddSingleton(new UserRepository(connectionString));
builder.Services.AddSingleton(new AuthRepository(connectionString));
builder.Services.AddSingleton(jwt);
builder.Services.AddSingleton<AuthenticationService>();
builder.Services.AddSingleton<AuthorizationService>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(Roles.Admin));
});

var app = builder.Build();

// Optional: create the first admin from configuration (Seed:AdminPassword).
var seedPassword = app.Configuration["Seed:AdminPassword"];
if (!string.IsNullOrEmpty(seedPassword))
{
    var seedUsers = app.Services.GetRequiredService<UserRepository>();
    if (seedUsers.GetByUsername("admin") is null)
    {
        seedUsers.CreateUser(new User
        {
            Username = "admin",
            Email = "admin@safevault.local",
            PasswordHash = PasswordService.Hash(seedPassword),
            Role = Roles.Admin
        });
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

// ---------- Public endpoints ----------

app.MapPost("/register", (RegisterRequest req, AuthenticationService auth) =>
{
    var result = auth.Register(req.Username, req.Email, req.Password);

    if (result.Errors.Count > 0)
    {
        if (InputSanitizer.ContainsSuspiciousPattern(req.Username) || InputSanitizer.ContainsSuspiciousPattern(req.Email))
            app.Logger.LogWarning("Suspicious input rejected on /register");
        return Results.BadRequest(new { errors = result.Errors });
    }

    if (result.Conflict)
        return Results.Json(new { error = "Username or email is already in use." },
            statusCode: StatusCodes.Status409Conflict);

    return Results.Json(new { message = "User registered." }, statusCode: StatusCodes.Status201Created);
});

app.MapPost("/login", (LoginRequest req, AuthenticationService auth) =>
{
    var result = auth.Login(req.Username, req.Password);

    return result.Status switch
    {
        LoginStatus.Success => Results.Ok(new { token = result.Token }),
        LoginStatus.LockedOut => Results.Json(new { error = "Too many failed attempts. Try again later." },
            statusCode: StatusCodes.Status429TooManyRequests),
        _ => Results.Json(new { error = "Invalid username or password." },
            statusCode: StatusCodes.Status401Unauthorized)
    };
});

// ---------- Authenticated endpoints ----------

app.MapGet("/profile", (ClaimsPrincipal principal) =>
        Results.Ok(new
        {
            username = principal.Identity?.Name,
            role = principal.FindFirst(ClaimTypes.Role)?.Value
        }))
    .RequireAuthorization();

app.MapGet("/user/area", (ClaimsPrincipal principal, UserRepository users, AuthorizationService authz) =>
    {
        var current = users.GetByUsername(principal.Identity?.Name ?? string.Empty);
        return authz.CanAccessUserArea(current)
            ? Results.Ok(new { message = "Welcome to the user area." })
            : Results.StatusCode(StatusCodes.Status403Forbidden);
    })
    .RequireAuthorization();

// ---------- Admin only (RBAC) ----------

app.MapGet("/admin/dashboard", (ClaimsPrincipal principal, string? search,
        UserRepository users, AuthorizationService authz) =>
    {
        // Second check: the role is read from the database, not only from the token.
        var current = users.GetByUsername(principal.Identity?.Name ?? string.Empty);
        if (!authz.CanAccessAdminDashboard(current))
            return Results.StatusCode(StatusCodes.Status403Forbidden);

        search ??= string.Empty;
        if (search.Length > 50)
            return Results.BadRequest(new { error = "Search text is too long." });

        var found = users.SearchUsers(search); // parameterized query

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>SafeVault Admin</title></head><body>");
        html.Append("<h1>Users</h1>");
        // Every user-controlled value is sanitized (HTML-encoded) before output.
        html.Append("<p>Results for: ").Append(InputSanitizer.Sanitize(search)).Append("</p>");
        html.Append("<table><tr><th>Username</th><th>Email</th><th>Role</th></tr>");
        foreach (var u in found)
        {
            html.Append("<tr><td>").Append(InputSanitizer.Sanitize(u.Username)).Append("</td><td>")
                .Append(InputSanitizer.Sanitize(u.Email)).Append("</td><td>")
                .Append(InputSanitizer.Sanitize(u.Role)).Append("</td></tr>");
        }
        html.Append("</table></body></html>");

        return Results.Content(html.ToString(), "text/html; charset=utf-8");
    })
    .RequireAuthorization("AdminOnly");

app.Run();

// Needed so the test project can start the app with WebApplicationFactory<Program>.
public partial class Program { }

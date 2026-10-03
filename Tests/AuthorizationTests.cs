using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests;

public class AuthorizationTests
{
    private readonly AuthorizationService _authz = new();

    private static User Admin() => new() { Username = "admin", Role = Roles.Admin };
    private static User Normal() => new() { Username = "alice", Role = Roles.User };

    [Fact]
    public void Admin_can_access_admin_dashboard() =>
        Assert.True(_authz.CanAccessAdminDashboard(Admin()));

    [Fact]
    public void Normal_user_cannot_access_admin_dashboard() =>
        Assert.False(_authz.CanAccessAdminDashboard(Normal()));

    [Fact]
    public void Normal_user_can_access_user_area() =>
        Assert.True(_authz.CanAccessUserArea(Normal()));

    [Fact]
    public void Admin_can_access_user_area() =>
        Assert.True(_authz.CanAccessUserArea(Admin()));

    [Fact]
    public void Missing_user_has_no_access()
    {
        Assert.False(_authz.CanAccessAdminDashboard(null));
        Assert.False(_authz.CanAccessUserArea(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("admin")]        // wrong case must not match
    [InlineData("Superuser")]
    public void Unknown_or_wrongly_cased_roles_have_no_access(string role)
    {
        var user = new User { Username = "x", Role = role };

        Assert.False(_authz.CanAccessAdminDashboard(user));
        Assert.False(_authz.CanAccessUserArea(user));
    }

    [Fact]
    public void Role_check_works()
    {
        Assert.True(_authz.IsInRole(Admin(), Roles.Admin));
        Assert.False(_authz.IsInRole(Normal(), Roles.Admin));
    }
}

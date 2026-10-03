using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>Role-based access control (RBAC) rules in one place.</summary>
public class AuthorizationService
{
    public bool IsInRole(User? user, string role) =>
        user is not null && string.Equals(user.Role, role, StringComparison.Ordinal);

    public bool CanAccessAdminDashboard(User? user) => IsInRole(user, Roles.Admin);

    public bool CanAccessUserArea(User? user) =>
        IsInRole(user, Roles.User) || IsInRole(user, Roles.Admin);
}

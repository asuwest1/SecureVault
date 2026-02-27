using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;

namespace SecureVault.Api.Filters;

/// <summary>
/// Authorization filter that verifies the caller has the required permission on a secret.
/// Returns 404 (not 403) for inaccessible secrets — prevents existence disclosure.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class RequireSecretPermissionAttribute : Attribute, IAsyncAuthorizationFilter
{
    private readonly SecretPermission _required;

    public RequireSecretPermissionAttribute(SecretPermission required)
    {
        _required = required;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        if (!context.HttpContext.User.Identity?.IsAuthenticated ?? true)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var user = context.HttpContext.User;
        var userId = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var isSuperAdmin = bool.Parse(user.FindFirstValue("is_super_admin") ?? "false");
        var roleIds = user.FindAll("role_ids").Select(c => Guid.Parse(c.Value)).ToList();

        // Extract secret ID from route — controller action must have {id} parameter
        if (!context.RouteData.Values.TryGetValue("id", out var idValue) ||
            !Guid.TryParse(idValue?.ToString(), out var secretId))
        {
            context.Result = new NotFoundResult();
            return;
        }

        var permissionService = context.HttpContext.RequestServices.GetRequiredService<IPermissionService>();
        var permission = await permissionService.GetSecretPermissionAsync(
            userId, roleIds, isSuperAdmin, secretId);

        // Return 404 for no permission — prevents information disclosure about secret existence
        if (permission == null || !permission.Value.HasFlag(_required))
        {
            context.Result = new NotFoundResult();
        }
    }
}

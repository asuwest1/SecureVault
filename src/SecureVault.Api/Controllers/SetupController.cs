using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureVault.Api.Services;

namespace SecureVault.Api.Controllers;

/// <summary>
/// First-run setup endpoints. Disabled (410 Gone) once initialization is complete.
/// </summary>
[ApiController]
[Route("api/v1/setup")]
[AllowAnonymous]
public class SetupController : ControllerBase
{
    private readonly FirstRunService _firstRun;

    public SetupController(FirstRunService firstRun)
    {
        _firstRun = firstRun;
    }

    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct)
    {
        var initialized = await _firstRun.IsInitializedAsync(ct);
        return Ok(new { initialized });
    }

    [HttpPost("initialize")]
    public async Task<IActionResult> Initialize(
        [FromBody] InitializeRequest request, CancellationToken ct)
    {
        if (await _firstRun.IsInitializedAsync(ct))
            return StatusCode(410, new { error = "System already initialized." });

        try
        {
            await _firstRun.InitializeAsync(
                request.AdminUsername, request.AdminEmail, request.AdminPassword, ct);

            return Ok(new { message = "System initialized successfully." });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}

public record InitializeRequest(
    string AdminUsername,
    string AdminEmail,
    string AdminPassword
);

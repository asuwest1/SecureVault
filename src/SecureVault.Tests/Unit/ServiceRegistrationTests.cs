using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureVault.Infrastructure.Data;
using Xunit;

namespace SecureVault.Tests.Unit;

public class ServiceRegistrationTests
{
    [Fact]
    public void ProductionRegistrations_ResolveFactoryFromRootAndContextFromScope()
    {
        using var app = new WebApplicationFactory<Program>();
        // Keep the real Program registrations; do not replace database services.
        var factory = app.Services.GetRequiredService<IDbContextFactory<AppDbContext>>();
        using var context = factory.CreateDbContext();
        using var scope = app.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Should().NotBeSameAs(context);
    }
}

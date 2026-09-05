using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SecureVault.Infrastructure.Data.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20260905000000_SecurityState")]
public class SecurityState : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("ALTER TABLE users ADD security_version uniqueidentifier NOT NULL DEFAULT NEWID();");
        migrationBuilder.Sql("CREATE TABLE system_state (id int NOT NULL PRIMARY KEY CHECK (id = 1), is_initialized bit NOT NULL);");
        // Never reopen an existing vault, even if its administrator was previously demoted.
        migrationBuilder.Sql("INSERT INTO system_state VALUES (1, CASE WHEN EXISTS (SELECT 1 FROM users) OR EXISTS (SELECT 1 FROM folders) THEN 1 ELSE 0 END);");
        migrationBuilder.Sql("ALTER TABLE refresh_tokens ADD security_version uniqueidentifier NOT NULL DEFAULT NEWID();");
        migrationBuilder.Sql("UPDATE refresh_tokens SET is_revoked = 1;");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn("security_version", "refresh_tokens");
        migrationBuilder.DropTable("system_state");
        migrationBuilder.DropColumn("security_version", "users");
    }
}

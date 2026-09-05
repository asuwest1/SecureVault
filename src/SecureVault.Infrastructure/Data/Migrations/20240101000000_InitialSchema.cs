using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureVault.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    [Microsoft.EntityFrameworkCore.Infrastructure.DbContext(typeof(AppDbContext))]
    [Migration("20240101000000_InitialSchema")]
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    action = table.Column<int>(type: "int", nullable: false),
                    actor_user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    actor_username = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    target_type = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    target_id = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ip_address = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    detail = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    event_time = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    description = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    username = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    email = table.Column<string>(type: "nvarchar(254)", maxLength: 254, nullable: false),
                    password_hash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    is_active = table.Column<bool>(type: "bit", nullable: false, defaultValue: true),
                    is_super_admin = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    is_ldap_user = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    failed_attempts = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    mfa_enabled = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    mfa_secret_enc = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    updated_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "folders",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    parent_folder_id = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    depth = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    updated_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_folders", x => x.id);
                    // SQL Server does not allow ON DELETE CASCADE on self-referencing FKs.
                    // Use NO ACTION; folder deletion cascade is enforced in application code.
                    table.ForeignKey(
                        name: "FK_folders_folders_parent_folder_id",
                        column: x => x.parent_folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.NoAction);
                });

            migrationBuilder.CreateTable(
                name: "api_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    token_hash = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    last_used_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    is_revoked = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_api_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_api_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    token_hash = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    is_revoked = table.Column<bool>(type: "bit", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_refresh_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_roles",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    role_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    assigned_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_roles", x => new { x.user_id, x.role_id });
                    table.ForeignKey(
                        name: "FK_user_roles_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_user_roles_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "folder_acl",
                columns: table => new
                {
                    folder_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    role_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    permissions = table.Column<int>(type: "int", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_folder_acl", x => new { x.folder_id, x.role_id });
                    table.ForeignKey(
                        name: "FK_folder_acl_folders_folder_id",
                        column: x => x.folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    // SQL Server: multiple cascade paths not allowed; use NO ACTION on roles.
                    table.ForeignKey(
                        name: "FK_folder_acl_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.NoAction);
                });

            migrationBuilder.CreateTable(
                name: "secrets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    username = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    url = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    notes = table.Column<string>(type: "nvarchar(4096)", maxLength: 4096, nullable: true),
                    type = table.Column<int>(type: "int", nullable: false),
                    tags = table.Column<string>(type: "nvarchar(2048)", nullable: false, defaultValue: ""),
                    value_enc = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    dek_enc = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    nonce = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    folder_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    updated_by_user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    updated_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()"),
                    deleted_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    purge_after = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secrets", x => x.id);
                    table.ForeignKey(
                        name: "FK_secrets_folders_folder_id",
                        column: x => x.folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_secrets_users_created_by_user_id",
                        column: x => x.created_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "secret_acl",
                columns: table => new
                {
                    secret_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    role_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    permissions = table.Column<int>(type: "int", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secret_acl", x => new { x.secret_id, x.role_id });
                    table.ForeignKey(
                        name: "FK_secret_acl_secrets_secret_id",
                        column: x => x.secret_id,
                        principalTable: "secrets",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_secret_acl_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.NoAction);
                });

            migrationBuilder.CreateTable(
                name: "secret_versions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    secret_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    version_number = table.Column<int>(type: "int", nullable: false),
                    notes = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    value_enc = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    dek_enc = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    nonce = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSUTCDATETIME()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secret_versions", x => x.id);
                    table.ForeignKey(
                        name: "FK_secret_versions_secrets_secret_id",
                        column: x => x.secret_id,
                        principalTable: "secrets",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Indexes
            migrationBuilder.CreateIndex(name: "IX_audit_log_action", table: "audit_log", column: "action");
            migrationBuilder.CreateIndex(name: "IX_audit_log_actor_user_id", table: "audit_log", column: "actor_user_id");
            migrationBuilder.CreateIndex(name: "IX_audit_log_event_time", table: "audit_log", column: "event_time");
            migrationBuilder.CreateIndex(name: "IX_api_tokens_token_hash", table: "api_tokens", column: "token_hash", unique: true);
            migrationBuilder.CreateIndex(name: "IX_api_tokens_user_id", table: "api_tokens", column: "user_id");
            migrationBuilder.CreateIndex(name: "IX_folders_parent_folder_id", table: "folders", column: "parent_folder_id");
            migrationBuilder.CreateIndex(name: "IX_folder_acl_role_id", table: "folder_acl", column: "role_id");
            migrationBuilder.CreateIndex(name: "IX_refresh_tokens_token_hash", table: "refresh_tokens", column: "token_hash", unique: true);
            migrationBuilder.CreateIndex(name: "IX_refresh_tokens_user_id_is_revoked", table: "refresh_tokens", columns: ["user_id", "is_revoked"]);
            migrationBuilder.CreateIndex(name: "IX_roles_name", table: "roles", column: "name", unique: true);
            migrationBuilder.CreateIndex(name: "IX_secret_acl_role_id", table: "secret_acl", column: "role_id");
            migrationBuilder.CreateIndex(name: "IX_secrets_deleted_at", table: "secrets", column: "deleted_at");
            migrationBuilder.CreateIndex(name: "IX_secrets_folder_id", table: "secrets", column: "folder_id");
            migrationBuilder.CreateIndex(name: "IX_secrets_type", table: "secrets", column: "type");
            migrationBuilder.CreateIndex(name: "IX_secret_versions_secret_id_version_number", table: "secret_versions", columns: ["secret_id", "version_number"], unique: true);
            migrationBuilder.CreateIndex(name: "IX_user_roles_role_id", table: "user_roles", column: "role_id");
            migrationBuilder.CreateIndex(name: "IX_users_email", table: "users", column: "email", unique: true);
            migrationBuilder.CreateIndex(name: "IX_users_username", table: "users", column: "username", unique: true);

            // Append-only audit log: block UPDATE/DELETE via INSTEAD OF triggers.
            // Replaces the historical PostgreSQL REVOKE UPDATE,DELETE pattern.
            migrationBuilder.Sql(@"
                CREATE TRIGGER trg_audit_log_no_update ON audit_log
                INSTEAD OF UPDATE AS
                BEGIN
                    RAISERROR('audit_log is append-only; UPDATE is not permitted.', 16, 1);
                    ROLLBACK TRANSACTION;
                END;
            ");

            migrationBuilder.Sql(@"
                CREATE TRIGGER trg_audit_log_no_delete ON audit_log
                INSTEAD OF DELETE AS
                BEGIN
                    -- Allow DELETE only when the executing principal is a member of db_owner,
                    -- so the scheduled retention job (run as db_owner) can purge old rows.
                    IF IS_MEMBER('db_owner') = 1
                    BEGIN
                        DELETE FROM audit_log
                        WHERE id IN (SELECT id FROM deleted);
                    END
                    ELSE
                    BEGIN
                        RAISERROR('audit_log is append-only; DELETE is restricted to db_owner.', 16, 1);
                        ROLLBACK TRANSACTION;
                    END
                END;
            ");

            // Full-text search: SQL Server's full-text catalog is optional and not always
            // available (LocalDB / Express edition without full-text installed). The application
            // falls back to LIKE-based search on name/username/notes; see SecretsController.
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS trg_audit_log_no_update;");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS trg_audit_log_no_delete;");

            migrationBuilder.DropTable(name: "audit_log");
            migrationBuilder.DropTable(name: "secret_acl");
            migrationBuilder.DropTable(name: "secret_versions");
            migrationBuilder.DropTable(name: "folder_acl");
            migrationBuilder.DropTable(name: "api_tokens");
            migrationBuilder.DropTable(name: "refresh_tokens");
            migrationBuilder.DropTable(name: "user_roles");
            migrationBuilder.DropTable(name: "secrets");
            migrationBuilder.DropTable(name: "folders");
            migrationBuilder.DropTable(name: "roles");
            migrationBuilder.DropTable(name: "users");
        }
    }
}

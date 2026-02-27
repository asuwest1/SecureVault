using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SecureVault.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
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
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    action = table.Column<int>(type: "integer", nullable: false),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    actor_username = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    target_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    target_id = table.Column<Guid>(type: "uuid", nullable: true),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    detail = table.Column<string>(type: "jsonb", nullable: true),
                    event_time = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    username = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    email = table.Column<string>(type: "character varying(254)", maxLength: 254, nullable: false),
                    password_hash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    is_super_admin = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    is_ldap_user = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    mfa_enabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    mfa_secret_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "folders",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    parent_folder_id = table.Column<Guid>(type: "uuid", nullable: true),
                    depth = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_folders", x => x.id);
                    table.ForeignKey(
                        name: "FK_folders_folders_parent_folder_id",
                        column: x => x.parent_folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    token_hash = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    is_revoked = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
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
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    is_revoked = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
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
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role_id = table.Column<Guid>(type: "uuid", nullable: false),
                    assigned_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
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
                    folder_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role_id = table.Column<Guid>(type: "uuid", nullable: false),
                    permissions = table.Column<int>(type: "integer", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
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
                    table.ForeignKey(
                        name: "FK_folder_acl_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "secrets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    username = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    url = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    notes = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: true),
                    type = table.Column<int>(type: "integer", nullable: false),
                    tags = table.Column<string[]>(type: "varchar(64)[]", nullable: false),
                    value_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    dek_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    nonce = table.Column<byte[]>(type: "bytea", nullable: false),
                    folder_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    updated_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    purge_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
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
                    secret_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role_id = table.Column<Guid>(type: "uuid", nullable: false),
                    permissions = table.Column<int>(type: "integer", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
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
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "secret_versions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    secret_id = table.Column<Guid>(type: "uuid", nullable: false),
                    version_number = table.Column<int>(type: "integer", nullable: false),
                    notes = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    value_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    dek_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    nonce = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
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

            // Full-text search vector on secrets (name + username + notes + tags)
            migrationBuilder.Sql(@"
                ALTER TABLE secrets
                ADD COLUMN search_vector tsvector
                GENERATED ALWAYS AS (
                    to_tsvector('english',
                        coalesce(name, '') || ' ' ||
                        coalesce(username, '') || ' ' ||
                        coalesce(notes, '') || ' ' ||
                        coalesce(array_to_string(tags, ' '), '')
                    )
                ) STORED;
            ");

            migrationBuilder.Sql("CREATE INDEX IX_secrets_search_vector ON secrets USING GIN (search_vector);");

            // GIN index on tags array
            migrationBuilder.Sql("CREATE INDEX IX_secrets_tags ON secrets USING GIN (tags);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
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

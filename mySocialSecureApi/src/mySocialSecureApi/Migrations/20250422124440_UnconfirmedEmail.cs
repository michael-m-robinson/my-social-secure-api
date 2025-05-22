using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace My_Social_Secure_Api.Migrations
{
    /// <inheritdoc />
    public partial class UnconfirmedEmail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UnconfirmedEmail",
                table: "LoginHistories",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UnconfirmedEmail",
                table: "LoginAlerts",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UnconfirmedEmail",
                table: "DeviceRecognitions",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UnconfirmedEmail",
                table: "LoginHistories");

            migrationBuilder.DropColumn(
                name: "UnconfirmedEmail",
                table: "LoginAlerts");

            migrationBuilder.DropColumn(
                name: "UnconfirmedEmail",
                table: "DeviceRecognitions");
        }
    }
}

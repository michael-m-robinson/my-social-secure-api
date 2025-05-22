using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace My_Social_Secure_Api.Migrations
{
    /// <inheritdoc />
    public partial class identityandregistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SocialSecurityBenefitType",
                table: "Calculations");

            migrationBuilder.RenameColumn(
                name: "SocialSecurityBenefitType",
                table: "AspNetUsers",
                newName: "City");

            migrationBuilder.AddColumn<string>(
                name: "State",
                table: "AspNetUsers",
                type: "character varying(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "State",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "City",
                table: "AspNetUsers",
                newName: "SocialSecurityBenefitType");

            migrationBuilder.AddColumn<string>(
                name: "SocialSecurityBenefitType",
                table: "Calculations",
                type: "text",
                nullable: false,
                defaultValue: "");
        }
    }
}

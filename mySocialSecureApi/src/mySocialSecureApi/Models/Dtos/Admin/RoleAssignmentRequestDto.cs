namespace My_Social_Secure_Api.Models.Dtos.Admin;

public class RoleAssignmentRequestDto
{
    public string UserId { get; set; } = string.Empty;
    public string RoleName { get; set; } = string.Empty;
}
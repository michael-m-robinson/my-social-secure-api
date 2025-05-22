namespace My_Social_Secure_Api.Models.Dtos.Auth;

public class LogoutRequestDto
{
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
}
namespace My_Social_Secure_Api.Models.Account;

public class PasswordChangeRequest
{
    public string Scheme { get; set; } = "https";
    public HostString Host { get; set; } = new("example.com");
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
}
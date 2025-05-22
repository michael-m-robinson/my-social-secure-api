namespace My_Social_Secure_Api.Models.Auth;

public class EmailConfirmationRequest
{
    public string Scheme { get; init; } = string.Empty;
    public HostString Host { get; init; } = new HostString("example.com");
    public string UserId { get; init; } = string.Empty;
    public string Token { get; init; } = string.Empty;
}
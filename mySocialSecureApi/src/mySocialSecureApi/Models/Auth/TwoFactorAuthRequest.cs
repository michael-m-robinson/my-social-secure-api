namespace My_Social_Secure_Api.Models.Auth;

public class TwoFactorAuthRequest
{
    public required string Scheme { get; init; } = "https";
    public required HostString Host { get; init; } = new("example.com");
    public required string UserName { get; init; } = string.Empty;
    public required string Code { get; init; } = string.Empty;
    public required bool RememberMe { get; init; }
}
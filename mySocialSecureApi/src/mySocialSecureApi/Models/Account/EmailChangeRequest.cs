namespace My_Social_Secure_Api.Models.Account;

public class EmailChangeRequest
{
    public string UserId { get; init; } = string.Empty;
    public string NewEmail { get; init; } = string.Empty;
    public string Scheme { get; init; } = string.Empty;
    public HostString Host { get; init; }
    public string Token { get; init; } = string.Empty;
}
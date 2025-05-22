using System.Text.Json.Serialization;

namespace My_Social_Secure_Api.Models.Dtos.Security;

public class VerifyTwoFactorDto
{
    public string Code { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public bool RememberMe { get; set; }
    [JsonIgnore]
    public HostString Host { get; set; } = new HostString("example.com");
    [JsonIgnore]
    public string Scheme { get; set; } = "https";
}
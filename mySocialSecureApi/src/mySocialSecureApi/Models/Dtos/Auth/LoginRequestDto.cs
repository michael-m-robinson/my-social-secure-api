using System.Text.Json.Serialization;

namespace My_Social_Secure_Api.Models.Dtos.Auth;

public class LoginRequestDto
{
    public required string UserName { get; init; }
    public required string Password { get; init; }
    [JsonIgnore]
    public HostString Host { get; set; } = new HostString("example.com");
    [JsonIgnore]
    public string Scheme { get; set; } = "https";
    public bool RememberMe { get; set; }
}
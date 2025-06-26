namespace My_Social_Secure_Api.Models.Auth;

public class JwtSettings
{
    public string Secret { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public double ExpireMinutes { get; set; } = 15;
    public double TwoFactorExpireMinutes { get; set; } = 5;
    public double AccessExpireMinutes { get; set; } = 15;
}
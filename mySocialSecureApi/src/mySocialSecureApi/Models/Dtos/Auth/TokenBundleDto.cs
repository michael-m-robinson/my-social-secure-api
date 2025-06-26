using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Auth;

public class TokenBundleDto: BaseOperationDto
{
    public string AccessToken { get; set; } = null!;
    public DateTime AccessTokenExpiresUtc { get; set; }

    public string RefreshToken { get; set; } = null!;
    public DateTime RefreshTokenExpiresUtc { get; set; }
}
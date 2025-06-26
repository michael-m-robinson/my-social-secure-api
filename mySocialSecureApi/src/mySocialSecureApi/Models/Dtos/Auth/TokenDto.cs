using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Auth;

public class TokenDto : BaseOperationDto
{
    public string Token { get; set; } = default!; // Refresh token
    public DateTime ExpiresUtc { get; set; }
    public string? AccessToken { get; set; } = null;
    public DateTime? AccessTokenExpiresUtc { get; set; } // metadata
}

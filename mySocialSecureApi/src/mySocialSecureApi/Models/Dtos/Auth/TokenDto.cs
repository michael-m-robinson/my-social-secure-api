using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Auth;

public class TokenDto: BaseOperationDto
{
    public DateTime ExpiresUtc { get; set; }
}
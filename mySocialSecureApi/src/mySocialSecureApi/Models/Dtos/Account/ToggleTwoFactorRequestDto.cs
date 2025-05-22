using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class ToggleTwoFactorRequestDto: BaseOperationDto
{
    public string UserId { get; set; }
    public bool IsEnabled { get; set; }
}
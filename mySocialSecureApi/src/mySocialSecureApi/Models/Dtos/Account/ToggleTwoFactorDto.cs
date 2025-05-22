using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class ToggleTwoFactorDto: BaseOperationDto
{
    public bool IsEnabled { get; set; }
}
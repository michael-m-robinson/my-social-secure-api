using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Account;

public class ToggleTwoFactorRequest
    : BaseOperationDto
{
    public bool IsEnabled { get; init; }
}
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.LoginTracking;

public class LoginHistoryListDto:BaseOperationDto
{
    public List<LoginHistoryDto> LoginHistories { get; set; } = new();
}
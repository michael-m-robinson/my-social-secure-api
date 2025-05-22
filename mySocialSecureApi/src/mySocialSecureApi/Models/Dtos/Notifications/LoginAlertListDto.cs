using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Notifications;

public class LoginAlertListDto: BaseOperationDto
{
    public List<LoginAlertDto> LoginAlerts { get; set; }
}
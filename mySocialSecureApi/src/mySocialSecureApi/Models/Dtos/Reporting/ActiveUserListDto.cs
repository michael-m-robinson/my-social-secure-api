using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Reporting;

public class ActiveUserListDto: BaseOperationDto
{
    public List<ActiveUserDto> TopActiveUsers { get; set; } = new();
}
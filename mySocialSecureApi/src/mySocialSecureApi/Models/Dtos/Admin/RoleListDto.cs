using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Admin;

public class RoleListDto: BaseOperationDto
{
    public List<string> Roles { get; set; } = new();
}
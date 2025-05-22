using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Admin;

public class UserListDto: BaseOperationDto
{
    public List<UserDto> Users { get; set; } = new();
}
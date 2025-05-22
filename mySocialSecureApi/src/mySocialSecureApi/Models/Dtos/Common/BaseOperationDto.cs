namespace My_Social_Secure_Api.Models.Dtos.Common;

public abstract class BaseOperationDto
{
    public required Enums.Common.OperationStatus Status { get; set; } = Enums.Common.OperationStatus.Ok;
    public string? Description { get; set; }
    public List<string>? Errors { get; set; }
    public string? Token { get; set; }
}
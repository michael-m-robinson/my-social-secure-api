using System.ComponentModel.DataAnnotations;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Models.Dtos.Common;

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace My_Social_Secure_Api.Models.Common;


public class ApiError: BaseOperationDto
{
    [Required]
    public ErrorCategory Category { get; init; }
    [Required]
    public string Code { get; set; } = string.Empty;
}
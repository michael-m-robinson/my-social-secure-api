using System.ComponentModel.DataAnnotations;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.LoginTracking;

public class LoginHistoryDto: BaseOperationDto
{
    public string? IpAddress { get; set; }
    public string? Device { get; set; }
    public string? Location { get; set; }
    public DateTime LoginTimeUtc { get; set; }
}
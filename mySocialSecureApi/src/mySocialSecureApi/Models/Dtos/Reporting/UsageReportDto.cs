using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Reporting;

public class UsageReportDto: BaseOperationDto
{
    public int TotalUsers { get; set; } = 0;
    public int TotalFeedback { get; set; } = 0;
}
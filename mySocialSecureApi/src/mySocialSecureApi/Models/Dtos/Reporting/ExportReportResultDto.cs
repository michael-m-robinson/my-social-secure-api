using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Reporting;

public class ExportReportResultDto: BaseOperationDto
{
    public string FileName { get; set; } = string.Empty;
}
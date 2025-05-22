using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Reporting;

namespace My_Social_Secure_Api.Interfaces.Services.Reporting;

public interface IReportService
{
    Task<ApiResponse<UsageReportDto>> GetAppUsageReportAsync();
}
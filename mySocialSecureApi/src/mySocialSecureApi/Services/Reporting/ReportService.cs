using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Reporting;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Reporting;
using Microsoft.EntityFrameworkCore;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Reporting;

public class ReportService : IReportService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ReportService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public ReportService(
        ApplicationDbContext context,
        ILogger<ReportService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<ApiResponse<UsageReportDto>> GetAppUsageReportAsync()
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        try
        {
            _logger.LogInformation("GetAppUsageReportAsync started. CorrelationId: {CorrelationId}", correlationId);

            return new ApiResponse<UsageReportDto>
            {
                Success = true,
                Message = "App usage report",
                Data = await BuildUsageReportAsync()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while generating app usage report. CorrelationId: {CorrelationId}",
                correlationId);
            return new ApiResponse<UsageReportDto>
            {
                Success = false,
                Message = "An error occurred while generating the usage report.",
                Error = new ApiError
                {
                    Status = OperationStatus.Error,
                    Code = "INTERNAL_ERROR",
                    Category = ErrorCategory.Internal,
                    Description = ex.Message,
                    Errors = new List<string> { ex.Message }
                }
            };
        }
    }

    private async Task<UsageReportDto> BuildUsageReportAsync()
    {
        return new UsageReportDto
        {
            Status = OperationStatus.Ok,
            Description = "The usage report was generated successfully and is available for review.",
            TotalUsers = await _context.Users.CountAsync(),
            TotalFeedback = await _context.Feedbacks.CountAsync(),
        };
    }
}
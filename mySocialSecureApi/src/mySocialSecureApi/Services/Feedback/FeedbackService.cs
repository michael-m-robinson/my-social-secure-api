using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Feedback;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Feedback;
using My_Social_Secure_Api.Models.Entities.Feedback;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Feedback;

public class FeedbackService : IFeedbackService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<FeedbackService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public FeedbackService(ApplicationDbContext context, ILogger<FeedbackService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<ApiResponse<FeedbackListDto>> GetFeedbackAsync()
    {
        try
        {
            _logger.LogInformation("GetFeedbackAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("GetFeedbackAsync requested from IP: {IpAddress}", ip);

            var feedbackList = await _context.Feedbacks
                .AsNoTracking()
                .OrderByDescending(f => f.CreatedAt)
                .Select(f => new FeedbackDto
                {
                    Status = OperationStatus.Ok,
                    Id = f.Id.ToString(),
                    UserId = f.UserId,
                    Feedback = f.Feedback,
                    CreatedAt = f.CreatedAt
                })
                .ToListAsync();

            _logger.LogInformation("Fetched {Count} feedback entries.", feedbackList.Count);

            return GenericSuccessResponse(new FeedbackListDto
            {
                Status = OperationStatus.Ok,
                Description = "Feedback fetched successfully.",
                Feedback = feedbackList
            }, "Feedback fetched successfully.");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while fetching feedback.");
            return DatabaseErrorResponse<FeedbackListDto>("Failed to retrieve feedback due to a database error.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt during feedback retrieval.");
            return UnauthorizedErrorResponse<FeedbackListDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching feedback.");
            return InternalErrorResponse<FeedbackListDto>();
        }
    }

    public async Task<ApiResponse<FeedbackDto>> GetByIdAsync(Guid id)
    {
        try
        {
            _logger.LogInformation("GetByIdAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("GetByIdAsync requested from IP: {IpAddress}", ip);

            var feedback = await _context.Feedbacks
                .AsNoTracking()
                .FirstOrDefaultAsync(f => f.Id == id);

            if (feedback == null)
            {
                _logger.LogWarning("Feedback with ID {Id} not found.", id);
                return NotFoundErrorResponse<FeedbackDto>("Feedback not found.");
            }

            var feedbackDto = new FeedbackDto
            {
                Status = OperationStatus.Ok,
                Description = "Feedback fetched successfully.",
                Id = feedback.Id.ToString(),
                UserId = feedback.UserId,
                Feedback = feedback.Feedback,
                CreatedAt = feedback.CreatedAt
            };

            return GenericSuccessResponse(feedbackDto, "Feedback fetched successfully.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt during feedback retrieval.");
            return UnauthorizedErrorResponse<FeedbackDto>();
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while fetching feedback.");
            return DatabaseErrorResponse<FeedbackDto>("Failed to retrieve feedback due to a database error.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching feedback by ID {Id}.", id);
            return InternalErrorResponse<FeedbackDto>();
        }
    }

    public async Task<ApiResponse<OperationDto>> SubmitAsync(CreateFeedbackDto dto, string userId)
    {
        if (string.IsNullOrWhiteSpace(dto.Feedback))
        {
            _logger.LogWarning("Invalid feedback submission by user {UserId}.", userId);
            return ValidationErrorResponse<OperationDto>("Invalid feedback data.");
        }

        try
        {
            _logger.LogInformation("GetByIdAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("GetByIdAsync requested from IP: {IpAddress}", ip);

            var entity = new FeedbackModel
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Feedback = dto.Feedback,
                CreatedAt = DateTime.UtcNow
            };

            _context.Feedbacks.Add(entity);
            var result = await _context.SaveChangesAsync();

            _logger.LogInformation("Submitted feedback with ID {Id} by user {UserId}.", entity.Id, userId);

            return result > 0
                ? GenericSuccessResponse(new OperationDto
                {
                    Status = OperationStatus.Ok,
                    Description = "Feedback submitted successfully."
                }, "Feedback submitted successfully.")
                : InternalErrorResponse<OperationDto>();
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt during feedback retrieval.");
            return UnauthorizedErrorResponse<OperationDto>();
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while fetching feedback.");
            return DatabaseErrorResponse<OperationDto>("Failed to retrieve feedback due to a database error.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching feedback.");
            return InternalErrorResponse<OperationDto>();
        }
    }

    public async Task<ApiResponse<OperationDto>> DeleteFeedbackAsync(Guid feedbackId)
    {
        try
        {
            _logger.LogInformation("DeleteFeedbackAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("DeleteFeedbackAsync requested from IP: {IpAddress}", ip);

            var feedback = await _context.Feedbacks.FindAsync(feedbackId);
            if (feedback == null)
            {
                _logger.LogWarning("Attempt to delete non-existent feedback with ID {Id}.", feedbackId);
                return NotFoundErrorResponse<OperationDto>("Feedback not found.");
            }

            _context.Feedbacks.Remove(feedback);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted feedback with ID {Id}.", feedbackId);

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Feedback deleted successfully."
            }, "Feedback deleted successfully.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt during feedback retrieval.");
            return UnauthorizedErrorResponse<OperationDto>();
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while fetching feedback.");
            return DatabaseErrorResponse<OperationDto>("Failed to retrieve feedback due to a database error.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while deleting feedback with ID {Id}.", feedbackId);
            return InternalErrorResponse<OperationDto>();
        }
    }

    private ApiResponse<T> GenericSuccessResponse<T>(T data, string message) => new()
    {
        Success = true,
        Data = data,
        Message = message
    };

    private ApiResponse<T> NotFoundErrorResponse<T>(string message) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Description = "The resource you're trying to access was not found.",
            Code = "NOT_FOUND",
            Category = ErrorCategory.NotFound,
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> ValidationErrorResponse<T>(string message) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Description = "Some fields contain invalid or missing values.",
            Code = "VALIDATION_ERROR",
            Category = ErrorCategory.Validation,
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> InternalErrorResponse<T>() => new()
    {
        Success = false,
        Message = "An internal error occurred. Please try again later.",
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Description =
                "The server encountered an unexpected condition that prevented it from fulfilling the request.",
            Code = "INTERNAL_ERROR",
            Category = ErrorCategory.Internal,
            Errors = new List<string> { "A server error has occurred." }
        }
    };

    private ApiResponse<T> DatabaseErrorResponse<T>(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description = "The request could not be completed due to a database error.",
                Code = "DATABASE_ERROR",
                Category = ErrorCategory.Internal,
                Errors = new List<string>() { message }
            }
        };
    }

    private ApiResponse<T> UnauthorizedErrorResponse<T>()
    { 
        return new ApiResponse<T>
        {
            Success = false,
            Message = "Access denied.",
            Error = new ApiError
            {
                Status = OperationStatus.Failed,
                Description = "You do not have permission to access this resource.",
                Code = "UNAUTHORIZED_ACCESS",
                Category = ErrorCategory.Authorization,
                Errors = new List<string>() { "Access denied." }
            }
        };
    }
}
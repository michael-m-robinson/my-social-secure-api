using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Feedback;

namespace My_Social_Secure_Api.Interfaces.Services.Feedback;

public interface IFeedbackService
{
    public Task<ApiResponse<FeedbackListDto>> GetFeedbackAsync();
    Task<ApiResponse<FeedbackDto>> GetByIdAsync(Guid id);
    Task<ApiResponse<OperationDto>> SubmitAsync(CreateFeedbackDto dto, string userId);
    Task<ApiResponse<OperationDto>> DeleteFeedbackAsync(Guid feedbackId);
}
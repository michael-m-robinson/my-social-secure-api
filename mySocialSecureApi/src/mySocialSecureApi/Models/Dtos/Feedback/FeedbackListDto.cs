using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Feedback;

public class FeedbackListDto: BaseOperationDto
{
    public List<FeedbackDto> Feedback { get; set; } = new();
}
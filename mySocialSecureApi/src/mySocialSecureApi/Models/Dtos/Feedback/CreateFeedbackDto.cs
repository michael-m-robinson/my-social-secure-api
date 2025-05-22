using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Dtos.Feedback;

public class CreateFeedbackDto
{
    [Required]
    [MaxLength(1000)]
    public required string Feedback { get; set; }
}
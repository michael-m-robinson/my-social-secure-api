using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class RegistrationEmailConfirmationDto
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string Token { get; set; } = string.Empty;
}
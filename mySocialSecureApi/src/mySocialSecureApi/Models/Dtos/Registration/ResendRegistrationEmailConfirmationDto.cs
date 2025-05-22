using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class ResendRegistrationEmailConfirmationDto
{
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [JsonIgnore]
    [Required]
    public HostString Host { get; set; } = new("example.com");

    [JsonIgnore]
    [Required]
    public string Scheme { get; set; } = "https";
}
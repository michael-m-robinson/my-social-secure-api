using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class ChangePasswordRequestDto
{
    [JsonIgnore]
    [Required]
    public string UserId { get; set; } = string.Empty;

    [JsonIgnore]
    [Required]
    public string Scheme { get; set; } = "https";

    [JsonIgnore]
    [Required]
    public HostString Host { get; set; } = default;
}
using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class InsuranceDto
{
    [Required] public string ProviderName { get; init; } = null!;
    public bool IsFederal { get; init; }
}
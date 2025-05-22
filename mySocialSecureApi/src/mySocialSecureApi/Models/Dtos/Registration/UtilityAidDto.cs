using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class UtilityAidDto
{
    [Required] public string AidType { get; init; } = default!;
    public decimal EstimatedAmount { get; init; }
}
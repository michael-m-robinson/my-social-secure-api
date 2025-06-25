using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class RegisterRequestDto
{
    [Required] public string UserName { get; init; } = null!;
    [Required] public string Email { get; init; } = null!;
    [Required] public string FirstName { get; init; } = null!;
    [Required] public string LastName { get; init; } = null!;
    [Required] public string City { get; init; } = null!;
    [Required] public string State { get; init; } = null!;
    [Required] public string BenefitType { get; init; } = null!;
    [Required] public string Password { get; init; } = null!;
    [Required] public string ConfirmPassword { get; set; } = null!;
    [Required] public bool TwoFactorEnabled { get; set; }

    // Medical Insurance
    public List<InsuranceDto> Insurances { get; init; } = new();

    // Utility Aid
    public bool ReceivesUtilityAid { get; init; }
    public List<UtilityAidDto> UtilityAids { get; init; } = new();

    // Work History
    public bool HasWorkedBefore { get; init; }
    public bool WorkedInLastFiveYears { get; init; }
    public decimal? EarningsLastFiveYears { get; init; }
    public int? TrialWorkMonthsUsed { get; init; }
    public bool TrialWorkPeriodEnded { get; init; }

    // Job Info
    public bool HasNewJob { get; init; }
    public decimal? EstimatedMonthlyIncome { get; init; }
    public bool SavedForFutureUse { get; init; }
    
    //Server information
    [JsonIgnore] public HostString Host { get; set; } = new HostString("localhost", 80);
    [JsonIgnore] public string Scheme { get; set; } = "https";
}

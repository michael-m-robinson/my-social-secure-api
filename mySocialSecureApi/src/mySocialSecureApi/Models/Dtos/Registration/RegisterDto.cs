using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Registration;

public class RegisterDto: BaseOperationDto
{
    public Guid Id { get; set; }
    public string UserName { get; set; } = default!;
    public string Email { get; set; } = default!;
    public string FirstName { get; set; } = default!;
    public string LastName { get; set; } = default!;
    public string City { get; set; } = default!;
    public string State { get; set; } = default!;
    public string BenefitType { get; set; } = default!;

    public List<InsuranceDto> Insurances { get; set; } = new();
    public List<UtilityAidDto> UtilityAids { get; set; } = new();

    public bool HasWorkedBefore { get; set; }
    public bool WorkedInLastFiveYears { get; set; }
    public decimal? EarningsLastFiveYears { get; set; }
    public int? TrialWorkMonthsUsed { get; set; }
    public bool TrialWorkPeriodEnded { get; set; }

    public bool HasNewJob { get; set; }
    public decimal? EstimatedMonthlyIncome { get; set; }
    public bool SavedForFutureUse { get; set; }

    public int RemainingTrialWorkMonths { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool EmailConfirmationSent { get; set; }
}
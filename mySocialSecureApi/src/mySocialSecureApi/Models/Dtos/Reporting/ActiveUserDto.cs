namespace My_Social_Secure_Api.Models.Dtos.Reporting;

public class ActiveUserDto
{
    public string UserId { get; set; } = string.Empty;
    public int CalculationCount { get; set; }
}
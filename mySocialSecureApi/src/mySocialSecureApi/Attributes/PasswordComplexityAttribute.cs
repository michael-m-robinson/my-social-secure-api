using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using My_Social_Secure_Api.Services.Security;

namespace My_Social_Secure_Api.Attributes;

public class PasswordComplexityAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        var password = value as string;
        if (string.IsNullOrWhiteSpace(password)) return new ValidationResult("Password is required.");

        // Check for 12 characters
        if (password.Length < 12) return new ValidationResult("Password must be at least 12 characters.");

        // Check for at least 1 uppercase letter
        if (!Regex.IsMatch(password, @"[A-Z]"))
            return new ValidationResult("Password must contain at least one uppercase letter.");

        // Check for at least 1 lowercase letter
        if (!Regex.IsMatch(password, @"[a-z]"))
            return new ValidationResult("Password must contain at least one lowercase letter.");

        // Check for at least 1 digit
        if (!Regex.IsMatch(password, @"[0-9]"))
            return new ValidationResult("Password must contain at least one digit.");

        // Check for at least 1 special character
        if (!Regex.IsMatch(password, @"[^A-Za-z0-9]"))
            return new ValidationResult("Password must contain at least one special character.");

        // Check for common passwords
        var checker = validationContext.GetService(typeof(PwnedPasswordService))
            as PwnedPasswordService;

        var result = checker?.IsPasswordPwnedAsync(password).GetAwaiter().GetResult();
        if (result == true)
            return new ValidationResult("Password should not contain common dictionary words or personal information.");

        return ValidationResult.Success;
    }
}
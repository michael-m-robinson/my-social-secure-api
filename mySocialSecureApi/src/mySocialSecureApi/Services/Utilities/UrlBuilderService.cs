using System.Web;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Account;
using My_Social_Secure_Api.Models.Auth;

namespace My_Social_Secure_Api.Services.Utilities;

public class UrlBuilderService(
    ILogger<UrlBuilderService> logger,
    IHttpContextAccessor httpContextAccessor) : IUrlBuilderService
{
    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    private string CorrelationId =>
        httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public string BuildEmailChangeCallbackUrl(EmailChangeRequest request)
    {
        var host = ValidateRequestModel(request.Scheme, request.Host, request.UserId, request.NewEmail, request.Token);

        var baseUrl = $"{request.Scheme}://{host}/account/confirm-email-change";
        var query = $"userId={Encode(request.UserId)}&newEmail={Encode(request.NewEmail)}&token={Encode(request.Token)}";
        logger.LogInformation(
            "Building email change callback URL with Correlation ID: {CorrelationId}, Base URL: {BaseUrl}, Query: {Query}",
            CorrelationId, baseUrl, query);
        return $"{baseUrl}?{query}";
    }

    public string BuildTwoFactorCallbackUrl(TwoFactorAuthRequest request)
    {
        var host = ValidateRequestModel(request.Scheme, request.Host, request.UserName, request.Code);

        var baseUrl = $"{request.Scheme}://{host}/auth/confirm-2fa";
        var query =
            $"userName={Encode(request.UserName)}&twoFactorCode={Encode(request.Code)}&rememberMe={request.RememberMe.ToString().ToLower()}";
        logger.LogInformation(
            "Building two-factor callback URL with Correlation ID: {CorrelationId}, Base URL: {BaseUrl}, Query: {Query}",
            CorrelationId, baseUrl, query);
        return $"{baseUrl}?{query}";
    }

    public string BuildEmailConfirmationUrl(EmailConfirmationRequest request)
    {
        var host = ValidateRequestModel(request.Scheme, request.Host, request.UserId, request.Token);

        var baseUrl = $"{request.Scheme}://{host}/auth/confirm-email";
        var query = $"userId={Encode(request.UserId)}&token={Encode(request.Token)}";
        logger.LogInformation(
            "Building email confirmation URL with Correlation ID: {CorrelationId}, Base URL: {BaseUrl}, Query: {Query}",
            CorrelationId, baseUrl, query);
        return $"{baseUrl}?{query}";
    }
    
    public string BuildPasswordChangeUrl(PasswordChangeRequest request)
    {
        var host = ValidateRequestModel(request.Scheme, request.Host, request.UserId, request.Token);

        var baseUrl = $"{request.Scheme}://{host}/account/change-password";
        var query = $"userId={Encode(request.UserId)}&token={Encode(request.Token)}";
        logger.LogInformation(
            "Building password change callback URL with Correlation ID: {CorrelationId}, Base URL: {BaseUrl}, Query: {Query}",
            CorrelationId, baseUrl, query);
        return $"{baseUrl}?{query}";
    }

    private static string ValidateRequestModel(string scheme, HostString host, params string[] requiredFields)
    {
        if (string.IsNullOrWhiteSpace(scheme))
            throw new ArgumentException("Scheme is required.", nameof(scheme));

        if (!host.HasValue || string.IsNullOrWhiteSpace(host.Value))
            throw new ArgumentException("Host is required.", nameof(host));

        foreach (var field in requiredFields)
        {
            if (string.IsNullOrWhiteSpace(field))
                throw new ArgumentException("All required fields must be non-empty.");
        }

        return host.Value;
    }
}
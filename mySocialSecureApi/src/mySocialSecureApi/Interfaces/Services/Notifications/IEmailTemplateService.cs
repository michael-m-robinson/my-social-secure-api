namespace My_Social_Secure_Api.Interfaces.Services.Notifications;

public interface IEmailTemplateService
{
    Task<string> LoadTemplateAsync(string templateName, Dictionary<string, string> replacements);
}
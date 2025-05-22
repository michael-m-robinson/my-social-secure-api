using System.Text.Json;

namespace My_Social_Secure_Api.Models.Error;

public class ErrorDetails
{
    public int StatusCode { get; set; }
    public string Message { get; set; } = "An unexpected error occurred.";

    public override string ToString() => JsonSerializer.Serialize(this);
}
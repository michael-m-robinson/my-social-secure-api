using System.Text.Json.Serialization;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class DeleteAccountRequestDto
{
    [JsonIgnore]
    public string UserId { get; set; } = string.Empty;
    public bool Confirm { get; set; }
}
namespace My_Social_Secure_Api.Models.Common;

public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Message { get; set; }
    public ApiError? Error { get; set; }
    
    public static ApiResponse<T> FromError(ApiError error) => new()
    {
        Success = false,
        Error = error,
        Message = error.Description
    };
}
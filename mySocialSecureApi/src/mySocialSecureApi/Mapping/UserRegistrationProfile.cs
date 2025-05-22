using AutoMapper;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Entities.Registration;

namespace My_Social_Secure_Api.Mapping;

public class UserRegistrationProfile : Profile
{
    public UserRegistrationProfile()
    {
        CreateMap<UserRegistration, RegisterDto>();
        CreateMap<UserInsurance, InsuranceDto>();
        CreateMap<UserUtilityAid, UtilityAidDto>();
    }
}
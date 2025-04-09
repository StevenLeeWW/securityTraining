using Microsoft.AspNetCore.Authorization;

public class UserResourceRequirement : IAuthorizationRequirement
{
    public UserResourceRequirement(){
        // No specific properties needed for this requirement
    }
}
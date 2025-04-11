using Microsoft.AspNetCore.Authorization;

namespace VulnerableApp.Controllers
{
    public class UserResourceRequirement : IAuthorizationRequirement
    {
        // This class is intentionally left empty. It serves as a marker for the authorization handler.
    }
}
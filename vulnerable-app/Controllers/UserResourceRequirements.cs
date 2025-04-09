using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using VulnerableApp.Models;

namespace VulnerableApp.Authorization;

public class UserResourceRequirement : IAuthorizationRequirement
{
    public UserResourceRequirement()
    {
        // No specific properties needed for this requirement
    }
}
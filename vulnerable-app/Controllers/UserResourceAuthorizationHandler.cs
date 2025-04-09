public class UserResourceAuthorizationHandler : AuthorizationHandler<UserResourceRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        UserResourceRequirement requirement
        User resource)
    {
        var currentUserId = int.Parse(context.User.FindFirst("UserId")?.Value ?? "0");
        if (resource.UserId == currentUserId || context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
        }
        else
        {
context.Fail();
        }
 
        return Task.CompletedTask;
    }
}
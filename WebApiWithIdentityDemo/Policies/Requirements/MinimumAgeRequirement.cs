using Microsoft.AspNetCore.Authorization;

namespace WebApiWithIdentityDemo.Policies.Requirements;

public class MinimumAgeRequirement(int minimumAge) : IAuthorizationRequirement
{
    public int MinimumAge { get; } = minimumAge;
}
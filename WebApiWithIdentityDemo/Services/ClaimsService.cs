using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using WebApiWithIdentityDemo.Data.Models;

namespace WebApiWithIdentityDemo.Services;

public interface IClaimsService
{
    Task<IList<Claim>> GetUserClaims(string userName);
    Task<IdentityResult> AddClaim(string userName, string claimType, string claimValue);
}

public class ClaimsService(UserManager<ApplicationUser> userManager) : IClaimsService
{
    public async Task<IList<Claim>> GetUserClaims(string userName)
    {
        var user = await userManager.FindByNameAsync(userName);

        if (user is null)
        {
            return new List<Claim>();
        }

        return await userManager.GetClaimsAsync(user);
    }
    
    public async Task<IdentityResult> AddClaim(string userName, string claimType, string claimValue)
    {
        var user = await userManager.FindByNameAsync(userName);

        if (user is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.InvalidUserName(userName));
        }

        var claim = new Claim(claimType, claimValue, ClaimValueTypes.String);
        return await userManager.AddClaimAsync(user,claim);
    }
}
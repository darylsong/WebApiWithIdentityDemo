using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using WebApiWithIdentityDemo.Controllers;
using WebApiWithIdentityDemo.Data.Models;

namespace WebApiWithIdentityDemo.Services;

public interface IAccountService
{
    Task<IdentityResult> Register(RegisterRequest request);
    Task<ApplicationUser?> GetUser(string userName);
    Task<SignInResult> SignIn(ApplicationUser user, string password);
    Task<string> GetJwtSecurityTokenAsync(ApplicationUser user);
    Task<IdentityResult> AddToRole(string userName, string roleName);
    Task<IList<string>> GetRoles(string userName);
}

public class AccountService(
    IOptions<JwtConfigOptions> jwtConfigOptions,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) : IAccountService
{
    public async Task<IdentityResult> Register(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.UserName,
            Email = request.Email,
        };

        return await userManager.CreateAsync(user, request.Password);
    }

    public async Task<ApplicationUser?> GetUser(string userName)
    {
        return await userManager.FindByNameAsync(userName);
    }

    public async Task<SignInResult> SignIn(ApplicationUser user, string password)
    {
        return await signInManager.CheckPasswordSignInAsync(
            user,
            password,
            false
        );
    }

    public async Task<string> GetJwtSecurityTokenAsync(ApplicationUser user)
    {
        var signingCredentials = GetSigningCredentials();
        
        var claims = await GetClaims(user);
        
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        
        return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
    }
    
    public async Task<IdentityResult> AddToRole(string userName, string roleName)
    {
        var user = await GetUser(userName);
        
        if (user is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.InvalidUserName(userName));
        }

        return await userManager.AddToRoleAsync(user, roleName);
    }
    
    public async Task<IList<string>> GetRoles(string userName)
    {
        var user = await GetUser(userName);
        
        if (user is null)
        {
            return new List<string>();
        }

        return await userManager.GetRolesAsync(user);
    }

    private SigningCredentials GetSigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(jwtConfigOptions.Value.Secret);
        
        var secret = new SymmetricSecurityKey(key);
        
        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    private async Task<List<Claim>> GetClaims(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName)
        };
        
        var roles = await userManager.GetRolesAsync(user);
        
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        return claims;
    }

    private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
    {
        var tokenOptions = new JwtSecurityToken
        (
            issuer: jwtConfigOptions.Value.ValidIssuer,
            audience: jwtConfigOptions.Value.ValidAudience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(jwtConfigOptions.Value.ExpiresInMinutes),
            signingCredentials: signingCredentials
        );
        
        return tokenOptions;
    }
}
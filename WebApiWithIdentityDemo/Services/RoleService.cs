using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace WebApiWithIdentityDemo.Services;

public interface IRoleService
{
    Task<IdentityRole?> GetRole(string roleName);
    Task<List<IdentityRole>> GetRoles();
    Task<IdentityResult> CreateRole(string roleName);
    Task<IdentityResult> DeleteRole(string roleName);
}

public class RoleService(
    RoleManager<IdentityRole> roleManager) : IRoleService
{
    public async Task<IdentityRole?> GetRole(string roleName)
    {
        return await roleManager.Roles
            .SingleOrDefaultAsync(role => role.Name == roleName);
    }

    public async Task<List<IdentityRole>> GetRoles()
    {
        return await roleManager.Roles.ToListAsync();
    }

    public async Task<IdentityResult> CreateRole(string roleName)
    {
        return await roleManager.CreateAsync(new IdentityRole(roleName));
    }
    
    public async Task<IdentityResult> DeleteRole(string roleName)
    {
        var role = await roleManager.FindByNameAsync(roleName);

        if (role is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.InvalidRoleName(roleName));
        }
        
        return await roleManager.DeleteAsync(role);
    }
}
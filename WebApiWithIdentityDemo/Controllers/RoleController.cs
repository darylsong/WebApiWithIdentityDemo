using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentityDemo.Services;

namespace WebApiWithIdentityDemo.Controllers;

[Authorize(Roles = "Admin")]
[Route("api/[controller]")]
[ApiController]
public class RoleController(IRoleService roleService) : ControllerBase
{
    [HttpGet("{roleName}")]
    public async Task<ActionResult> GetRole(string roleName)
    {
        return Ok(await roleService.GetRole(roleName));
    }

    [HttpGet]
    public async Task<ActionResult> GetRoles()
    {
        return Ok(await roleService.GetRoles());
    }
    
    [HttpPost]
    public async Task<ActionResult> CreateRole(string roleName)
    {
        return Ok(await roleService.CreateRole(roleName));
    }
    
    [HttpDelete("{roleName}")]
    public async Task<ActionResult> DeleteRole(string roleName)
    {
        return Ok(await roleService.DeleteRole(roleName));
    }
}
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApiWithIdentityDemo.Controllers;

[Authorize(Policy = "EmployeeOnly")]
[Route("api/[controller]/[action]")]
[ApiController]
public class TestClaimsController : ControllerBase
{
    [HttpGet]
    public ActionResult Test()
    {
        return Ok("Successful");
    }
}
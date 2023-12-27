using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApiWithIdentityDemo.Data.Models;

namespace WebApiWithIdentityDemo.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : 
    IdentityDbContext<ApplicationUser>(options);
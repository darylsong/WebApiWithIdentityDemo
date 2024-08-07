using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using WebApiWithIdentityDemo;
using WebApiWithIdentityDemo.Data;
using WebApiWithIdentityDemo.Data.Models;
using WebApiWithIdentityDemo.Helpers;
using WebApiWithIdentityDemo.Policies.Handlers;
using WebApiWithIdentityDemo.Policies.Requirements;
using WebApiWithIdentityDemo.Services;

var builder = WebApplication.CreateBuilder(args);

// Add configurations from appsettings
builder.Services
    .AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.JwtConfig));

builder.Services
    .AddOptions<SmtpOptions>()
    .Bind(builder.Configuration.GetSection(SmtpOptions.SmtpConfig));

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme.",
    });
    
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer",
                }
            },
            new string[] { }
        }
    });
});

// Add EF Core
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"))); 

// Add ASP.NET Core Identity
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Add JWT authentication
var jwtConfigOptions = builder.Configuration
    .GetSection(JwtOptions.JwtConfig)
    .Get<JwtOptions>()!;

JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Remove default claims

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(configureOptions =>
    {
        configureOptions.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtConfigOptions.ValidIssuer,
            ValidAudience = jwtConfigOptions.ValidAudience,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(jwtConfigOptions.Secret)),
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
        };
    });

// Add policy authorization
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"))
    .AddPolicy("AtLeast21", policy =>
    policy.Requirements.Add(new MinimumAgeRequirement(21)));

// Add policy requirement handlers

builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();

// Add application services
builder.Services.AddScoped<IEmailSender<ApplicationUser>, EmailSender>();
builder.Services.AddTransient<IAccountService, AccountService>();
builder.Services.AddTransient<IRoleService, RoleService>();
builder.Services.AddTransient<IClaimsService, ClaimsService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
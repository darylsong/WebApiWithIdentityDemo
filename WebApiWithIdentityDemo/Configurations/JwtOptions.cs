namespace WebApiWithIdentityDemo;

public class JwtOptions
{
    public const string JwtConfig = "JwtConfig";
    
    public string ValidIssuer { get; set; }
    
    public string ValidAudience { get; set; }
    
    public string Secret { get; set; }
    
    public int ExpiresInMinutes { get; set; }
}
using System.Security.Claims;

namespace JwtWebApi.Services.UserService
{
    public class UserService : IUserService
    {
        IHttpContextAccessor httpContextAccessor;

        public UserService(IHttpContextAccessor accessor)
        {
            httpContextAccessor = accessor;
        }

        public IHttpContextAccessor Accessor { get; }

        public string GetMyName()
        {
            return GetMyClaim(ClaimTypes.NameIdentifier, "Username not found");
        }

        public string GetMyRole()
        {
            return GetMyClaim(ClaimTypes.Role, "Role not found");
        }

        private string GetMyClaim(string claimType, string defaultValue = "Claim not found")
        {
            var result = string.Empty;

            if (httpContextAccessor.HttpContext?.User != null)
            {
                result = httpContextAccessor.HttpContext.User.FindFirstValue(claimType) ?? defaultValue;
            }

            return result;
        }
    }
}

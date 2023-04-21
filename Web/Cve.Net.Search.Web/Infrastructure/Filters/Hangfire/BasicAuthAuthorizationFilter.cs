using Hangfire.Dashboard;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Text;
using System;
using System.Text.RegularExpressions;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire
{
    /// <summary>
    /// Represents Hangfire authorization filter for basic authentication
    /// </summary>
    public class BasicAuthAuthorizationFilter : IDashboardAuthorizationFilter
    {
        private readonly BasicAuthAuthorizationFilterOptions _options;

        public BasicAuthAuthorizationFilter()
            : this(new BasicAuthAuthorizationFilterOptions())
        {
        }

        public BasicAuthAuthorizationFilter(BasicAuthAuthorizationFilterOptions options)
        {
            _options = options;
        }

        public bool Authorize(DashboardContext _context)
        {
            var context = _context.GetHttpContext();

            string header = context.Request.Headers["Authorization"];

            // Get authorization key
            var authorizationHeader = context.Request.Headers["Authorization"].ToString();
            var authHeaderRegex = new Regex(@"Basic (.*)");

            if (!authHeaderRegex.IsMatch(authorizationHeader))
                return Unathorized(context);

            var authBase64 = Encoding.UTF8.GetString(Convert.FromBase64String(authHeaderRegex.Replace(authorizationHeader, "$1")));
            var authSplit = authBase64.Split(Convert.ToChar(":"), 2);
            var authUsername = authSplit[0];
            var authPassword = authSplit.Length > 1 ? authSplit[1] : throw new Exception("Unable to get password");

            return _options.Users.Any(user => user.Validate(authUsername, authPassword, _options.LoginCaseSensitive)) || Unathorized(context);            
        }

        #region Private

        private static bool Unathorized(HttpContext context)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Append("WWW-Authenticate", "Basic");
            return false;
        }

        #endregion
    }
}

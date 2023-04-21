using System.Collections.Generic;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire
{
    /// <summary>
    /// Represents options for Hangfire basic authentication
    /// </summary>
    public class BasicAuthAuthorizationFilterOptions
    {
        public BasicAuthAuthorizationFilterOptions()
        {
            LoginCaseSensitive = true;
            Users = new BasicAuthAuthorizationUser[] { };
        }

        /// <summary>
        /// Whether or not login checking is case sensitive.
        /// </summary>
        public bool LoginCaseSensitive { get; set; }

        /// <summary>
        /// Represents users list to access Hangfire dashboard.
        /// </summary>
        public IEnumerable<BasicAuthAuthorizationUser> Users { get; set; }
    }
}

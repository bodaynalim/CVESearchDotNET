using System.Collections;
using System.Text;
using System;
using System.Security.Cryptography;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire
{
    /// <summary>
    /// Represents user to access Hangfire dashboard via basic authentication
    /// </summary>
    public class BasicAuthAuthorizationUser
    {
        /// <summary>
        /// Represents user's name
        /// </summary>
        public string Login { get; set; }

        /// <summary>
        /// SHA1 hashed password
        /// </summary>
        public byte[] Password { get; set; }

        /// <summary>
        /// Setter to update password as plain text
        /// </summary>
        public string PasswordClear
        {
            set
            {
                using (var cryptoProvider = SHA256.Create())
                {
                    Password = cryptoProvider.ComputeHash(Encoding.UTF8.GetBytes(value));
                }
            }
        }

        /// <summary>
        /// Validate user
        /// </summary>
        /// <param name="login">User name</param>
        /// <param name="password">User password</param>
        /// <param name="loginCaseSensitive">Whether or not login checking is case sensitive</param>
        /// <returns></returns>
        public bool Validate(string login, string password, bool loginCaseSensitive)
        {
            if (string.IsNullOrWhiteSpace(login) || string.IsNullOrWhiteSpace(password) || 
                !login.Equals(Login, loginCaseSensitive ? StringComparison.CurrentCulture : StringComparison.OrdinalIgnoreCase))
                return false;

            using var cryptoProvider = SHA256.Create();
            byte[] passwordHash = cryptoProvider.ComputeHash(Encoding.UTF8.GetBytes(password));
            return StructuralComparisons.StructuralEqualityComparer.Equals(passwordHash, Password);
        }
    }
}

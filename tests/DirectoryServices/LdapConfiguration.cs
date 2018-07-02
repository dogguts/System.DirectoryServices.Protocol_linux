// '/dotnet/corefx/src/Common/tests/System/DirectoryServices/LdapConfiguration.cs'
using System.IO;
using System.Xml.Linq;

namespace System.DirectoryServices.Tests
{
    internal class LdapConfiguration
    {
        private LdapConfiguration(string serverName, string domain, string userName, string password, string port, System.DirectoryServices.Protocols.AuthType at)
        {
            ServerName = serverName;
            Domain = domain;
            UserName = userName;
            Password = password;
            Port = port;
            AuthenticationTypes = at;
        }

        private static LdapConfiguration s_ldapConfiguration = GetConfiguration("LDAP.Configuration.xml");

        internal static LdapConfiguration Configuration => s_ldapConfiguration;

        internal string ServerName { get; set; }
        internal string UserName { get; set; }
        internal string Password { get; set; }
        internal string Port { get; set; }
        internal string Domain { get; set; }
        internal System.DirectoryServices.Protocols.AuthType AuthenticationTypes { get; set; }
        internal string LdapPath => string.IsNullOrEmpty(Port) ? $"LDAP://{ServerName}/{Domain}" : $"LDAP://{ServerName}:{Port}/{Domain}";
        internal string RootDSEPath => string.IsNullOrEmpty(Port) ? $"LDAP://{ServerName}/rootDSE" : $"LDAP://{ServerName}:{Port}/rootDSE";
        internal string UserNameWithNoDomain
        {
            get
            {
                string[] parts = UserName.Split('\\');
                if (parts.Length > 1)
                    return parts[parts.Length - 1];

                parts = UserName.Split('@');
                if (parts.Length > 1)
                    return parts[0];

                return UserName;
            }
        }

        internal string GetLdapPath(string prefix) // like "ou=something"
        {
            return string.IsNullOrEmpty(Port) ? $"LDAP://{ServerName}/{prefix},{Domain}" : $"LDAP://{ServerName}:{Port}/{prefix},{Domain}";
        }

        private const string LDAP_CAP_ACTIVE_DIRECTORY_OID = "1.2.840.113556.1.4.800";

        internal bool IsActiveDirectoryServer => false;
         
        internal static LdapConfiguration GetConfiguration(string configFile)
        {
            return null;
        }
    }
}
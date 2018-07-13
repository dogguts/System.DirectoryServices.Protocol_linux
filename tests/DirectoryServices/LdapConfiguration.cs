// '/dotnet/corefx/src/Common/tests/System/DirectoryServices/LdapConfiguration.cs'
using System.IO;
using System.Xml.Linq;

namespace System.DirectoryServices.Tests
{
    internal class NativeMethods
    {
        public enum AuthenticationModes
        {
            SecureAuthentication = 0x1,
            UseEncryption = 0x2,
            UseSSL = 0x2,
            ReadonlyServer = 0x4,
            NoAuthentication = 0x10,
            FastBind = 0x20,
            UseSigning = 0x40,
            UseSealing = 0x80,
            UseDelegation = 0x100,
            UseServerBinding = 0x200
        }
    }
    /// <devdoc>
    ///  Specifies what kind of acknowledgment to get after sending a message.
    /// </devdoc>
    [Flags]
    public enum AuthenticationTypes
    {
        None = 0,

        /// <devdoc>
        ///     Requests secure authentication. When this flag is set, the WinNT provider uses NT LAN Manager (NTLM) 
        ///     to authenticate the client. Active Directory will use Kerberos, and possibly NTLM, to authenticate the client. 
        /// </devdoc>
        Secure = NativeMethods.AuthenticationModes.SecureAuthentication,

        /// <devdoc>
        ///     Forces ADSI to use encryption for data exchange over the network. 
        /// </devdoc>
        Encryption = NativeMethods.AuthenticationModes.UseEncryption,

        /// <devdoc>
        ///     Encrypts the channel with SSL. Data will be encrypted using SSL. Active Directory requires that the 
        ///     Certificate Server be installed to support SSL encryption. 
        /// </devdoc>
        SecureSocketsLayer = NativeMethods.AuthenticationModes.UseSSL,

        /// <devdoc>
        ///     For a WinNT provider, ADSI tries to connect to a primary domain controller or a backup domain 
        ///     controller. For Active Directory, this flag indicates that a writeable server is not required for a 
        ///     serverless binding. 
        /// </devdoc>
        ReadonlyServer = NativeMethods.AuthenticationModes.ReadonlyServer,

        /// <devdoc>
        ///     Request no authentication. The providers may attempt to bind client, as an anonymous user, to the targeted 
        ///     object. The WinNT provider does not support this flag. Active Directory establishes a connection between 
        ///     the client and the targeted object, but will not perform any authentication. Setting this flag amounts to 
        ///     requesting an anonymous binding, which means "Everyone" as the security context. 
        /// </devdoc>
        Anonymous = NativeMethods.AuthenticationModes.NoAuthentication,

        /// <devdoc>
        ///     When this flag is set, ADSI will not attempt to query the objectClass property and thus will only expose 
        ///     the base interfaces supported by all ADSI objects instead of the full object support. 
        /// </devdoc>
        FastBind = NativeMethods.AuthenticationModes.FastBind,

        /// <devdoc>
        ///     Verifies data integrity to ensure the data received is the same as the data sent. The Secure flag 
        ///     must be set also in order to use the signing. 
        /// </devdoc>
        Signing = NativeMethods.AuthenticationModes.UseSigning,

        /// <devdoc>
        ///     Encrypts data using Kerberos. The Secure flag must be set also in order to use the sealing. 
        /// </devdoc>
        Sealing = NativeMethods.AuthenticationModes.UseSealing,

        /// <devdoc>
        ///     Enables ADSI to delegate the user's security context, which is necessary for moving objects across domains. 
        /// </devdoc>
        Delegation = NativeMethods.AuthenticationModes.UseDelegation,

        /// <devdoc>
        ///     Specify this flag when using the LDAP provider if your ADsPath includes a server name. Do not use 
        ///     this flag for paths that include a domain name or for serverless paths.
        /// </devdoc>
        ServerBind = NativeMethods.AuthenticationModes.UseServerBinding
    }
    internal class LdapConfiguration
    {
        private LdapConfiguration(string serverName, string domain, string userName, string password, string port, AuthenticationTypes at)
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
        internal AuthenticationTypes AuthenticationTypes { get; set; }
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
               System.Diagnostics.Debug.WriteLine("GetConfiguration");
            if (!File.Exists(configFile))
            {
                System.Diagnostics.Debug.WriteLine(configFile + " not found ");
                return null;

            }

            LdapConfiguration ldapConfig = null;
            try
            {
                string serverName = "";
                string domain = "";
                string port = "";
                string user = "";
                string password = "";
                AuthenticationTypes at = AuthenticationTypes.None;

                XElement config = XDocument.Load(configFile).Element("Configuration");
                if (config != null)
                {
                    XElement child = config.Element("ServerName");
                    if (child != null)
                        serverName = child.Value;

                    child = config.Element("Domain");
                    if (child != null)
                        domain = child.Value;

                    child = config.Element("Port");
                    if (child != null)
                        port = child.Value;

                    child = config.Element("User");
                    if (child != null)
                        user = child.Value;

                    child = config.Element("Password");
                    if (child != null)
                        password = child.Value;

                    child = config.Element("AuthenticationTypes");
                    if (child != null)
                    {
                        string[] parts = child.Value.Split(',');
                        foreach (string p in parts)
                        {
                            string s = p.Trim();
                            if (s.Equals("Anonymous", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.Anonymous;
                            if (s.Equals("Delegation", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.Delegation;
                            if (s.Equals("Encryption", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.FastBind;
                            if (s.Equals("FastBind", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.FastBind;
                            if (s.Equals("ReadonlyServer", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.ReadonlyServer;
                            if (s.Equals("Sealing", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.Sealing;
                            if (s.Equals("Secure", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.Secure;
                            if (s.Equals("SecureSocketsLayer", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.SecureSocketsLayer;
                            if (s.Equals("ServerBind", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.ServerBind;
                            if (s.Equals("Signing", StringComparison.OrdinalIgnoreCase))
                                at |= AuthenticationTypes.Signing;
                        }
                    }

                    ldapConfig = new LdapConfiguration(serverName, domain, user, password, port, at);
                }
            }
            catch
            {
                // Couldn't read the configurations, usually we'll skip the tests which depend on that
            }
            return ldapConfig;
        }
    }
}

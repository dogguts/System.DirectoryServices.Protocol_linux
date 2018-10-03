// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security;

namespace System.DirectoryServices.Protocols
{

   
    //typedef int (LDAP_TLS_CONNECT_CB) LDAP_P (( struct ldap *ld, void *ssl, void *ctx, void *arg ));





    /*struct ldap {
        // thread shared 
        struct ldap_common	*ldc;

        // thread specific  
        ber_int_t		ld_errno;
        char			*ld_error;
        char			*ld_matched;
        char			**ld_referrals;
    };*/

    // public static extern int ldap_result([In] ConnectionHandle ldapHandle, int messageId, int all, LDAP_TIMEVAL timeout, ref IntPtr result);


    [StructLayout(LayoutKind.Sequential)]
    internal class Luid
    {
        private int _lowPart;
        private int _highPart;

        public int LowPart => _lowPart;
        public int HighPart => _highPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class SEC_WINNT_AUTH_IDENTITY_EX
    {
        public int version;
        public int length;
        public string user;
        public int userLength;
        public string domain;
        public int domainLength;
        public string password;
        public int passwordLength;
        public int flags;
        public string packageList;
        public int packageListLength;
    }

    internal enum BindMethod : uint
    {
        LDAP_AUTH_OTHERKIND = 0x86,
        LDAP_AUTH_SICILY = LDAP_AUTH_OTHERKIND | 0x0200,
        LDAP_AUTH_MSN = LDAP_AUTH_OTHERKIND | 0x0800,
        LDAP_AUTH_NTLM = LDAP_AUTH_OTHERKIND | 0x1000,
        LDAP_AUTH_DPA = LDAP_AUTH_OTHERKIND | 0x2000,
        LDAP_AUTH_NEGOTIATE = LDAP_AUTH_OTHERKIND | 0x0400,
        LDAP_AUTH_SSPI = LDAP_AUTH_NEGOTIATE,
        LDAP_AUTH_DIGEST = LDAP_AUTH_OTHERKIND | 0x4000,
        LDAP_AUTH_EXTERNAL = LDAP_AUTH_OTHERKIND | 0x0020
    }

    /// <summary>Peer  certificate  checking  strategy</summary>
    internal enum LDAP_OPT_X_TLS
    {
        /// <summary>certificate is not requested</summary>
        NEVER = 0,
        /// <summary>certificate is requested. If no certificate is provided, or a bad certificate is provided, the session is immediately terminated.</summary>
        HARD = 1,
        /// <summary>certificate is requested. If no certificate is provided, or a bad certificate is provided, the session is immediately terminated.</summary>
        DEMAND = 2,
        /// <summary>certificate is requested. If no certificate is provided, the session proceeds normally. If a bad certificate is provided, it will be ignored and the session proceeds normally.</summary>
        ALLOW = 3,
        /// <summary>certificate is requested. If no certificate is provided, the session proceeds normally. If a bad certificate is provided, the session is immediately terminated.</summary>
        TRY = 4,
    }

    /// <summary>
    /// Sets/gets the CRL evaluation strategy
    /// </summary>
    internal enum LDAP_OPT_X_TLS_CRL
    {
        NONE = 0,
        PEER = 1,
        ALL = 2
    }



    internal enum LdapOption
    {
        /// <summary>Used to retrieve some basic information about the LDAP API implementation at execution time.</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_API_INFO = 0x00,
        /// <summary>Sets or retrieves the value of the underlying SOCKET descriptor that corresponds to the default LDAP connection</summary>
        /// <remarks>ldap-c-api-3 (historic)</remarks>
        LDAP_OPT_DESC = 0x01,
        /// <summary>Determines how aliases are handled during search</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_DEREF = 0x02,
        /// <summary>Sets/gets the value that defines the maximum number of entries to be returned by a search operation</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_SIZELIMIT = 0x03,
        /// <summary>Sets/gets  the  value  that defines the time limit after which a search operation should be terminated by  the  server</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_TIMELIMIT = 0x04,
        /* 0x05 - 0x07 not defined */
        /// <summary>Determines whether the library should implicitly chase referrals or not.</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_REFERRALS = 0x08,
        /// <summary>Determines whether LDAP I/O operations are automatically restarted if they abort prematurely</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_RESTART = 0x09,

        /* 0x0a - 0x10 not defined */

        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_SSL = 0x0a,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_REFERRAL_HOP_LIMIT = 0x10,

        /// <summary>This option indicates the version of the LDAP protocol used when communicating with the primary LDAP server. </summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_PROTOCOL_VERSION = 0x11,
        LDAP_OPT_VERSION = LDAP_OPT_PROTOCOL_VERSION,
        /// <summary>Sets/gets the server-side controls to be used for all operations</summary>
        /// <remarks>
        /// ldap-c-api:  This is now deprecated as modern LDAP C API provides replacements for all main operations which 
        /// accepts server-side controls as explicit arguments
        /// </remarks>
        LDAP_OPT_SERVER_CONTROLS = 0x12,
        /// <summary>
        /// Sets/gets  the  client-side  controls to be used for all operations
        /// </summary>
        /// <remarks>
        /// ldap-c-api:  This is now deprecated as modern LDAP C API provides replacements for all main operations which 
        /// accepts client-side controls as explicit arguments
        /// </remarks>
        LDAP_OPT_CLIENT_CONTROLS = 0x13,

        /* 0x14 not defined */

        /// <summary>
        /// Used to retrieve version information about LDAP API extended features at execution time
        /// </summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_API_FEATURE_INFO = 0x15,

        /* 0x16 - 0x2f not defined */

        /// <summary>
        /// Sets/gets a space-separated list of hosts to be contacted by the library when trying to establish a connection.
        /// </summary>
        /// <remarks>ldap-c-api: This is now deprecated in favor of LDAP_OPT_URI.</remarks>
        LDAP_OPT_HOST_NAME = 0x30,
        /// <summary>Sets/gets the LDAP result code associated to the handle</summary>
        /// <remarks>ldap-c-api: formerly known as LDAP_OPT_ERROR_NUMBER</remarks>
        LDAP_OPT_RESULT_CODE = 0x31,
        LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE,
        /// <summary>Sets/gets a string containing the error string associated to the LDAP handle.</summary>
        /// <remarks>ldap-c-api: formerly known as LDAP_OPT_ERROR_STRING</remarks>
        LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x32,
        LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE,
        /// <summary>Sets/gets a string containing the matched DN associated to the LDAP handle</summary>
        /// <remarks>ldap-c-api</remarks>
        LDAP_OPT_MATCHED_DN = 0x33,
        /* 0x0034 - 0x3fff not defined */

        /* 0x0091 used by Microsoft for LDAP_OPT_AUTO_RECONNECT */

        /// <summary>
        /// Sets or retrieves a ULONG value giving the flags to pass to the SSPI InitializeSecurityContext function.
        /// </summary>
        /// <remarks>microsoft (defined in openldap/support unknown)</remarks>
        LDAP_OPT_SSPI_FLAGS = 0x0092,

        /* 0x0093 used by Microsoft for LDAP_OPT_SSL_INFO */

        /* 0x0094 used by Microsoft for LDAP_OPT_REF_DEREF_CONN_PER_MSG */

        /// <summary>
        /// Determines the Kerberos signing state or enables Kerberos signing
        /// </summary>
        /// <remarks>microsoft (defined in openldap/support unknown)</remarks>
        LDAP_OPT_SIGN = 0x0095,
        /// <summary>
        /// Enables/disables Kerberos encryption prior to binding using the LDAP_AUTH_NEGOTIATE flag
        /// </summary>
        /// <remarks>microsoft (defined in openldap/support unknown)</remarks>
        LDAP_OPT_ENCRYPT = 0x0096,
        /// <summary>
        /// Sets or retrieves the preferred SASL binding method prior to binding using the LDAP_AUTH_NEGOTIATE flag.
        /// </summary>
        /// <remarks>microsoft (defined in openldap/support unknown)</remarks>
        LDAP_OPT_SASL_METHOD = 0x0097,

        /* 0x0098 used by Microsoft for LDAP_OPT_AREC_EXCLUSIVE */
        /// <summary>
        /// Sets or retrieves the security context associated with the current connection.
        /// </summary>
        /// <remarks>microsoft (defined in openldap/support unknown)</remarks>
        LDAP_OPT_SECURITY_CONTEXT = 0x0099,
        /* 0x009A used by Microsoft for LDAP_OPT_ROOTDSE_CACHE */
        /* 0x009B - 0x3fff not defined */

        /* OpenLDAP TLS options */
        LDAP_OPT_X_TLS = 0x6000,
        /// <summary>
        /// Sets/gets the TLS library context. New TLS sessions will inherit their default settings from this library context.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CTX = 0x6001,    // OpenSSL CTX
        /// <summary>
        /// Sets/gets  the  full-path  of  the CA certificate file.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CACERTFILE = 0x6002,
        /// <summary>
        /// Sets/gets  the path of the directory containing CA certificates.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CACERTDIR = 0x6003,
        /// <summary>
        /// Sets/gets  the  full-path of the certificate file.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CERTFILE = 0x6004,
        /// <summary>
        /// Sets/gets  the  full-path  of the certificate key file.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_KEYFILE = 0x6005,
        /// <summary>
        /// Sets/gets the peer certificate checking strategy
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006,
        /// <summary>
        /// Sets/gets the minimum protocol version.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007,
        /// <summary>
        /// Sets/gets the allowed cipher suite.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008,
        /// <summary>
        /// Sets/gets the random file when /dev/random and /dev/urandom are not available 
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009,
        /// <summary>
        /// Gets the  TLS  session  context  associated  with  this  handle
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_SSL_CTX = 0x600a,    // OpenSSL SSL
        /// <summary>
        /// Sets/gets the CRL evaluation strategy
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CRLCHECK = 0x600b,
        /// <summary>
        /// Sets/gets the connection callback handle.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CONNECT_CB = 0x600c,
        /// <summary>
        /// Sets/gets the connection callback argument.
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d,
        /// <summary>
        /// Gets/sets the full-path of the file containing the parameters for Diffie-Hellman ephemeral key exchange 
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_DHFILE = 0x600e,
        /// <summary>
        /// Instructs the library to create a new TLS library context 
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_NEWCTX = 0x600f,
        /// <summary>
        /// Sets/gets the full-path of the CRL file
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_CRLFILE = 0x6010,   // GNUtls only 

        /// <summary>
        /// retrieve the TLS implementation name
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_TLS_PACKAGE = 0x6011,


        /* OpenLDAP SASL options */
        LDAP_OPT_X_SASL_MECH = 0x6100,
        LDAP_OPT_X_SASL_REALM = 0x6101,
        LDAP_OPT_X_SASL_AUTHCID = 0x6102,
        LDAP_OPT_X_SASL_AUTHZID = 0x6103,
        LDAP_OPT_X_SASL_SSF = 0x6104,/* read-only */
        LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105,/* write-only */
        LDAP_OPT_X_SASL_SECPROPS = 0x6106,/* write-only */
        LDAP_OPT_X_SASL_SSF_MIN = 0x6107,
        LDAP_OPT_X_SASL_SSF_MAX = 0x6108,
        LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109,
        LDAP_OPT_X_SASL_MECHLIST = 0x610a,/* read-only */
        LDAP_OPT_X_SASL_NOCANON = 0x610b,
        LDAP_OPT_X_SASL_USERNAME = 0x610c,/* read-only */
        LDAP_OPT_X_SASL_GSS_CREDS = 0x610d,

        /* OpenLDAP GSSAPI options */
        LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT = 0x6200,
        LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL = 0x6201,

        /*
         * OpenLDAP per connection tcp-keepalive settings
         * (Linux only, ignored where unsupported)
         */
        /// <summary>
        /// Sets/gets the number of seconds a connection needs to remain idle before TCP starts sending keepalive probes
        /// </summary>
        /// <remarks>OpenLDAP</remarks>
        LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300,
        /// <summary>
        /// Sets/gets the maximum number of keepalive probes TCP should send before dropping the connection
        /// </summary>
        LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301,
        /// <summary>
        /// Sets/gets the interval in seconds between individual keepalive probes
        /// </summary>
        LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302,


        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_HOST_REACHABLE = 0x3E,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_PING_KEEP_ALIVE = 0x36,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_PING_WAIT_TIME = 0x37,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_PING_LIMIT = 0x38,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_DNSDOMAIN_NAME = 0x3B,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_GETDSNAME_FLAGS = 0x3D,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_PROMPT_CREDENTIALS = 0x3F,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_TCP_KEEPALIVE = 0x40,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_FAST_CONCURRENT_BIND = 0x41,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_SEND_TIMEOUT = 0x42,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_REFERRAL_CALLBACK = 0x70,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_CLIENT_CERTIFICATE = 0x80,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_SERVER_CERTIFICATE = 0x81,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_AUTO_RECONNECT = 0x91,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_SSL_INFO = 0x93,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_AREC_EXCLUSIVE = 0x98,
        [Obsolete("MS SPECIFIC")]
        LDAP_OPT_ROOTDSE_CACHE = 0x9a
    }

    internal enum ResultAll
    {
        LDAP_MSG_ALL = 1,
        LDAP_MSG_RECEIVED = 2,
        LDAP_MSG_POLLINGALL = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class LDAP_TIMEVAL
    {
        public int tv_sec;
        public int tv_usec;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class berval
    {
        public int bv_len = 0;
        public IntPtr bv_val = IntPtr.Zero;

        public berval() { }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class SafeBerval
    {
        public int bv_len = 0;
        public IntPtr bv_val = IntPtr.Zero;

        ~SafeBerval()
        {
            if (bv_val != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(bv_val);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class LdapControl
    {
        public IntPtr ldctl_oid = IntPtr.Zero;
        public berval ldctl_value = null;
        public bool ldctl_iscritical = false;

        public LdapControl() { }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LdapReferralCallback
    {
        public int sizeofcallback;
        public QUERYFORCONNECTIONInternal query;
        public NOTIFYOFNEWCONNECTIONInternal notify;
        public DEREFERENCECONNECTIONInternal dereference;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPTOAPI_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecPkgContext_IssuerListInfoEx
    {
        public IntPtr aIssuers;
        public int cIssuers;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class LdapMod
    {
        public int type = 0;
        public IntPtr attribute = IntPtr.Zero;
        public IntPtr values = IntPtr.Zero;

        ~LdapMod()
        {
            if (attribute != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attribute);
            }

            if (values != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(values);
            }
        }
    }

 [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool LDAP_TLS_CONNECT_CB(IntPtr connectionHandle, IntPtr ssl, IntPtr ctx, IntPtr arg);

    internal class Wldap32
    {
        private const string Wldap32dll = "ldap";

        public const int SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2;
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;
        public const string MICROSOFT_KERBEROS_NAME_W = "Kerberos";


        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_TLS_CONNECT_CB([In] ConnectionHandle ldapHandle, [In] LdapOption option, LDAP_TLS_CONNECT_CB outValue);



        [DllImport(Wldap32dll, EntryPoint = "ldap_bind_s")]
        public static extern int ldap_bind_s([In]ConnectionHandle ldapHandle, string dn, SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_init(string hostName, int portNumber);

        //[DllImport(Wldap32dll, ExactSpelling = true, EntryPoint = "ldap_connect", CharSet = CharSet.Unicode)]
        //public static extern int ldap_connect([In] ConnectionHandle ldapHandle);//, LDAP_TIMEVAL timeout);
        public static int ldap_connect([In] ConnectionHandle ldapHandle, LDAP_TIMEVAL timeout)
        {
            //NOTE: stub
            return (int)ResultCode.Success;
        }


        [DllImport(Wldap32dll, EntryPoint = "ldap_unbind")]
        public static extern int ldap_unbind([In] IntPtr ldapHandle);

        [DllImport(Wldap32dll, EntryPoint = "ldap_get_option")]
        public static extern int ldap_get_option_int([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref int outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_int([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref int inValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_get_option")]
        public static extern int ldap_get_option_ptr([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref IntPtr outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_ptr([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref IntPtr inValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_get_option")]
        public static extern int ldap_get_option_sechandle([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref SecurityHandle outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_get_option")]
        public static extern int ldap_get_option_secInfo([In] ConnectionHandle ldapHandle, [In] LdapOption option, [In, Out] SecurityPackageContextConnectionInformation outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_referral([In] ConnectionHandle ldapHandle, [In] LdapOption option, ref LdapReferralCallback outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_clientcert([In] ConnectionHandle ldapHandle, [In] LdapOption option, QUERYCLIENTCERT outValue);

        [DllImport(Wldap32dll, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_servercert([In] ConnectionHandle ldapHandle, [In] LdapOption option, VERIFYSERVERCERT outValue);

        [DllImport(Wldap32dll, EntryPoint = "LdapGetLastError")]
        public static extern int LdapGetLastError();

        [DllImport(Wldap32dll, EntryPoint = "cldap_open", SetLastError = true)]
        public static extern IntPtr cldap_open(string hostName, int portNumber);

        [DllImport(Wldap32dll)]
        public static extern int ldap_simple_bind_s([In] ConnectionHandle ldapHandle, string distinguishedName, string password);

        [DllImport(Wldap32dll, EntryPoint = "ldap_delete_ext")]
        public static extern int ldap_delete_ext([In] ConnectionHandle ldapHandle, string dn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_result", SetLastError = true)]
        public static extern int ldap_result([In] ConnectionHandle ldapHandle, int messageId, int all, LDAP_TIMEVAL timeout, ref IntPtr result);

        [DllImport(Wldap32dll, EntryPoint = "ldap_parse_result")]
        public static extern int ldap_parse_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref int serverError, ref IntPtr dn, ref IntPtr message, ref IntPtr referral, ref IntPtr control, byte freeIt);

        //[DllImport(Wldap32dll, EntryPoint = "ldap_parse_result")]
        //public static extern int ldap_parse_result_referral([In] ConnectionHandle ldapHandle, [In] IntPtr result, IntPtr serverError, IntPtr dn, IntPtr message, ref IntPtr referral, IntPtr control, byte freeIt);

        [DllImport(Wldap32dll, EntryPoint = "ldap_memfree")]
        public static extern void ldap_memfree([In] IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ldap_value_free")]
        public static extern int ldap_value_free([In] IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ldap_controls_free")]
        public static extern int ldap_controls_free([In] IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ldap_abandon")]
        public static extern int ldap_abandon([In] ConnectionHandle ldapHandle, [In] int messagId);

        [DllImport(Wldap32dll, EntryPoint = "ldap_start_tls_s")]
        public static extern int ldap_start_tls([In] ConnectionHandle ldapHandle, IntPtr ServerControls, IntPtr ClientControls);

        [DllImport(Wldap32dll, EntryPoint = "ldap_stop_tls_s")]
        public static extern byte ldap_stop_tls(ConnectionHandle ldapHandle);

        [DllImport(Wldap32dll, EntryPoint = "ldap_tls_inplace")]
        public static extern int ldap_tls_inplace([In] ConnectionHandle ldapHandle);
        [DllImport(Wldap32dll, EntryPoint = "ldap_install_tls")]
        public static extern int ldap_install_tls([In] ConnectionHandle ldapHandle);



        [DllImport(Wldap32dll, EntryPoint = "ldap_rename")]
        public static extern int ldap_rename([In] ConnectionHandle ldapHandle, string dn, string newRdn, string newParentDn, int deleteOldRdn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_compare_ext")]
        public static extern int ldap_compare([In] ConnectionHandle ldapHandle, string dn, string attributeName, string strValue, berval binaryValue, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_add_ext")]
        public static extern int ldap_add([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_modify_ext")]
        public static extern int ldap_modify([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_extended_operation")]
        public static extern int ldap_extended_operation([In] ConnectionHandle ldapHandle, string oid, berval data, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport(Wldap32dll, EntryPoint = "ldap_perror")]
        public static extern unsafe void ldap_perror(/*fn ptr->delegate: DBGPRINT*/ void* DebugPrintRoutine);

        [DllImport(Wldap32dll, EntryPoint = "ldap_parse_extended_result")]
        public static extern int ldap_parse_extended_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt);

        [DllImport(Wldap32dll, EntryPoint = "ldap_msgfree")]
        public static extern int ldap_msgfree([In] IntPtr result);

        [DllImport(Wldap32dll, EntryPoint = "ldap_search_ext")]
        public static extern int ldap_search([In] ConnectionHandle ldapHandle, string dn, int scope, string filter, IntPtr attributes, bool attributeOnly, IntPtr servercontrol, IntPtr clientcontrol, int timelimit, int sizelimit, ref int messageNumber);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_first_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_next_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(Wldap32dll, EntryPoint = "ldap_first_reference")]
        public static extern IntPtr ldap_first_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(Wldap32dll, EntryPoint = "ldap_next_reference")]
        public static extern IntPtr ldap_next_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_get_dn([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_first_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr address);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ldap_next_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, [In, Out] IntPtr address);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ber_free([In] IntPtr berelement, int option);

        [DllImport(Wldap32dll, EntryPoint = "ldap_get_values_len")]
        public static extern IntPtr ldap_get_values_len([In] ConnectionHandle ldapHandle, [In] IntPtr result, string name);

        [DllImport(Wldap32dll, EntryPoint = "ldap_value_free_len")]
        public static extern IntPtr ldap_value_free_len([In] IntPtr berelement);

        [DllImport(Wldap32dll, EntryPoint = "ldap_parse_reference")]
        public static extern int ldap_parse_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr referrals);



        [DllImport(Wldap32dll, EntryPoint = "ber_skip_tag")]
        public static extern int ber_skip_tag(BerSafeHandle berElement, ref int lenPtr);


        [DllImport(Wldap32dll, EntryPoint = "ber_alloc")]
        public static extern IntPtr ber_alloc(int option);

        [DllImport(Wldap32dll, EntryPoint = "ber_printf")]
        public static extern int ber_printf_emptyarg(BerSafeHandle berElement, string format);

        [DllImport(Wldap32dll, EntryPoint = "ber_printf")]
        public static extern int ber_printf_int(BerSafeHandle berElement, string format, int value);

        [DllImport(Wldap32dll, EntryPoint = "ber_printf")]
        public static extern int ber_printf_bytearray(BerSafeHandle berElement, string format, HGlobalMemHandle value, int length);

        [DllImport(Wldap32dll, EntryPoint = "ber_printf")]
        public static extern int ber_printf_berarray(BerSafeHandle berElement, string format, IntPtr value);

        [DllImport(Wldap32dll)]
        public static extern int ber_flatten(BerSafeHandle berElement, ref IntPtr value);

        [DllImport(Wldap32dll)]
        public static extern IntPtr ber_init(berval value);

        [DllImport(Wldap32dll, EntryPoint = "ber_scanf")]
        public static extern int ber_scanf(BerSafeHandle berElement, string format);

        [DllImport(Wldap32dll, EntryPoint = "ber_scanf")]
        public static extern int ber_scanf_int(BerSafeHandle berElement, string format, ref int value);

        [DllImport(Wldap32dll, EntryPoint = "ber_scanf")]
        public static extern int ber_scanf_ptr(BerSafeHandle berElement, string format, ref IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ber_scanf")]
        public static extern int ber_scanf_bitstring(BerSafeHandle berElement, string format, ref IntPtr value, ref int length);

        [DllImport(Wldap32dll, EntryPoint = "ber_bvfree")]
        public static extern int ber_bvfree(IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ber_bvecfree")]
        public static extern int ber_bvecfree(IntPtr value);

        [DllImport(Wldap32dll, EntryPoint = "ldap_create_sort_control")]
        public static extern int ldap_create_sort_control(ConnectionHandle handle, IntPtr keys, byte critical, ref IntPtr control);

        [DllImport(Wldap32dll, EntryPoint = "ldap_control_free")]
        public static extern int ldap_control_free(IntPtr control);

        //TODO: yeah, won't work well on *ux
        [DllImport("Crypt32.dll", EntryPoint = "CertFreeCRLContext")]
        public static extern int CertFreeCRLContext(IntPtr certContext);

        [DllImport(Wldap32dll, EntryPoint = "ldap_result2error")]
        public static extern int ldap_result2error([In] ConnectionHandle ldapHandle, [In] IntPtr result, int freeIt);

        [DllImport(Wldap32dll, EntryPoint = "ldap_err2string")]
        public static extern IntPtr ldap_err2string(int err);


    }
}

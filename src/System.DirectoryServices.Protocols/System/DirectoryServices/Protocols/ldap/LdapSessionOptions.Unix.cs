using System.Collections;
using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapSessionOptions
    {

        //typedef int (LDAP_TLS_CONNECT_CB) LDAP_P (( struct ldap *ld, void *ssl, void *ctx, void *arg ));

        public static LDAP_TLS_CONNECT_CB _routine = new LDAP_TLS_CONNECT_CB(ConnectTls);

        public static bool ConnectTls([In] IntPtr ldapHandle, IntPtr ssl, IntPtr ctx, IntPtr arg)
        {
            //callback for ldap_set_option/ldap_set_option_TLS_CONNECT_CB, currently unused
            return true;
        }

        public unsafe void StartTransportLayerSecurity(DirectoryControlCollection controls)
        {
            IntPtr serverControlArray = IntPtr.Zero;
            LdapControl[] managedServerControls = null;
            IntPtr clientControlArray = IntPtr.Zero;
            LdapControl[] managedClientControls = null;
            //IntPtr ldapResult = IntPtr.Zero;
            //IntPtr referral = IntPtr.Zero;

            //int serverError = 0;
            //Uri[] responseReferral = null;

            if (_connection._disposed)
            {
                throw new ObjectDisposedException(GetType().Name);

            }

            try
            {
                IntPtr tempPtr = IntPtr.Zero;

                // build server control
                managedServerControls = _connection.BuildControlArray(controls, true);
                int structSize = Marshal.SizeOf(typeof(LdapControl));
                if (managedServerControls != null)
                {
                    serverControlArray = Utility.AllocHGlobalIntPtrArray(managedServerControls.Length + 1);
                    for (int i = 0; i < managedServerControls.Length; i++)
                    {
                        IntPtr controlPtr = Marshal.AllocHGlobal(structSize);
                        Marshal.StructureToPtr(managedServerControls[i], controlPtr, false);
                        tempPtr = (IntPtr)((long)serverControlArray + IntPtr.Size * i);
                        Marshal.WriteIntPtr(tempPtr, controlPtr);
                    }

                    tempPtr = (IntPtr)((long)serverControlArray + IntPtr.Size * managedServerControls.Length);
                    Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
                }

                // Build client control.
                managedClientControls = _connection.BuildControlArray(controls, false);
                if (managedClientControls != null)
                {
                    clientControlArray = Utility.AllocHGlobalIntPtrArray(managedClientControls.Length + 1);
                    for (int i = 0; i < managedClientControls.Length; i++)
                    {
                        IntPtr controlPtr = Marshal.AllocHGlobal(structSize);
                        Marshal.StructureToPtr(managedClientControls[i], controlPtr, false);
                        tempPtr = (IntPtr)((long)clientControlArray + IntPtr.Size * i);
                        Marshal.WriteIntPtr(tempPtr, controlPtr);
                    }

                    tempPtr = (IntPtr)((long)clientControlArray + IntPtr.Size * managedClientControls.Length);
                    Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
                }

                // requested certificate. 
                //  - no certificate = no problem. 
                //  - bad certificate = no problem
                var require_cert = (int)LDAP_OPT_X_TLS.ALLOW;
                Wldap32.ldap_set_option_int(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_REQUIRE_CERT, ref require_cert);
                //new tls client context
                var off = 0;
                Wldap32.ldap_set_option_int(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_NEWCTX, ref off);

                //var test tls connect callback
                var result = Wldap32.ldap_set_option_TLS_CONNECT_CB(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CONNECT_CB, _routine);



                int error = Wldap32.ldap_start_tls(_connection._ldapHandle, serverControlArray, clientControlArray);


                //IntPtr ret1 = IntPtr.Zero;
                //Wldap32.ldap_get_option_ptr(_connection._ldapHandle, LdapOption.LDAP_OPT_X_TLS_CACERTFILE, ref ret1);
                //Console.WriteLine(Encoding.PtrToStringUTF8(ret1));

                //typedef int (LDAP_TLS_CONNECT_CB) LDAP_P (( struct ldap *ld, void *ssl, void *ctx, void *arg ));


                //TODO: check referrals equivalent with openldap 
                /*                if (ldapResult != IntPtr.Zero)
                                {
                                    // Parse the referral.                          
                                    int resultError = Wldap32.ldap_parse_result_referral(_connection._ldapHandle, ldapResult, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref referral, IntPtr.Zero, 0  );
                                    if (resultError == 0 && referral != IntPtr.Zero)
                                    {
                                        char** referralPtr = (char**)referral;
                                        char* singleReferral = referralPtr[0];
                                        int i = 0;
                                        ArrayList referralList = new ArrayList();
                                        while (singleReferral != null)
                                        {
                                            string s = Encoding.PtrToString((IntPtr)singleReferral);
                                            referralList.Add(s);

                                            i++;
                                            singleReferral = referralPtr[i];
                                        }

                                        // Free heap memory.
                                        if (referral != IntPtr.Zero)
                                        {
                                            Wldap32.ldap_value_free(referral);
                                            referral = IntPtr.Zero;
                                        }

                                        if (referralList.Count > 0)
                                        {
                                            responseReferral = new Uri[referralList.Count];
                                            for (int j = 0; j < referralList.Count; j++)
                                            {
                                                responseReferral[j] = new Uri((string)referralList[j]);
                                            }
                                        }
                                    }
                                }
                */
                if (error != (int)ResultCode.Success)
                {
                    string errorText = Encoding.PtrToString(Wldap32.ldap_err2string(error));

                    string errorAdditional = GetStringValueHelper(LdapOption.LDAP_OPT_DIAGNOSTIC_MESSAGE, true);

                    if (error > 0)
                    {
                        //positive, indicating an LDAP resultCode other than 'success' 

                        ExtendedResponse response = new ExtendedResponse(null, null, (ResultCode)error, errorText, null);
                        response.ResponseName = "1.3.6.1.4.1.1466.20037";
                        throw new TlsOperationException(response);
                    }
                    else if (error < 0)
                    {
                        //negative, indicating an API error code; 
                        error = Math.Abs(error) + 80; //convert negative number for exception for compatibilty with original S.DS.P
                        throw new LdapException(error, errorText, errorAdditional);
                    }
                }
            }
            finally
            {
                if (serverControlArray != IntPtr.Zero)
                {
                    // Release the memory from the heap.
                    for (int i = 0; i < managedServerControls.Length; i++)
                    {
                        IntPtr tempPtr = Marshal.ReadIntPtr(serverControlArray, IntPtr.Size * i);
                        if (tempPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(tempPtr);
                        }
                    }
                    Marshal.FreeHGlobal(serverControlArray);
                }

                if (managedServerControls != null)
                {
                    for (int i = 0; i < managedServerControls.Length; i++)
                    {
                        if (managedServerControls[i].ldctl_oid != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(managedServerControls[i].ldctl_oid);
                        }

                        if (managedServerControls[i].ldctl_value != null)
                        {
                            if (managedServerControls[i].ldctl_value.bv_val != IntPtr.Zero)
                            {
                                Marshal.FreeHGlobal(managedServerControls[i].ldctl_value.bv_val);
                            }
                        }
                    }
                }

                if (clientControlArray != IntPtr.Zero)
                {
                    // Release the memor from the heap.
                    for (int i = 0; i < managedClientControls.Length; i++)
                    {
                        IntPtr tempPtr = Marshal.ReadIntPtr(clientControlArray, IntPtr.Size * i);
                        if (tempPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(tempPtr);
                        }
                    }

                    Marshal.FreeHGlobal(clientControlArray);
                }

                if (managedClientControls != null)
                {
                    for (int i = 0; i < managedClientControls.Length; i++)
                    {
                        if (managedClientControls[i].ldctl_oid != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(managedClientControls[i].ldctl_oid);
                        }

                        if (managedClientControls[i].ldctl_value != null)
                        {
                            if (managedClientControls[i].ldctl_value.bv_val != IntPtr.Zero)
                                Marshal.FreeHGlobal(managedClientControls[i].ldctl_value.bv_val);
                        }
                    }
                }

                /*if (referral != IntPtr.Zero)
                {
                    Wldap32.ldap_value_free(referral);
                }*/
            }
        }

        //NOTE: needs testing/validation 
        public bool TcpKeepAlive
        {
            get
            {
                int outValue = GetIntValueHelper(LdapOption.LDAP_OPT_X_KEEPALIVE_INTERVAL);
                return outValue > 0;
            }
            set
            {
                SetIntValueHelper(LdapOption.LDAP_OPT_X_KEEPALIVE_IDLE, value ? 60 : 0);
                SetIntValueHelper(LdapOption.LDAP_OPT_X_KEEPALIVE_PROBES, value ? 3 : 0);
                SetIntValueHelper(LdapOption.LDAP_OPT_X_KEEPALIVE_INTERVAL, value ? 30 : 0);
            }
        }

        private string _domainName = null;
        /// <summary>Not implemented on *nix, doesn't do anything</summary>
        public string DomainName
        {
            get
            {
                if (_connection._disposed) { throw new ObjectDisposedException(GetType().Name); }
                return _domainName;
            }
            set
            {
                if (_connection._disposed) { throw new ObjectDisposedException(GetType().Name); }
                _domainName = value;
            }
        }

        /// <summary>Not implemented on *nix, doesn't do anything</summary>
        internal bool FQDN { set { } }

        private bool _rootDseCache = true;
        /// <summary>Not implemented on *nix, doesn't do anything</summary>
        public bool RootDseCache
        {
            get
            {
                if (_connection._disposed) { throw new ObjectDisposedException(GetType().Name); };
                return _rootDseCache;
            }
            set
            {
                if (_connection._disposed) { throw new ObjectDisposedException(GetType().Name); }
                _rootDseCache = value;
            }
        }

        /// <summary>Not implemented on *nix, doesn't do anything</summary>
        public bool AutoReconnect { get; set; } = true;

        /// <summary>Not implemented on *nix, doesn't do anything </summary>
        /// <returns>true</returns>
        public bool HostReachable
        {
            get => true;
        }

        /// <summary>Not implemented on *nix, doesn't do anything </summary>
        public LocatorFlags LocatorFlag { get; set; } = LocatorFlags.None;

        /// <summary>Not implemented on *nix, doesn't do anything </summary>
        public TimeSpan PingKeepAliveTimeout { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>Not implemented on *nix, doesn't do anything </summary>
        public int PingLimit { get; set; } = 4;

        /// <summary>Not implemented on *nix, doesn't do anything </summary>
        public TimeSpan PingWaitTimeout { get; set; } = TimeSpan.FromSeconds(2);


        public string SaslMethod
        {
            get => GetStringValueHelper(LdapOption.LDAP_OPT_X_SASL_MECH, true);
            set => SetStringValueHelper(LdapOption.LDAP_OPT_X_SASL_MECH, value);
        }

    }
}
using System.Collections;
using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapSessionOptions
    {
        public unsafe void StartTransportLayerSecurity(DirectoryControlCollection controls)
        {
            IntPtr serverControlArray = IntPtr.Zero;
            LdapControl[] managedServerControls = null;
            IntPtr clientControlArray = IntPtr.Zero;
            LdapControl[] managedClientControls = null;
            IntPtr ldapResult = IntPtr.Zero;
            IntPtr referral = IntPtr.Zero;

            int serverError = 0;
            Uri[] responseReferral = null;

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

                int error = Wldap32.ldap_start_tls(_connection._ldapHandle, ref serverError, ref ldapResult, serverControlArray, clientControlArray);
                if (ldapResult != IntPtr.Zero)
                {
                    // Parse the referral.                          
                    int resultError = Wldap32.ldap_parse_result_referral(_connection._ldapHandle, ldapResult, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref referral, IntPtr.Zero, 0 /* not free it */);
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

                if (error != (int)ResultCode.Success)
                {
                    if (Utility.IsResultCode((ResultCode)error))
                    {
                        // If the server failed request for whatever reason, the ldap_start_tls returns LDAP_OTHER
                        // and the ServerReturnValue will contain the error code from the server.   
                        if (error == (int)ResultCode.Other)
                        {
                            error = serverError;
                        }

                        string errorMessage = OperationErrorMappings.MapResultCode(error);
                        ExtendedResponse response = new ExtendedResponse(null, null, (ResultCode)error, errorMessage, responseReferral);
                        response.ResponseName = "1.3.6.1.4.1.1466.20037";
                        throw new TlsOperationException(response);
                    }
                    else if (Utility.IsLdapError((LdapError)error))
                    {
                        string errorMessage = LdapErrorMappings.MapResultCode(error);
                        throw new LdapException(error, errorMessage);
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

                if (referral != IntPtr.Zero)
                {
                    Wldap32.ldap_value_free(referral);
                }
            }
        }
    }

    public bool TcpKeepAlive
        {
            get
            {
                int outValue = GetIntValueHelper(LdapOption.LDAP_OPT_TCP_KEEPALIVE);
                return outValue == 1;
            }
            set
            {
                int temp = value ? 1 : 0;
                SetIntValueHelper(LdapOption.LDAP_OPT_TCP_KEEPALIVE, temp);
            }
        }

            public string DomainName
        {
            get => GetStringValueHelper(LdapOption.LDAP_OPT_DNSDOMAIN_NAME, true);
            set => SetStringValueHelper(LdapOption.LDAP_OPT_DNSDOMAIN_NAME, value);
        }

public bool RootDseCache
        {
            get
            {
                int outValue = GetIntValueHelper(LdapOption.LDAP_OPT_ROOTDSE_CACHE);
                return outValue == 1;
            }
            set
            {
                int temp = value ? 1 : 0;
                SetIntValueHelper(LdapOption.LDAP_OPT_ROOTDSE_CACHE, temp);
            }
        }

public bool AutoReconnect
        {
            get
            {
                int outValue = GetIntValueHelper(LdapOption.LDAP_OPT_AUTO_RECONNECT);
                return outValue == 1;
            }
            set
            {
                int temp = value ? 1 : 0;
                SetIntValueHelper(LdapOption.LDAP_OPT_AUTO_RECONNECT, temp);
            }
        }

                public string SaslMethod
        {
            get => GetStringValueHelper(LdapOption.LDAP_OPT_SASL_METHOD, true);
            set => SetStringValueHelper(LdapOption.LDAP_OPT_SASL_METHOD, value);
        }

        public bool HostReachable
        {
            get
            {
                int outValue = GetIntValueHelper(LdapOption.LDAP_OPT_HOST_REACHABLE);
                return outValue == 1;
            }
        }

        public LocatorFlags LocatorFlag
        {
            get
            {
                int result = GetIntValueHelper(LdapOption.LDAP_OPT_GETDSNAME_FLAGS);
                return (LocatorFlags)result;
            }
            set
            {
                // We don't do validation to the dirsync flag here as underneath API does not check for it and we don't want to put
                // unnecessary limitation on it.
                SetIntValueHelper(LdapOption.LDAP_OPT_GETDSNAME_FLAGS, (int)value);
            }
        }

        public TimeSpan PingKeepAliveTimeout
        {
            get
            {
                int result = GetIntValueHelper(LdapOption.LDAP_OPT_PING_KEEP_ALIVE);
                return new TimeSpan(result * TimeSpan.TicksPerSecond);
            }
            set
            {
                if (value < TimeSpan.Zero)
                {
                    throw new ArgumentException(SR.NoNegativeTimeLimit, nameof(value));
                }

                // Prevent integer overflow.
                if (value.TotalSeconds > int.MaxValue)
                {
                    throw new ArgumentException(SR.TimespanExceedMax, nameof(value));
                }

                int seconds = (int)(value.Ticks / TimeSpan.TicksPerSecond);
                SetIntValueHelper(LdapOption.LDAP_OPT_PING_KEEP_ALIVE, seconds);
            }
        }

        public int PingLimit
        {
            get => GetIntValueHelper(LdapOption.LDAP_OPT_PING_LIMIT);
            set
            {
                if (value < 0)
                {
                    throw new ArgumentException(SR.ValidValue, nameof(value));
                }

                SetIntValueHelper(LdapOption.LDAP_OPT_PING_LIMIT, value);
            }
        }

        public TimeSpan PingWaitTimeout
        {
            get
            {
                int result = GetIntValueHelper(LdapOption.LDAP_OPT_PING_WAIT_TIME);
                return new TimeSpan(result * TimeSpan.TicksPerMillisecond);
            }
            set
            {
                if (value < TimeSpan.Zero)
                {
                    throw new ArgumentException(SR.NoNegativeTimeLimit, nameof(value));
                }

                // Prevent integer overflow.
                if (value.TotalMilliseconds > int.MaxValue)
                {
                    throw new ArgumentException(SR.TimespanExceedMax, nameof(value));
                }

                int milliseconds = (int)(value.Ticks / TimeSpan.TicksPerMillisecond);
                SetIntValueHelper(LdapOption.LDAP_OPT_PING_WAIT_TIME, milliseconds);
            }
        }


}
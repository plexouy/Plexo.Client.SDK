using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Goova.ElSwitch.Client.SDK.Properties;
using Goova.ElSwitch.Exceptions;

namespace Goova.ElSwitch.Client.SDK
{
    public class CertificateHelper
    {
        private Dictionary<string, RSAHelper> SignKeys { get; } = new Dictionary<string, RSAHelper>();
        internal Dictionary<string, Dictionary<string, RSAHelper>> VerifyKeys = new Dictionary<string, Dictionary<string, RSAHelper>>();
        internal SemaphoreSlim ServerCertSemaphore = new SemaphoreSlim(1);

        public T Sign<T, S>(string clientname, S obj) where T : SignedObject<S>, new()
        {
            if (SignKeys.ContainsKey(clientname))
                return SignKeys[clientname].Sign<T,S>(obj);
            throw new CertificateException("Unable to find certificate for client '" + clientname + "'");
        }

        public S Verify<T, S>(string clientname, T obj) where T : SignedObject<S>
        {
            if (!VerifyKeys.ContainsKey(clientname))
                throw new CertificateException("Unable to find certificate for client '" + clientname + "'");
            if (!VerifyKeys[clientname].ContainsKey(obj.Object.Fingerprint))
                throw new FingerPrintException("Unable to find certificate for fingerprint '" + obj.Object.Fingerprint + "' in client '" + clientname + "'");
            return VerifyKeys[clientname][obj.Object.Fingerprint].Verify<T, S>(obj);

        }



        public CertificateHelper()
        {
            foreach (string s in Settings.Default.Clients)
            {
                string[] spl = s.Split(',');
                if (spl.Length>3 || spl.Length<2)
                    throw new ConfigurationException("Invalid Client line in configuration");
                VerifyKeys.Add(spl[0].Trim(),new Dictionary<string, RSAHelper>());
                X509Certificate2 priv = SearchCertificate(spl[1].Trim(), spl.Length>2 ? spl[2].Trim() : null);
                if (priv == null)
                    throw new CertificateException("Unable to find Certificate '" + spl[1].Trim() + "' in the X509 Store");
                SignKeys.Add(spl[0].Trim(),new RSAHelper(priv,true));
            }
        }

        private X509Certificate2 SearchCertificate(string certname, string password=null)
        {
            StoreName[] stores = {StoreName.My, StoreName.TrustedPublisher, StoreName.TrustedPeople, StoreName.Root, StoreName.CertificateAuthority, StoreName.AuthRoot, StoreName.AddressBook};
            StoreLocation[] locations = { StoreLocation.CurrentUser, StoreLocation.LocalMachine};
            foreach (StoreLocation location in locations)
            {
                foreach (StoreName s in stores)
                {
                    X509Store store = new X509Store(s, location);
                    store.Open(OpenFlags.ReadOnly);
                    foreach (X509Certificate2 m in store.Certificates)
                    {
                        if (m.Subject.Equals("CN="+certname, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return m;
/*                            if (!string.IsNullOrEmpty(password))
                                return new X509Certificate2(m.RawData, password);
                            return m;*/
                        }
                    }
                    store.Close();
                }
            }
            return null;
        }
    }
}
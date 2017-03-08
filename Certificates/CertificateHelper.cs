using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Goova.Plexo.Client.SDK.Properties;
using Goova.Plexo.Exceptions;
using Goova.Plexo.Helpers;

namespace Goova.Plexo.Client.SDK.Certificates
{
    public class CertificateHelper
    {
        private Dictionary<string, SignatureHelper> SignKeys { get; } = new Dictionary<string, SignatureHelper>();
        internal Dictionary<string, Dictionary<string, SignatureHelper>> VerifyKeys = new Dictionary<string, Dictionary<string, SignatureHelper>>();
        internal SemaphoreSlim ServerCertSemaphore = new SemaphoreSlim(1);

        public T Sign<T, TS>(string clientname, TS obj) where T : SignedObject<TS>, new()
        {
            if (SignKeys.ContainsKey(clientname))
                return SignKeys[clientname].Sign<T,TS>(obj);
            throw new CertificateException("Unable to find certificate for client '" + clientname + "'");
        }

        public TS Verify<T, TS>(string clientname, T obj) where T : SignedObject<TS>
        {
            if (!VerifyKeys.ContainsKey(clientname))
                throw new CertificateException("Unable to find certificate for client '" + clientname + "'");
            if (!VerifyKeys[clientname].ContainsKey(obj.Object.Fingerprint))
                throw new FingerprintException("Unable to find certificate for fingerprint '" + obj.Object.Fingerprint + "' in client '" + clientname + "'");
            return VerifyKeys[clientname][obj.Object.Fingerprint].Verify<T, TS>(obj);

        }

        public CertificateHelper()
        {
            foreach (string s in Settings.Default.Clients)
            {
                string[] spl = s.Split(',');
                if (spl.Length!=2)
                    throw new ConfigurationException("Invalid Client line in configuration");
                VerifyKeys.Add(spl[0].Trim(),new Dictionary<string, SignatureHelper>());
                X509Certificate2 priv = SearchCertificate(spl[1].Trim());
                if (priv == null)
                    throw new CertificateException("Unable to find Certificate '" + spl[1].Trim() + "' in the X509 Store");
                SignKeys.Add(spl[0].Trim(),new SignatureHelper(priv,true));
            }
        }

        private X509Certificate2 SearchCertificate(string certname)
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
                        if (m.Subject.Equals("CN=" + certname, StringComparison.InvariantCultureIgnoreCase))
                        {
                            store.Close();
                            return m;
                        }
                    }
                    store.Close();
                }
            }
            return null;
        }
    }
}
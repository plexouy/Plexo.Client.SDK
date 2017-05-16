using Plexo.Client.SDK.Certificates;

namespace Plexo.Client.SDK.Certificates
{
    public class CertificateHelperFactory
    {
        private static CertificateHelper _instance;
        public static CertificateHelper Instance => _instance ?? (_instance = new CertificateHelper());
    }
}

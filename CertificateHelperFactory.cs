namespace Goova.ElSwitch.Client.SDK
{
    public class CertificateHelperFactory
    {
        private static CertificateHelper _instance;
        public static CertificateHelper Instance => _instance ?? (_instance = new CertificateHelper());
    }
}

using System.Collections.Generic;

namespace Plexo.Client.SDK
{
    public class PaymentGatewayClientFactory
    {
        private static readonly Dictionary<string,PaymentGatewayClient> Instances=new Dictionary<string, PaymentGatewayClient>();
        private static readonly Dictionary<string, PaymentGatewayClient> InstancesIssuer = new Dictionary<string, PaymentGatewayClient>();

        public static PaymentGatewayClient GetClient(string clientname)
        {
            lock (Instances)
            {
                if (!Instances.ContainsKey(clientname))
                    Instances[clientname] = PaymentGatewayClient.CreateClient(Properties.Settings.Default.PaymentServerUrl, clientname);
                return Instances[clientname];
            }
        }
        public static PaymentGatewayClient GetIssuer(string issuername)
        {
            lock (InstancesIssuer)
            {
                if (!InstancesIssuer.ContainsKey(issuername))
                    InstancesIssuer[issuername] = PaymentGatewayClient.CreateClientForIssuer(Properties.Settings.Default.PaymentServerUrl, issuername);
                return InstancesIssuer[issuername];
            }
        }
    }
}
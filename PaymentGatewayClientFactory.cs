using System.Collections.Generic;

namespace Goova.Plexo.Client.SDK
{
    public class PaymentGatewayClientFactory
    {
        private static readonly Dictionary<string,PaymentGatewayClient> Instances=new Dictionary<string, PaymentGatewayClient>();

        public static PaymentGatewayClient GetClient(string clientname)
        {
            lock (Instances)
            {
                if (!Instances.ContainsKey(clientname))
                    Instances[clientname] = PaymentGatewayClient.Create(ElSwitch.Client.SDK.Properties.Settings.Default.PaymentServerUrl, clientname);
                return Instances[clientname];
            }
        }

    }
}
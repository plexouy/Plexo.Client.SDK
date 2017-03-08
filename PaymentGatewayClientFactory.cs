using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Goova.ElSwitch.Client.SDK
{
    public class PaymentGatewayClientFactory
    {
        private static Dictionary<string,PaymentGatewayClient> _instances=new Dictionary<string, PaymentGatewayClient>();

        public static PaymentGatewayClient GetClient(string clientname)
        {
            lock (_instances)
            {
                if (!_instances.ContainsKey(clientname))
                    _instances[clientname] = PaymentGatewayClient.Create(Properties.Settings.Default.PaymentServerUrl, clientname);
                return _instances[clientname];
            }
        }

    }
}
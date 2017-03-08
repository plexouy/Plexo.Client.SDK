using System;
using System.Linq;
using System.Reflection;
using System.ServiceModel;
using System.Threading.Tasks;
using Goova.ElSwitch.Client.SDK.Logging;

namespace Goova.ElSwitch.Client.SDK
{
    [ServiceBehavior(IncludeExceptionDetailInFaults = true)]
    public class SecureCallback : ISecureCallback
    {
        private static ICallback CallbackImplementation;
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        public async Task<ClientSignedResponse> Instrument(ServerSignedRequest<IntrumentCallback> instrument)
        {
            ServerResponse<IntrumentCallback> sins = null;
            try
            {
                PaymentGatewayClient cl = PaymentGatewayClientFactory.GetClient(instrument.Object.Object.Client);
                if (cl == null)
                    return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "Unable to locate PaymentGatewayClient for client '" + instrument.Object.Object.Client + "'.");
                sins = await cl.UnwrapRequest(instrument);
                if (sins.ResultCode!=ResultCodes.Ok)
                    return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, sins.ErrorMessage);
            }
            catch (Exception e)
            {
                return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "System Error",e.ToString());
            }
            if (CallbackImplementation == null)
                return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "Callback message lost.There is no ICallback implementation");
            ClientResponse cr=await CallbackImplementation.Instrument(sins.Response);
            try
            {
                return CertificateHelperFactory.Instance.Sign<ClientSignedResponse, ClientResponse>(cr.Client, cr);
            }
            catch (Exception e)
            {
                return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "System Error", e.ToString());
            }
        }

        private ClientSignedResponse GenerateError(ResultCodes resultcode, string client, string msg, string logmsg=null)
        {
            Logger.Error(logmsg ?? msg);
            ClientResponse r = new ClientResponse();
            r.Client = client;
            r.ResultCode = resultcode;
            r.ErrorMessage = msg;
            return CertificateHelperFactory.Instance.Sign<ClientSignedResponse, ClientResponse>(r.Client, r);
        }
        static SecureCallback()
        {
            CallbackImplementation = (ICallback)AppDomain.CurrentDomain.GetAssemblies().SelectMany(a => a.GetTypes()).Where(a => a.GetInterfaces().Contains(typeof(ICallback))).Select(a => Activator.CreateInstance(a)).FirstOrDefault();
            if (CallbackImplementation==null)
                Logger.Error("There is no ICallback implementation");
        }
    }



}

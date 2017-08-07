using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceModel;
using System.Threading.Tasks;
using Plexo.Client.SDK.Certificates;
using Plexo.Client.SDK.Logging;
using Plexo.Helpers;

namespace Plexo.Client.SDK
{
    [ServiceBehavior(IncludeExceptionDetailInFaults = true)]
    public class SecureCallback : ISecureCallback
    {
        private static readonly ICallback CallbackImplementation;
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        public async Task<ClientSignedResponse> Instrument(ServerSignedRequest<IntrumentCallback> instrument)
        {
            ServerResponse<IntrumentCallback> sins;
            try
            {
                PaymentGatewayClient cl = PaymentGatewayClientFactory.GetClient(instrument.Object.Object.Client);
                if (cl == null)
                    return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "Unable to locate PaymentGatewayClient for client '" + instrument.Object.Object.Client + "'.");
                using (var scope = new FlowingOperationContextScope(cl.InnerChannel))
                {
                    sins = await cl.UnwrapRequest(instrument).ContinueOnScope(scope);
                
                }
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
            cr.Client = instrument.Object.Object.Client;
            try
            {
                return CertificateHelperFactory.Instance.Sign<ClientSignedResponse, ClientResponse>(cr.Client, cr);
            }
            catch (Exception e)
            {
                return GenerateError(ResultCodes.ClientServerError, instrument.Object.Object.Client, "System Error", e.ToString());
            }
        }

        public async Task<ClientSignedResponse> Payment(ServerSignedRequest<TransactionCallback> transaction)
        {

            ServerResponse<TransactionCallback> sins;
            try
            {
                PaymentGatewayClient cl = PaymentGatewayClientFactory.GetClient(transaction.Object.Object.Client);
                if (cl == null)
                    return GenerateError(ResultCodes.ClientServerError, transaction.Object.Object.Client, "Unable to locate PaymentGatewayClient for client '" + transaction.Object.Object.Client + "'.");
                using (var scope = new FlowingOperationContextScope(cl.InnerChannel))
                {
                    sins = await cl.UnwrapRequest(transaction).ContinueOnScope(scope);

                }
                if (sins.ResultCode != ResultCodes.Ok)
                    return GenerateError(ResultCodes.ClientServerError, transaction.Object.Object.Client, sins.ErrorMessage);
            }
            catch (Exception e)
            {
                return GenerateError(ResultCodes.ClientServerError, transaction.Object.Object.Client, "System Error", e.ToString());
            }
            if (CallbackImplementation == null)
                return GenerateError(ResultCodes.ClientServerError, transaction.Object.Object.Client, "Callback message lost.There is no ICallback implementation");
            ClientResponse cr = await CallbackImplementation.Payment(sins.Response);
            cr.Client = transaction.Object.Object.Client;
            try
            {
                return CertificateHelperFactory.Instance.Sign<ClientSignedResponse, ClientResponse>(cr.Client, cr);
            }
            catch (Exception e)
            {
                return GenerateError(ResultCodes.ClientServerError, transaction.Object.Object.Client, "System Error", e.ToString());
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
            if (CallbackImplementation == null)
            {
                List<Assembly> asse = new List<Assembly>();
                Assembly assembly = Assembly.GetExecutingAssembly();
                UriBuilder uri = new UriBuilder(assembly.GetName().CodeBase);
                string dirname = Path.GetDirectoryName(Uri.UnescapeDataString(uri.Path));
                if (!string.IsNullOrEmpty(dirname))
                {
                    foreach (string dll in Directory.GetFiles(dirname, "*.dll", SearchOption.AllDirectories))
                    {
                        try
                        {
                            asse.Add(Assembly.LoadFile(dll));
                        }
                        catch (FileLoadException)
                        {
                        }
                        catch (BadImageFormatException)
                        {
                        }
                    }
                }
                CallbackImplementation = (ICallback)asse.SelectMany(a => a.GetTypes()).Where(a => a.GetInterfaces().Contains(typeof(ICallback))).Select(a => Activator.CreateInstance(a)).FirstOrDefault();
            }
            if (CallbackImplementation==null)
                Logger.Error("There is no ICallback implementation");
        }
    }



}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceModel;
using System.Threading.Tasks;
using Plexo.Client.SDK.Certificates;
using Plexo.Client.SDK.Logging;
using Plexo.Exceptions;
using Plexo.Helpers;

namespace Plexo.Client.SDK
{
    [ServiceBehavior(IncludeExceptionDetailInFaults = true)]
    public class SecureCallback : ISecureCallback
    {
        private static readonly ICallback CallbackImplementation;
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();


        private async Task<ClientSignedResponse> SignWrapper<T>(ServerSignedRequest<T> request, Func<T, Task<ClientResponse>> func) where T : IClientCallback
        {
            ServerResponse<T> sins = new ServerResponse<T>();
            try
            {
                PaymentGatewayClient cl = PaymentGatewayClientFactory.GetClient(request.Object.Object.Client);
                if (cl == null)
                    throw new ResultCodeException(ResultCodes.ClientServerError, ("en", $"Unable to locate PaymentGatewayClient for client '{request.Object.Object.Client}'."), ("es", $"No puedo encontrar una clase que defina a PaymentGatewayClient con el client '{request.Object.Object.Client}'."));
                using (var scope = new FlowingOperationContextScope(cl.InnerChannel))
                {
                    sins = await cl.UnwrapRequest(request).ContinueOnScope(scope);
                }
                if (sins.ResultCode != ResultCodes.Ok)
                    return GenerateError(sins, request.Object.Object.Client);
                if (CallbackImplementation == null)
                    throw new ResultCodeException(ResultCodes.ClientServerError, ("en", "Callback message lost.There is no ICallback implementation"), ("es", "Mensaje del callback pedido. No hay implementacion de ICallback"));
                ClientResponse cr = await func(sins.Response);
                cr.Client = request.Object.Object.Client;
                return CertificateHelperFactory.Instance.Sign<ClientSignedResponse, ClientResponse>(cr.Client, cr);
            }
            catch (Exception e)
            {
                sins.PopulateFromException(e, Logger);
                return GenerateError(sins, request.Object.Object.Client);
            }
        }
        public async Task<ClientSignedResponse> Instrument(ServerSignedRequest<IntrumentCallback> instrument)
        {
            return await SignWrapper(instrument, i => CallbackImplementation.Instrument(i));            
        }

        public async Task<ClientSignedResponse> Payment(ServerSignedRequest<TransactionCallback> transaction)
        {
            return await SignWrapper(transaction, t => CallbackImplementation.Payment(t));
        }


        private ClientSignedResponse GenerateError(ServerResponse resp, string client)
        {            
            ClientResponse r = new ClientResponse();
            r.Client = client;
            r.I18NErrorMessages = resp.I18NErrorMessages;
            r.ErrorMessage = resp.ErrorMessage;
            r.ResultCode = resp.ResultCode;
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

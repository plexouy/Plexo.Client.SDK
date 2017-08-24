using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Web;
using System.Threading;
using System.Threading.Tasks;
using Goova.JsonDataContractSerializer;
using Plexo.Client.SDK.Certificates;
using Plexo.Client.SDK.Logging;
using Plexo.Exceptions;
using Plexo.Helpers;


namespace Plexo.Client.SDK
{
    public class PaymentGatewayClient : ClientBase<ISecurePaymentGateway>, IPaymentGateway
    {
        private string _clientName;
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        private PaymentGatewayClient(ServiceEndpoint enp) : base(enp)
        {
        }

        public static PaymentGatewayClient Create(string serverurl, string clientname, int timeout = 120, WebHttpBehavior behavior = null)
        {

            try
            {
                WebHttpBinding binding = new WebHttpBinding();
                binding.OpenTimeout = TimeSpan.FromSeconds(timeout);
                binding.CloseTimeout = TimeSpan.FromSeconds(timeout);
                binding.SendTimeout = TimeSpan.FromSeconds(timeout);
                binding.ReceiveTimeout = TimeSpan.FromSeconds(timeout);
                if (serverurl.StartsWith("https"))
                    binding.Security.Mode = WebHttpSecurityMode.Transport;
                ServiceEndpoint svc = new ServiceEndpoint(ContractDescription.GetContract(typeof(ISecurePaymentGateway)),
                    binding, new EndpointAddress(serverurl));
                binding.ContentTypeMapper=new NewtonsoftJsonContentTypeMapper();
                if (behavior == null)
                {
                    behavior = new NewtonsoftJsonBehavior
                    {
                        DefaultBodyStyle = WebMessageBodyStyle.Bare,
                        DefaultOutgoingRequestFormat = WebMessageFormat.Json,
                        DefaultOutgoingResponseFormat = WebMessageFormat.Json
                    };     
                    
                }
                svc.Behaviors.Add(behavior);
                
                PaymentGatewayClient pgc = new PaymentGatewayClient(svc);
                pgc._clientName = clientname;
                return pgc;
            }
            catch (Exception e)
            {
                Logger.ErrorException("Unable to create PaymentGatewayClient",e);
                throw;
            }

        }

        public async Task<ServerResponse<Session>> Authorize(Authorization authorization)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.Authorize, authorization);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }
        public async Task<ServerResponse> DeleteInstrument(DeleteInstrumentRequest info)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperT(Channel.DeleteInstrument, info);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }            
        }
        public async Task<ServerResponse<List<IssuerInfo>>> GetSupportedIssuers()
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperS(Channel.GetSupportedIssuers);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }

        }
        public async Task<ServerResponse<List<Commerce>>> GetCommerces()
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperS(Channel.GetCommerces);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }
        public async Task<ServerResponse<Commerce>> AddCommerce(CommerceRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.AddCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<Commerce>> ModifyCommerce(CommerceModifyRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.ModifyCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse> DeleteCommerce(CommerceIdRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperT(Channel.DeleteCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }

        }

        public async Task<ServerResponse> SetDefaultCommerce(CommerceIdRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperT(Channel.SetDefaultCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<List<IssuerData>>> GetCommerceIssuers(CommerceIdRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.GetCommerceIssuers, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<IssuerData>> AddIssuerCommerce(IssuerData commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.AddIssuerCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse> DeleteIssuerCommerce(CommerceIssuerIdRequest commerce)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperT(Channel.DeleteIssuerCommerce, commerce);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }


        public async Task<ServerResponse<Transaction>> Purchase(PaymentRequest payment)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.Purchase, payment);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<Transaction>> Cancel(CancelRequest cancel)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.Cancel, cancel);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<Transaction>> StartReserve(ReserveRequest payment)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.StartReserve, payment);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<Transaction>> EndReserve(Reserve reserve)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.EndReserve, reserve);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<Transaction>> Status(Reference payment)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.Status, payment);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }

        public async Task<ServerResponse<List<PaymentInstrument>>> GetInstruments(AuthorizationInfo info)
        {
            var currentSynchronizationContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(new OperationContextSynchronizationContext(InnerChannel));
                return await WrapperTS(Channel.GetInstruments, info);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(currentSynchronizationContext);
            }
        }



        private async Task<ServerResponse<S>> WrapperTS<T, S>(Func<ClientSignedRequest<T>, Task<ServerSignedResponse<S>>> func, T data)
        {
            ClientRequest<T> auth = WrapClient(data);
            ClientSignedRequest<T> signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest<T>, ClientRequest<T>>(_clientName, auth);
            return await UnwrapResponse(await func(signed));
        }

        private async Task<ServerResponse> WrapperT<T>(Func<ClientSignedRequest<T>, Task<ServerSignedResponse>> func, T data)
        {
            ClientRequest<T> auth = WrapClient(data);
            ClientSignedRequest<T> signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest<T>, ClientRequest<T>>(_clientName, auth);
            return await UnwrapResponse(await func(signed));
        }
        private async Task<ServerResponse<S>> WrapperS<S>(Func<ClientSignedRequest, Task<ServerSignedResponse<S>>> func)
        {
            ClientRequest r = new ClientRequest { Client = _clientName };
            ClientSignedRequest signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest, ClientRequest>(_clientName, r);
            return await UnwrapResponse(await func(signed));
        }

        private ClientRequest<T> WrapClient<T>(T obj)
        {
            return new ClientRequest<T> {Client = _clientName, Request = obj};
        }

       

        private async Task<SignatureHelper> GetSignatureHelper(string fingerprint, ServerResponse response)
        {
            if (!CertificateHelperFactory.Instance.VerifyKeys.ContainsKey(_clientName))
                throw new ConfigurationException(("en",$"Configuration do not have certificate information about the client '{_clientName}'"), ("es", $"La configuracion no tiene el certificado del cliente '{_clientName}'"));
            SignatureHelper c = CertificateHelperFactory.Instance.VerifyKeys[_clientName].FirstOrDefault(a => a.Key == fingerprint).Value;
            if (c == null)
            {
                await CertificateHelperFactory.Instance.ServerCertSemaphore.WaitAsync();
                try
                {
                    ServerSignedResponse<PublicKeyInfo> r = await Channel.GetServerPublicKey(fingerprint);
                    if (r.Object.Object.ResultCode != ResultCodes.Ok)
                        throw new FingerprintException(("en", "Invalid or outdated Fingerprint, server returns: " + (r.Object.Object.ErrorMessage ?? "")), ("es", "Huella invalida o vieja, el servido retorna: " + ((r.Object.Object.I18NErrorMessages.ContainsKey("es") ? r.Object.Object.I18NErrorMessages["es"] : r.Object.Object.ErrorMessage) ?? "")));
                    X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(r.Object.Object.Response.Key));
                    c = new SignatureHelper(cert, false);
                    SignatureHelper verify = null;
                    if (CertificateHelperFactory.Instance.VerifyKeys[_clientName].ContainsKey(r.Object.Fingerprint))
                        verify = CertificateHelperFactory.Instance.VerifyKeys[_clientName][r.Object.Fingerprint];
                    else if (r.Object.Fingerprint.Equals(r.Object.Object.Response.Fingerprint, StringComparison.InvariantCultureIgnoreCase))
                        verify = c;
                    if (verify == null)
                        throw new FingerprintException(("en", "Fingerprint not found: " + r.Object.Fingerprint), ("es", "Huella no encontrada: " + r.Object.Fingerprint));
                    verify.Verify<ServerSignedResponse<PublicKeyInfo>, ServerResponse<PublicKeyInfo>>(r);
                    CertificateHelperFactory.Instance.VerifyKeys[_clientName].Add(r.Object.Object.Response.Fingerprint, c);
                    return c;
                }
                finally
                {
                    CertificateHelperFactory.Instance.ServerCertSemaphore.Release();
                }
            }
            return c;

        }
        internal async Task<ServerResponse<T>> UnwrapRequest<T>(ServerSignedRequest<T> resp)
        {

            ServerResponse<T> response = new ServerResponse<T>();
            try
            {
                SignatureHelper c = await GetSignatureHelper(resp.Object.Fingerprint, response);
                T obj = c.Verify<ServerSignedRequest<T>, T>(resp);
                return new ServerResponse<T> { ResultCode = ResultCodes.Ok, Response = obj };
            }
            catch (Exception e)
            {
                response.PopulateFromException(e, Logger);
                return response;
            }
        }
        internal async Task<ServerResponse<T>> UnwrapResponse<T>(ServerSignedResponse<T> resp)
        {
            ServerResponse<T> response = new ServerResponse<T>();
           
            try
            {
                SignatureHelper c = await GetSignatureHelper(resp.Object.Fingerprint, response);
                return c.Verify<ServerSignedResponse<T>, ServerResponse<T>>(resp);
            }
            catch (Exception e)
            {
                response.PopulateFromException(e, Logger);
                return response;
            }
        }
        internal async Task<ServerResponse> UnwrapResponse(ServerSignedResponse resp)
        {
            ServerResponse response = new ServerResponse();
            try
            {
                SignatureHelper c = await GetSignatureHelper(resp.Object.Fingerprint, response);
                return c.Verify<ServerSignedResponse, ServerResponse>(resp);
            }
            catch (Exception e)
            {
                response.PopulateFromException(e, Logger);
                return response;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Web;
using System.Threading.Tasks;
using Goova.ElSwitch.Client.SDK.Logging;
using Goova.ElSwitch.Exceptions;
using ConfigurationException = Goova.ElSwitch.Exceptions.ConfigurationException;

namespace Goova.ElSwitch.Client.SDK
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
                if (behavior == null)
                    behavior = new WebHttpBehavior
                    {
                        DefaultBodyStyle = WebMessageBodyStyle.Bare,
                        DefaultOutgoingRequestFormat = WebMessageFormat.Json,
                        DefaultOutgoingResponseFormat = WebMessageFormat.Json,
                        HelpEnabled = true
                    };
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

        public async Task<ServerResponse<string>> Authorize(Authorization authorization)
        {
            ClientRequest<Authorization> auth = WrapClient(authorization);
            ClientSignedRequest<Authorization> signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest<Authorization>, ClientRequest<Authorization>>(_clientName, auth);
            return await UnwrapResponse(await Channel.Authorize(signed));

        }

        public async Task<ServerResponse<List<IssuerInfo>>> GetSupportedIssuers()
        {
            try
            {
                ClientRequest r = new ClientRequest { Client = _clientName };
                ClientSignedRequest signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest, ClientRequest>(_clientName, r);
                return await UnwrapResponse(await Channel.GetSupportedIssuers(signed));

            }
            catch (Exception e)
            {
                throw;
            }
        }

        public async Task<ServerResponse<Transaction>> Purchase(PaymentRequest payment)
        {
            ClientRequest<PaymentRequest> paym = WrapClient(payment);
            ClientSignedRequest<PaymentRequest> signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest<PaymentRequest>, ClientRequest<PaymentRequest>>(_clientName, paym);
            return await UnwrapResponse(await Channel.Purchase(signed));
        }

        public async Task<ServerResponse<Transaction>> Cancel(CancelRequest cancel)
        {
            ClientRequest<CancelRequest> paym = WrapClient(cancel);
            ClientSignedRequest<CancelRequest> signed = CertificateHelperFactory.Instance.Sign<ClientSignedRequest<CancelRequest>, ClientRequest<CancelRequest>>(_clientName, paym);
            return await UnwrapResponse(await Channel.Cancel(signed));
        }




        private ClientRequest<T> WrapClient<T>(T obj)
        {
            return new ClientRequest<T> {Client = _clientName, Request = obj};
        }

        internal async Task<ServerResponse<T>> UnwrapResponse<T>(SignedServerResponse<T> resp)
        {
            if (!CertificateHelperFactory.Instance.VerifyKeys.ContainsKey(_clientName))
                throw new ConfigurationException("Configuration do not have certificate information about the client '" + _clientName + "'");
            RSAHelper c = CertificateHelperFactory.Instance.VerifyKeys[_clientName].FirstOrDefault(a => a.Key == resp.Object.Fingerprint).Value;
            if (c == null)
            {
                await CertificateHelperFactory.Instance.ServerCertSemaphore.WaitAsync();
                try
                {
                    //Secure this over ssl
                    SignedServerResponse<PublicKeyInfo> r = await Channel.GetServerPublicKey(resp.Object.Fingerprint);
                    if (r.Object.Object.ResultCode != ResultCodes.Ok)
                    {
                        string msg = "Invalid or outdated Fingerprint, server returns: " + r.Object.Object.ErrorMessage ?? "";
                        Logger.Error(msg);
                        return new ServerResponse<T>() {ErrorMessage = msg, ResultCode = ResultCodes.InvalidFingerprint};
                    }
                    X509Certificate2 cert = new X509Certificate2(r.Object.Object.Response.Key);
                    c = new RSAHelper(cert, false);
                    RSAHelper verify = null;
                    if (CertificateHelperFactory.Instance.VerifyKeys[_clientName].ContainsKey(r.Object.Fingerprint))
                        verify = CertificateHelperFactory.Instance.VerifyKeys[_clientName][r.Object.Fingerprint];
                    else if (r.Object.Fingerprint.Equals(r.Object.Object.Response.Fingerprint, StringComparison.InvariantCultureIgnoreCase))
                        verify = c;
                    if (verify == null)
                    {
                        string msg = ("Fingerprint not found: " + r.Object.Fingerprint);
                        Logger.Error(msg);
                        return new ServerResponse<T>() {ErrorMessage = msg, ResultCode = ResultCodes.InvalidFingerprint};
                    }
                    verify.Verify<SignedServerResponse<PublicKeyInfo>, ServerResponse<PublicKeyInfo>>(r);
                    CertificateHelperFactory.Instance.VerifyKeys[_clientName].Add(r.Object.Object.Response.Fingerprint, c);

                }
                catch (ResultCodeException e)
                {
                    Logger.ErrorException(e.Message,e);
                    return new ServerResponse<T>() {ErrorMessage = e.Message, ResultCode = e.Code};
                }
                catch (Exception e)
                {
                    Logger.ErrorException(e.Message, e);
                    return new ServerResponse<T> {ErrorMessage = "System Error", ResultCode = ResultCodes.SystemError};
                }
                finally
                {
                    CertificateHelperFactory.Instance.ServerCertSemaphore.Release();
                }
            }
            try
            {
                return c.Verify<SignedServerResponse<T>, ServerResponse<T>>(resp);
            }
            catch (ResultCodeException e)
            {
                Logger.ErrorException(e.Message, e);
                return new ServerResponse<T>() {ErrorMessage = e.Message, ResultCode = e.Code};
            }
            catch (Exception e)
            {
                Logger.ErrorException(e.Message, e);
                return new ServerResponse<T> {ErrorMessage = "System Error", ResultCode = ResultCodes.SystemError};
            }
        }
        internal async Task<ServerResponse<T>> UnwrapRequest<T>(ServerSignedRequest<T> resp)
        {
            if (!CertificateHelperFactory.Instance.VerifyKeys.ContainsKey(_clientName))
                throw new ConfigurationException("Configuration do not have certificate information about the client '" + _clientName + "'");
            RSAHelper c = CertificateHelperFactory.Instance.VerifyKeys[_clientName].FirstOrDefault(a => a.Key == resp.Object.Fingerprint).Value;
            if (c == null)
            {
                await CertificateHelperFactory.Instance.ServerCertSemaphore.WaitAsync();
                try
                {
                    //Secure this over ssl
                    SignedServerResponse<PublicKeyInfo> r = await Channel.GetServerPublicKey(resp.Object.Fingerprint);
                    if (r.Object.Object.ResultCode != ResultCodes.Ok)
                    {
                        string msg = "Invalid or outdated Fingerprint, server returns: " + r.Object.Object.ErrorMessage ?? "";
                        Logger.Error(msg);
                        return new ServerResponse<T>() { ErrorMessage = msg, ResultCode = ResultCodes.InvalidFingerprint };
                    }
                    X509Certificate2 cert = new X509Certificate2(r.Object.Object.Response.Key);
                    c = new RSAHelper(cert, false);
                    RSAHelper verify = null;
                    if (CertificateHelperFactory.Instance.VerifyKeys[_clientName].ContainsKey(r.Object.Fingerprint))
                        verify = CertificateHelperFactory.Instance.VerifyKeys[_clientName][r.Object.Fingerprint];
                    else if (r.Object.Fingerprint.Equals(r.Object.Object.Response.Fingerprint, StringComparison.InvariantCultureIgnoreCase))
                        verify = c;
                    if (verify == null)
                    {
                        string msg = ("Fingerprint not found: " + r.Object.Fingerprint);
                        Logger.Error(msg);
                        return new ServerResponse<T>() { ErrorMessage = msg, ResultCode = ResultCodes.InvalidFingerprint };
                    }
                    verify.Verify<SignedServerResponse<PublicKeyInfo>, ServerResponse<PublicKeyInfo>>(r);
                    CertificateHelperFactory.Instance.VerifyKeys[_clientName].Add(r.Object.Object.Response.Fingerprint, c);

                }
                catch (ResultCodeException e)
                {
                    Logger.ErrorException(e.Message, e);
                    return new ServerResponse<T>() { ErrorMessage = e.Message, ResultCode = e.Code };
                }
                catch (Exception e)
                {
                    Logger.ErrorException(e.Message, e);
                    return new ServerResponse<T> { ErrorMessage = "System Error", ResultCode = ResultCodes.SystemError };
                }
                finally
                {
                    CertificateHelperFactory.Instance.ServerCertSemaphore.Release();
                }
            }
            try
            {
                T obj = c.Verify<ServerSignedRequest<T>, T>(resp);
                return new ServerResponse<T> { ResultCode = ResultCodes.Ok, Response = obj };
            }
            catch (ResultCodeException e)
            {
                Logger.ErrorException(e.Message, e);
                return new ServerResponse<T>() { ErrorMessage = e.Message, ResultCode = e.Code };
            }
            catch (Exception e)
            {
                Logger.ErrorException(e.Message, e);
                return new ServerResponse<T> { ErrorMessage = "System Error", ResultCode = ResultCodes.SystemError };
            }
        }
    }
}

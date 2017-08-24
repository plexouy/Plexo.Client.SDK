using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Plexo.Client.SDK.Logging;
using Plexo.Exceptions;

namespace Plexo.Client.SDK
{
    public static class Extensions
    {
        public static void PopulateFromException(this ServerResponse resp, ResultCodeException exception, ILog log = null)
        {
            resp.I18NErrorMessages = exception.I18NErrorMessages;
            resp.ErrorMessage = exception.ErrorMessage;
            resp.ResultCode = exception.Code;
            if (log != null)
                if (exception.IsErrorLogged || exception.OriginalException != null)
                    if (exception.OriginalException != null)
                        log.ErrorException(resp.ErrorMessage, exception.OriginalException);
                    else
                        log.ErrorException(resp.ErrorMessage, exception);
                else
                    log.Debug(resp.ErrorMessage);
        }

        public static void PopulateFromException(this ServerResponse resp, Exception exception, ILog log = null)
        {
            if (exception is ResultCodeException)
            {
                resp.PopulateFromException((ResultCodeException)exception, log);
                return;
            }
            resp.ResultCode = ResultCodes.SystemError;
            resp.I18NErrorMessages = new Dictionary<string, string>
            {
                {"en", "System Error, please try later"},
                {"es", "Error del Sistema, pruebe nuevamente mas tarde"}
            };
            resp.ErrorMessage = resp.I18NErrorMessages["en"];
            log?.ErrorException(resp.ErrorMessage, exception);
        }
    }
}
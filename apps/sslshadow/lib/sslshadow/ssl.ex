defmodule Sslshadow.SSL do

  require Logger
  def testcon({ip, port}) do
    testcon({:validate, ip, port})
  end
  def testcon({:validate, ip, port}) do
    ssltimeout = Application.get_env(:sslshadow, :ssltimeout, 10000)
    cafile = Application.get_env(:sslshadow, :cafile)
    case :ssl.connect(to_char_list(ip), port, [{:verify, :verify_peer}, {:cacertfile, cafile}], ssltimeout) do
      {:ok, sslsock}   -> Logger.debug("Got valid certificate")
                          validcert(:valid, ip,sslsock, :ok)
      {:error, reason} -> Logger.debug("Error detected: " <> inspect reason)
                          testcon({:novalidate, ip, port, reason})
      reason           -> Logger.debug("I should never happen" <> inspect reason)
                          testcon({:novalidate, ip, port, reason})
    end
  end
  def testcon({:novalidate, ip, port, reason}) do
    ssltimeout = Application.get_env(:sslshadow, :ssltimeout, 10000)
    case :ssl.connect(to_char_list(ip), port, [], ssltimeout) do
      {:ok, sslsock}   -> Logger.debug("Got unvalidated certificate and reason: " <> inspect reason)
                          validcert(:failedvalidation, ip, sslsock, reason)
      {:error, reason} -> Logger.debug("Gotten tagged :error: " <> inspect reason)
                          {:error, reason}
      reason           -> Logger.debug("Gotten untagged error: " <> inspect reason)
                          {:error, reason}
    end
  end

  def validcert(status, ip, sslsock, reason) do
    case :ssl.peercert(sslsock) do
      {:ok, cert} -> :ssl.close(sslsock)
                     {reason, cert}
#                     processcert({status, ip, cert, status})
      {:error, reason} -> Logger.debug("I don't exist" <> inspect reason)
                      :ssl.close(sslsock)
                      {:erron, reason}
    end
  end


#  def processcert({:failedvalidation, _ip, cert, reason}) do
#    Logger.debug("Cert failed validation, examine anyways... " <> inspect reason)
#    :public_key.pkix_decode_cert(cert, :otp)
##    :public_key.pkix_issuer_id(cert, :self) |> IO.inspect
##    :public_key.pkix_dist_points(cert) |> IO.inspect
#  end
#  def processcert({:valid, _ip, cert, :valid}) do
#    Logger.debug("Cert is valid, work to do")
#    :public_key.pkix_decode_cert(cert, :otp)
##    :public_key.pkix_issuer_id(cert, :self) |> IO.inspect
##    :public_key.pkix_dist_points(cert) |> IO.inspect
#  end

  def decode_cert(cert) do
    {:OTPCertificate,
      {:OTPTBSCertificate,
        version,
        serialNumber,
        signature,
        issuer,
        validity,
        subject,
        subjectpublickey,
        issuerUniqueID,
        subjectUniqueID,
        extensions},_,_} = :public_key.pkix_decode_cert(cert, :otp)

        results = Enum.map(extensions, &v3extensionlookup/1)
        |> Enum.filter(&(&1 != nil))
      {subject, results} #UniqueID, issuerUniqueID}
  end

  def v3extensionlookup({:Extension, {2, 5, 29, 14}, _bool, keyid}) do {:subjectKeyIdentifier, keyid} end
  def v3extensionlookup({:Extension, {2, 5, 29, 35}, _bool, {:AuthorityKeyIdentifier, authorityKeyIdentifier,_,_}}) do {:authorityKeyIdentifier, authorityKeyIdentifier} end
  def v3extensionlookup(_) do nil end
    
end

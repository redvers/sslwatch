defmodule Sslshadow.SSL do

  require Logger
  def testcon({ip, port}) do
    testcon({:validate, ip, port})
  end
  def testcon({:validate, ip, port}) do
    ssltimeout = Application.get_env(:sslshadow, :ssltimeout, 10000)
    cafile = Application.get_env(:sslshadow, :cafile)
    case :ssl.connect(to_char_list(ip), port, [{:verify, 2}, {:depth, 9}, {:cacertfile, cafile}], ssltimeout) do
      {:ok, sslsock}   -> #Logger.debug("Sslshadow.SSL: Got valid certificate")
                          validcert(:valid, ip,sslsock, :ok)
      {:error, reason} -> #Logger.debug("Sslshadow.SSL: Error detected: " <> inspect reason)
                          testcon({:novalidate, ip, port, reason})
      reason           -> #Logger.debug("Sslshadow.SSL: I should never happen" <> inspect reason)
                          testcon({:novalidate, ip, port, reason})
    end
  end
  def testcon({:novalidate, ip, port, reason}) do
    ssltimeout = Application.get_env(:sslshadow, :ssltimeout, 10000)
    case :ssl.connect(to_char_list(ip), port, [], ssltimeout) do
      {:ok, sslsock}   -> #Logger.debug("Sslshadow.SSL: Got unvalidated certificate and reason: " <> inspect reason)
                          validcert(:failedvalidation, ip, sslsock, reason)
      {:error, reason} -> #Logger.debug("Sslshadow.SSL: Gotten tagged :error: " <> inspect reason)
                          {:error, reason}
      reason           -> #Logger.debug("Sslshadow.SSL: Gotten untagged error: " <> inspect reason)
                          {:error, reason}
    end
  end

  def validcert(status, ip, sslsock, reason) do
    case :ssl.peercert(sslsock) do
      {:ok, cert} -> :ssl.close(sslsock)
                     {reason, cert}
#                     processcert({status, ip, cert, status})
      {:error, reason} -> #Logger.debug("Sslshadow.SSL: I don't exist" <> inspect reason)
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

#  def decode_cert(cert) do
#    :public_key.der_decode('X520CommonName', cert)
#  end
  def decode_cert(cert) do
    {:OTPCertificate,
      {:OTPTBSCertificate,
        _version,
        serialNumber, # Integer, good as is
        signature,    # binary
        {:rdnSequence, issuer},
        _validity,
        {:rdnSequence, subject},
        _subjectpublickey,
        _issuerUniqueID,
        _subjectUniqueID,
        extensions},_,_} = :public_key.pkix_decode_cert(cert, :otp)

    issuer = Enum.map(issuer, fn([{:AttributeTypeAndValue, oid, value}]) -> { String.to_atom(OID.oid2txt(oid)), value } end)
    extensions = Enum.map(extensions, fn({:Extension, oid, criticality, value}) -> { String.to_atom(OID.oid2txt(oid)), value } end)

                                      keyid = Keyword.get(extensions, String.to_atom("id-ce-subjectKeyIdentifier"))
    {:AuthorityKeyIdentifier, cakeyid,_,_}  = Keyword.get(extensions, String.to_atom("id-ce-authorityKeyIdentifier"))

    [ %SSLShadowDB.IP{serial: serialNumber, keyid: keyid, signingkeyid: cakeyid},
      %SSLShadowDB.Certs{serial: serialNumber, keyid: keyid, signingkeyid: cakeyid, blob: cert}]

  end

    


    

  def decodex_cert(cert) do
    {:OTPCertificate,
      {:OTPTBSCertificate,
        version,
        serialNumber,
        signature,
        issuer,
        validity,
        {:rdnSequence, subject},
        subjectpublickey,
        issuerUniqueID,
        subjectUniqueID,
        extensions},x,y} = :public_key.pkix_decode_cert(cert, :otp)

        results = Enum.map(extensions, &v3extensionlookup/1) |> Enum.filter(&(&1 != nil))
        subject = List.flatten(subject)
        |> Enum.map(&subjectlookup/1) |> Enum.filter(&(&1 != nil)) |> Enum.filter(&(&1 != nil))
      {subject, results} #UniqueID, issuerUniqueID}
  end




  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 3},       cn}) do %{CN:      cn} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 4},  surname}) do %{Su: surname} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 5},  serialN}) do %{SN: serialN} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 6},  country}) do %{C:  country} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 7}, locality}) do %{L: locality} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 8},    state}) do %{ST:   state} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 9},   staddr}) do %{SA:  staddr} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 10},       o}) do %{O:        o} end 
  def subjectlookup({:AttributeTypeAndValue, {2, 5, 4, 11},      ou}) do %{ON:      ou} end 
  def subjectlookup(ds) do Logger.debug("Unhandled Certificate OID: " <> inspect ds) ; nil end


  def v3extensionlookup({:Extension, {2, 5, 29, 14}, _bool, keyid}) do {:subjectKeyIdentifier, keyid} end
  def v3extensionlookup({:Extension, {2, 5, 29, 35}, _bool, {:AuthorityKeyIdentifier, authorityKeyIdentifier,_,_}}) do {:authorityKeyIdentifier, authorityKeyIdentifier} end
  def v3extensionlookup(_) do nil end
    
end

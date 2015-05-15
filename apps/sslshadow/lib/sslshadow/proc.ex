require Logger
defmodule Sslshadow.Proc do
  use Amnesia
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], [])
  end

  def ipin({ip,port}) do
    ip = to_char_list(ip)
    case SSLShadowDB.Cache.inMemCache?({ip,port}) do
      :hit    -> :ok
      :purged -> pullssl({ip, port})
      :miss   -> pullssl({ip, port})
    end
  end

  def handle_call({ip,port}, _from, state) do
    pullssl({ip,port})
    {:reply, :ok, state}
  end

  def pullssl({ip, port}) do
#    :ssl.connect(ip, port, [verify: :verify_peer, cacertfile: '/etc/ssl/certs/ca-certificates.crt', depth: 9], 2000)
    :ssl.connect(ip, port, [], 3000)
    |> haveCert?
    |> writeCert
    |> selfSigned?
    |> extractIssuer
    |> extractRdn
    |> decodeCert
    |> extractSubject
    |> writeMemCache({ip,port})
    |> writefqdn({ip,port})
    |> writesubAltNames({ip,port})
  end

  def writesubAltNames({:ok, _serialNumber, _cert, fqdn, subAlts, _decoded, issuer},{ip,port}) do
    Enum.map(subAlts, &List.to_string/1)
    |> Enum.map(fn(x) -> writefqdn({:ok, nil, nil, x, nil, nil, issuer},{ip,port}) end)
    case SSLShadowDB.DomainPersist.read!(fqdn) do
      nil     -> singleissuer = HashSet.new |> HashSet.put(issuer)
#                 Amnesia.transaction do
                   SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: singleissuer})
#                 end
      %SSLShadowDB.DomainPersist{issueids: hashset}
              -> 
#                 Amnesia.transaction do
                   SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: HashSet.put(hashset, issuer)})
#                 end
    end
  end
  def writesubAltNames(state = {:error, _},{_ip,_port}) do
    state
  end
  def writesubAltNames(state = {:final, _},{_ip,_port}) do
    state
  end
  def writesubAltNames(state,{ip,port}) do
    Logger.debug("BOOM: "<> inspect(state) <> inspect({ip, port}))
    state
  end


  def writeMemCache({:error, error},{ip,port}) do
    negcacheval = Application.get_env(:sslshadow, :negcache)
#    Amnesia.transaction do
      SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: {:error, error}, cachetime: (ts + negcacheval)})
      SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: nil, state: {:error, error}, timestamp: ts})
#    end
    {:error, error}
  end
  def writeMemCache({:final, final},{ip,port}) do
    ipcachetime = Application.get_env(:sslshadow, :negcache)
#    Amnesia.transaction do
      SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: {:final, final}, cachetime: (ts + ipcachetime)})
      SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: nil, state: {:final, final}, timestamp: ts})
#    end
    {:final, final}
  end
  def writeMemCache(state = {:ok, _serialNumber, cert, _fqdn, _subAlts, _decoded, issuer},{ip,port}) do
    ipcachetime = Application.get_env(:sslshadow, :negcache)
#    Amnesia.transaction do
      SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: :ok, cachetime: (ts + ipcachetime)})
      SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: issuer, state: :ok, timestamp: ts})
      SSLShadowDB.CertPersist.write!(%SSLShadowDB.CertPersist{issueid: issuer, blob: cert})
#    end
    state
  end
  def writefqdn(state = {:ok, _serialNumber, _cert, fqdn, _subAlts, _decoded, issuer},{_ip,_port}) do
    fqdn = to_string(fqdn)
    case SSLShadowDB.DomainPersist.read!(fqdn) do
      nil     -> singleissuer = HashSet.new |> HashSet.put(issuer)
#                 Amnesia.transaction do
                   SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: singleissuer})
#                 end
      %SSLShadowDB.DomainPersist{issueids: hashset}
              -> #Amnesia.transaction do
                   SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: HashSet.put(hashset, issuer)})
#                 end
    end
    state
  end
  def writefqdn(state,{_ip,_port}) do
#    Logger.debug("BOOM: " <> inspect state <> inspect {ip,port})
    state
  end


  def extractSubject({:error, error}) do
    {:error, error}
  end
  def extractSubject({:final, final}) do
    {:final, final}
  end
  def extractSubject({:ok, _serialNumber, cert, decoded, issuer}) do
    {:OTPCertificate,                                                                                                                                                 
       {:OTPTBSCertificate,
         _version,
         serialNumber, # Integer, good as is
         _signature,    # binary
         _theissuer,
         _validity,
         {:rdnSequence, subject},
         _subjectpublickey,
         _issuerUniqueID,
         _subjectUniqueID,
         extensions},_,_} = decoded

    fqdn = extractFQDN(subject)
    subAlts = extractsubAlts(extensions)

    {:ok, serialNumber, cert, fqdn, subAlts, decoded, issuer}

  end

  def extractsubAlts(extensions) when is_list(extensions) do
    List.flatten(extensions)
    |> Enum.filter(fn({_,oid,_,value}) -> if (oid == OID.txt2oid("id-ce-subjectAltName")) do value end end)
    |> filterSubs
    |> Enum.filter(fn(x) -> x end)
  end
  def extractsubAlts(_extensions) do
    []
  end

  def extractFQDN(subject) do
    List.flatten(subject)
    |> Enum.filter(fn({_,oid,value}) -> if (oid == OID.txt2oid("id-at-commonName")) do value end end)
    |> filterSubject
  end

  defp filterSubject([]) do
    []
  end
  defp filterSubject(other) do
    Enum.map(other, fn({_,_,{_, fqdn}}) -> fqdn end)
  end

  defp filterSubs([]) do
    []
  end
  defp filterSubs([{_,_,_,list}]) do
    Enum.map(list, &filterdNS/1)
  end

  def filterdNS({:dNSName, domain}) do
    domain
  end
  def filterdNS(unknown) do
    Logger.debug("Unknown subjectAlt item: " <> inspect unknown)
    nil
  end


  def decodeCert({:error, error}) do
    {:error, error}
  end
  def decodeCert({:final, final}) do
    {:final, final}
  end
  def decodeCert({:ok, serialNumber, cert, issuer}) do
    {:ok, serialNumber, cert, :public_key.pkix_decode_cert(cert, :otp), issuer}
  end

  def extractRdn({:error, error}) do
    {:error, error}
  end
  def extractRdn({:final, final}) do
    {:final, final}
  end
  def extractRdn({:ok, serialNumber, cert, _rdnSeq}) do
    {:ok, issuer} = :public_key.pkix_issuer_id(cert, :self)
    {:ok, serialNumber, cert, issuer}
  end

  def extractIssuer({:error, error}) do
    {:error, error}
  end
  def extractIssuer({:final, final}) do
    {:final, final}
  end
  def extractIssuer({:ok, cert}) do
    {:ok, {serialNumber,rdnSeq}} = :public_key.pkix_issuer_id(cert, :self)
    {:ok, serialNumber, cert, rdnSeq}
  end


  def writeCert({:error, error}) do
    {:error, error}
  end
  def writeCert({:ok, cert}) do
#    plaincert = :public_key.pkix_decode_cert(cert, :plain)
#    pementries = :public_key.pem_entry_encode(:Certificate, plaincert)
#    certfiledata = :public_key.pem_encode([pementries])
#    filename = :random.uniform*100000000000 |> trunc |> to_string
#    File.write!("/home/red/certs/" <> filename, certfiledata)

    {:ok, cert}
  end



  def selfSigned?({:ok, cert}) do
    case :public_key.pkix_is_self_signed(cert) do
      true -> {:final, :selfsigned}
      false -> {:ok, cert}
    end
  end
  def selfSigned?({:error, error}) do
    {:error, error}
  end

  def haveCert?({:ok, sslsocket}) do
    certresp = :ssl.peercert(sslsocket)
#    IO.inspect certresp
    :ssl.close(sslsocket)
    certresp
  end
  def haveCert?({:error, error}) do
    {:error, error}
  end















  
  def ts do
    {a,b,_} = :os.timestamp
    (a * 1000000) + b
  end





end

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

  def fipin({ip,port}) do
    ip = to_char_list(ip)
    case SSLShadowDB.Cache.inMemCache?({ip,port}) do
      :hit    -> :ok
#      :purged -> :poolboy.transaction(:sslproc, spawn(fn(wpid) -> GenServer.call(wpid, {ip,port}) end ))
#      :miss   -> :poolboy.transaction(:sslproc, spawn(fn(wpid) -> GenServer.call(wpid, {ip,port}) end ))
      :purged -> :poolboy.transaction(:sslproc, fn(wpid) -> spawn(GenServer, :call, [wpid, {ip,port}]) end )
      :miss   -> :poolboy.transaction(:sslproc, fn(wpid) -> spawn(GenServer, :call, [wpid, {ip,port}]) end )
    end
  end





  def handle_call({ip,port}, _from, state) do
    pullssl({ip,port})


    {:reply, :ok, state}
  end



  def pullssl({ip, port}) do
    :ssl.connect(ip, port, [verify: :verify_peer, cacertfile: '/etc/ssl/certs/ca-certificates.crt', depth: 9], 2000)
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
#    |> IO.inspect
  end

  def writesubAltNames(state = {:ok, serialNumber, cert, fqdn, subAlts, decoded, issuer},{ip,port}) do
    Enum.map(subAlts, &List.to_string/1)
    |> Enum.map(fn(x) -> writefqdn({:ok, nil, nil, x, nil, nil, issuer},{ip,port}) end)


    state
#    case SSLShadowDB.DomainPersist.read!(fqdn) do
#      nil     -> singleissuer = HashSet.new |> HashSet.put(issuer)
#                 SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: singleissuer})
#      %SSLShadowDB.DomainPersist{issueids: hashset}
#              -> SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: HashSet.put(hashset, issuer)})
#    end
  end
  def writesubAltNames(state,{ip,port}) do
#    Logger.debug("BOOM: "<> inspect state)
    state
  end


  def writeMemCache({:error, error},{ip,port}) do
    negcacheval = Application.get_env(:sslshadow, :negcache)
    SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: {:error, error}, cachetime: (ts + negcacheval)})
    SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: nil, state: {:error, error}, timestamp: ts})
    {:error, error}
  end
  def writeMemCache({:final, final},{ip,port}) do
    ipcachetime = Application.get_env(:sslshadow, :negcache)
    SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: {:final, final}, cachetime: (ts + ipcachetime)})
    SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: nil, state: {:final, final}, timestamp: ts})
    {:final, final}
  end
  def writeMemCache(state = {:ok, serialNumber, cert, fqdn, subAlts, decoded, issuer},{ip,port}) do
    ipcachetime = Application.get_env(:sslshadow, :negcache)
    SSLShadowDB.IPMemCache.write!(%SSLShadowDB.IPMemCache{ip: {ip,port}, state: :ok, cachetime: (ts + ipcachetime)})
    SSLShadowDB.IPPersist.write!(%SSLShadowDB.IPPersist{ip: {ip,port}, issueid: issuer, state: :ok, timestamp: ts})
    SSLShadowDB.CertPersist.write!(%SSLShadowDB.CertPersist{issueid: issuer, blob: cert})
    state
  end
  def writefqdn(state = {:ok, serialNumber, cert, fqdn, subAlts, decoded, issuer},{ip,port}) do
    fqdn = to_string(fqdn)
    case SSLShadowDB.DomainPersist.read!(fqdn) do
      nil     -> singleissuer = HashSet.new |> HashSet.put(issuer)
                 SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: singleissuer})
      %SSLShadowDB.DomainPersist{issueids: hashset}
              -> SSLShadowDB.DomainPersist.write!(%SSLShadowDB.DomainPersist{domain: fqdn, issueids: HashSet.put(hashset, issuer)})
    end
    state
  end
  def writefqdn(state,{ip,port}) do
#    Logger.debug("BOOM: " <> inspect state)
    state
  end


  def extractSubject({:error, error}) do
    {:error, error}
  end
  def extractSubject({:final, final}) do
    {:final, final}
  end
  def extractSubject({:ok, serialNumber, cert, decoded, issuer}) do
    {:OTPCertificate,                                                                                                                                                 
       {:OTPTBSCertificate,
         _version,
         serialNumber, # Integer, good as is
         signature,    # binary
         _theissuer,
         _validity,
         {:rdnSequence, subject},
         _subjectpublickey,
         _issuerUniqueID,
         _subjectUniqueID,
         extensions},_,_} = decoded

    fqdn = filterSubject(List.flatten(subject) |> Enum.filter(fn({_,oid,value}) -> if (oid == OID.txt2oid("id-at-commonName")) do value end end))
    subAlts = filterSubs(List.flatten(extensions) |> Enum.filter(fn({_,oid,_,value}) -> if (oid == OID.txt2oid("id-ce-subjectAltName")) do value end end)) 
              |> Enum.filter(fn(x) -> x end)

    {:ok, serialNumber, cert, fqdn, subAlts, decoded, issuer}

  end

  defp filterSubject([]) do
    []
  end
  defp filterSubject([{_,_,{_,fqdn}}]) do
    fqdn
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
  def extractRdn({:ok, serialNumber, cert, rdnSeq}) do
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
    :ssl.close(sslsocket)
    certresp
  end
  def haveCert?({:error, error}) do
    {:error, error}
  end















  def handle_cast({:ip, {ip, port}}, state) do
    case SSLShadowDB.IP.read!({ip, port}) do
      %SSLShadowDB.IP{cachetime: cachetime, state: state}
          -> #Logger.debug("Item is in cache - check age")
             if ((cachetime + Application.get_env(:sslshadow, :ipcache)) < ts) do
               Logger.debug(to_string(ip) <> ": I expired from cache, purge and re-submit")
               Amnesia.transaction do
                 SSLShadowDB.IP.delete({ip, port})
               end

             GenServer.cast(self, {:ip, {ip, port}})
               {:noreply, state}
             else
               Logger.debug(to_string(ip) <> ": " <> Integer.to_string(cachetime - (ts - Application.get_env(:sslshadow, :ipcache))) <> "s remain in cache")
               {:noreply, state}
             end
             {:noreply, state}
      nil ->  case (Sslshadow.SSL.testcon({ip, port}) |> receivecert) do
        {:error, posixerror} -> Logger.debug(to_string(ip) <> ": POSIX error on connection")
             SSLShadowDB.IP.write!(%SSLShadowDB.IP{ip: {ip, port}, cachetime: ts, state: posixerror})
             {:noreply, state}
      [ipstruct, certstruct] -> ipstruct = Map.put(ipstruct, :ip, {ip, port})
                                ipstruct = Map.put(ipstruct, :cachetime, ts)

             SSLShadowDB.IP.write!(ipstruct)
             SSLShadowDB.Certs.write!(certstruct)
             case ipstruct.state do
               :valid -> Logger.debug(to_string(ip) <> ": Validated Certificate retrieved - " <> Integer.to_string(ipstruct.serial))
               {:tls_alert, error} -> Logger.debug(to_string(ip) <> ": TLS Errored Certificate - " <> to_string(error) <> " - " 
                                      <> Integer.to_string(ipstruct.serial))
             end
#            IO.inspect [ipstruct, certstruct]
             {:noreply, state}
      end
    end
  end

  def receivecert({:ok, cert}) do
#    Logger.debug("Sslshadow.Proc: Got validated certificate")
    [ipstruct, certstruct] = Sslshadow.SSL.decode_cert(cert) 
      ipstruct = Map.put(ipstruct, :state, :valid)
    certstruct = Map.put(certstruct, :state, :valid)
    [ipstruct, certstruct]
  end
  def receivecert({err = {:tls_alert, tlserror}, cert}) do
#    Logger.debug("Sslshadow.Proc: Got cert that failed validation")
    [ipstruct, certstruct] = Sslshadow.SSL.decode_cert(cert) 
      ipstruct = Map.put(ipstruct, :state, err)
    certstruct = Map.put(certstruct, :state, err)
    [ipstruct, certstruct]
  end
  def receivecert({:error, posixerror}) do
#    Logger.debug("Sslshadow.Proc: We have ourselves a POSIX error: ")
    {:error, posixerror}
  end
  def receivecert({:timeout, posixerror}) do
#    Logger.debug("Sslshadow.Proc: We have ourselves a timeout error: ")
    {:error, posixerror}
  end
  
  def ts do
    {a,b,_} = :os.timestamp
    (a * 1000000) + b
  end





end

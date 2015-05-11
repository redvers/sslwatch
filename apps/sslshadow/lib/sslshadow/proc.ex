require Logger
defmodule Sslshadow.Proc do
  use Amnesia
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], [])
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

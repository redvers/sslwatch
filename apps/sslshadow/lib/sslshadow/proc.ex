require Logger
defmodule Sslshadow.Proc do
  use Amnesia
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], [])
  end

  def handle_cast({:ip, {ip, port}}, state) do
    case SSLShadowDB.IP.read!({ip, port}) do
      %SSLShadowDB.IP{cachetime: cachetime, state: state} -> Logger.debug("Item is in cache - check age")
                                                             if (cachetime > (ts + Application.get_env(:sslshadow, :ipcache))) do
                                                               Logger.debug("I expired - purge")
                                                               Amnesia.transaction do
                                                                 SSHShadowDB.IP.delete({ip, port})
                                                               end

                                                               GenServer.cast(self, {:ip, {ip, port}})
                                                               {:noreply, state}
                                                             else
                                                               Logger.debug(Integer.to_string(cachetime - (ts - Application.get_env(:sslshadow, :ipcache))) <> " seconds remain")
                                                               {:noreply, state}
                                                             end


      
             {:noreply, state}
      nil ->  case (Sslshadow.SSL.testcon({ip, port}) |> receivecert) do
                                   nil -> Logger.debug("Time to negative-cache")
                                          {:noreply, state}
                [ipstruct, certstruct] -> [ipstruct, certstruct] = Sslshadow.SSL.testcon({ip, port}) |> receivecert
                                          ipstruct = Map.put(ipstruct, :ip, {ip, port})
                                          ipstruct = Map.put(ipstruct, :cachetime, ts)

                                          SSLShadowDB.IP.write!(ipstruct)

                                          IO.inspect [ipstruct, certstruct]
                                          {:noreply, state}
              end
    end
  end

  def receivecert({:ok, cert}) do
    Logger.debug("Sslshadow.Proc: Got validated certificate - " <> inspect cert)
    [ipstruct, certstruct] = Sslshadow.SSL.decode_cert(cert) 
      ipstruct = Map.put(ipstruct, :state, :valid)
    certstruct = Map.put(certstruct, :state, :valid)
    [ipstruct, certstruct]
  end
  def receivecert({err = {:tls_alert, tlserror}, cert}) do
    Logger.debug("Sslshadow.Proc: Got cert that failed validation - " <> inspect cert)
    [ipstruct, certstruct] = Sslshadow.SSL.decode_cert(cert) 
      ipstruct = Map.put(ipstruct, :state, err)
    certstruct = Map.put(certstruct, :state, err)
    [ipstruct, certstruct]
  end
  def receivecert({:error, posixerror}) do
    Logger.debug("Sslshadow.Proc: We have ourselves a POSIX error: " <> inspect posixerror)
    nil
  end
  
  def ts do
    {a,b,_} = :os.timestamp
    (a * 1000000) + b
  end





end

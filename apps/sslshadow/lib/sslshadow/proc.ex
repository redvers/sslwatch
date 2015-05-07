require Logger
defmodule Sslshadow.Proc do
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], [])
  end

#  def handle_cast({:ip, {ip, port}}, state) do
#    case Sslshadow.SSL.testcon({ip, port}) do
#      {:ok, cert} -> Logger.debug("Got validated certificate - " <> inspect cert)
#      {{:tls_alert, tlserror}, cert} -> Logger.debug("Got cert that failed validation - " <> inspect cert)
#      {:error, posixerror} -> Logger.debug("We have ourselves a POSIX error: " <> inspect posixerror)
#    end
#    {:noreply, state}
#  end
  def handle_cast({:ip, {ip, port}}, state) do
    Sslshadow.SSL.testcon({ip, port})
    |> receivecert
    {:noreply, state}
  end

  def receivecert({:ok, cert}) do
    Logger.debug("Got validated certificate - " <> inspect cert)
    Sslshadow.SSL.decode_cert(cert) |> IO.inspect
#  5   deftable IP, [:ip, :serial, :keyid, :signingkeyid, :state, :cachetime], type: :set do end 
#  6   deftable Certs, [:serial, :keyid, :signingkeyid, :state, :firstseen, :blob], type: :set do end

  end
  def receivecert({{:tls_alert, tlserror}, cert}) do
    Logger.debug("Got cert that failed validation - " <> inspect cert)
    Sslshadow.SSL.decode_cert(cert) |> IO.inspect
  end
  def receivecert({:error, posixerror}) do
    Logger.debug("We have ourselves a POSIX error: " <> inspect posixerror)
  end
  






end

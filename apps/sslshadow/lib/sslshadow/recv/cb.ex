require Logger
defmodule Sslshadow.Recv.CB do
  use Cbserverapi

  def start_link() do
    GenServer.start_link(__MODULE__, {"ingress.event.netconn", []}, name: String.to_atom("CB_ingress.event.netconn"))
  end

  def handle_info(full_message = {
    {:"basic.deliver", _consumer_tag, delivery_tag, _redelivered, "api.events", "ingress.event.netconn"},
    {:amqp_msg, {:P_basic, "application/protobuf", _, _, _, _, _, _, _, _, _, _, _, _, _},
    binary}}, state) do

    ds4 = %Cbprotobuf4.CbEventMsg{
      env: %Cbprotobuf4.CbEnvironmentMsg{
        endpoint: %Cbprotobuf4.CbEndpointEnvironmentMsg{
          HostId: _, SensorHostName: sensorhostname, SensorId: sensorid
        }
      },
      network: %Cbprotobuf4.CbNetConnMsg{ 
        ipv4Address: ipv4int,
        outbound: outbound,
        port: portint,
        protocol: protocol, # :ProtoTcp
        utf8_netpath: fqdn
      },
    } = Cbprotobuf4.CbEventMsg.decode(binary)

    if (fqdn == nil) do
      fqdn = ""
    end

    <<e,f>> = <<portint :: size(16)>>
    port    = (f * 0x100) + e

    if (is_integer(ipv4int)) do
      procipv4({ipv4int, port, fqdn})
      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  def procipv4({ipv4int, 443, fqdn}) do
    emit_ipv4ssl({ipv4int, 443, fqdn})
  end
  def procipv4({ipv4int, _portnum, _fqdn}) do
    :ok # IPv4 but not a requested SSL port
  end

  def emit_ipv4ssl({ipv4int, port, fqdn}) do
    <<a,b,c,d>> = <<ipv4int :: size(32)>>

    ipaddr = Integer.to_string(d) <> "." <>
             Integer.to_string(c) <> "." <>
             Integer.to_string(b) <> "." <>
             Integer.to_string(a)

    Sslshadow.Proc.Supervisor.fipin({ipaddr, port})
    Logger.debug("SSL Dispatch Got: #{fqdn} ->" <> ipaddr <> ":" <> Integer.to_string(port))
    :ok
  end


end

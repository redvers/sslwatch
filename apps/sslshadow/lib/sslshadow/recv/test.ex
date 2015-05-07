require Logger

defmodule Sslshadow.Recv.Test do
  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, nil, [name: Sslshadow.Recv.Test])
  end

  def inject({ip, port}) do
    GenServer.cast(Sslshadow.Recv.Test, {ip, port})
  end



  def handle_cast(any, state) do
    Logger.debug(inspect any)
    :poolboy.transaction(:sslproc, fn(wpid) -> Sslshadow.Recv.Test.dispatch(wpid, any) end )
    {:noreply, state}
  end

  def dispatch(wpid, {ip, port}) do
    Logger.debug("Dispatching #{ip} to " <> inspect wpid)
    GenServer.cast(wpid, {:ip, {ip, port}})
  end
end


require Logger

defmodule Sslshadow.Recv.Test do
  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, nil, [name: Sslshadow.Recv.Test])
  end

  def handle_cast(any, state) do
    Logger.debug(inspect any)
    {:noreply, state}
  end

end


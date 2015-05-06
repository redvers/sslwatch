require Logger
defmodule Sslshadow.Proc do
  use GenServer

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], [])
  end

  def handle_cast({:ip, ip}, state) do
    Logger.info("Worker has #{ip}")
    


    {:noreply, state}
  end


end

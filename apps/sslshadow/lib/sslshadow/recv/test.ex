require Logger

defmodule Sslshadow.Recv.Test do
  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, nil, [name: Sslshadow.Recv.Test])
  end

  def inject({ip, port}) do
    GenServer.cast(Sslshadow.Recv.Test, {ip, port})
  end
  def injectc({ip, port}) do
    GenServer.call(Sslshadow.Recv.Test, {ip, port}, 20000)
  end

  def iptest do
    stream = File.stream!("74.0-8")
    Enum.map(stream, &(Regex.replace(~r/\n/, &1, "")))
    |> Enum.map(&to_char_list/1)
  end


  def nettest do
    File.read!(Application.get_env(:testenv, :dir))
    |> String.split("\n")
    |> Enum.map(&to_char_list/1)
    |> Enum.filter(&validFQDN?/1)
    |> Enum.map(&(Process.spawn(Sslshadow.Recv.Test, :spawnHostname, [&1], [])))
  end

  def tupleToCharIP({a,b,c,d}) do
    a = Integer.to_string(a)
    b = Integer.to_string(b)
    c = Integer.to_string(c)
    d = Integer.to_string(d)
    Enum.join([a,b,c,d], ".")
    |> to_char_list
  end

  def spawnHostname(charlist) do
    case validResponse?(:inet_res.getbyname(charlist, :a)) do
              nil -> Logger.debug("No A records for " <> to_string(charlist))
       {:hostent, _,_,_,_, data} -> #IO.inspect data
                                    Enum.map(data, &tupleToCharIP/1)
                                    |> Enum.map(fn(ipchar) -> inject({ipchar, 443}) end )
    end
  end





  defp validResponse?({:ok, response}) do
    response
  end
  defp validResponse?(response) do
    nil
  end


  defp validFQDN?([]) do
    nil
  end
  defp validFQDN?(charlist) do
    charlist
  end


  def handle_call(any, _from, state) do
    #Logger.debug(inspect any)
    :poolboy.transaction(:sslproc, fn(wpid) -> Sslshadow.Recv.Test.dispatch(wpid, any) end )
    {:reply, :ok, state}
  end


  def handle_cast(any, state) do
    #Logger.debug(inspect any)
    :poolboy.transaction(:sslproc, fn(wpid) -> Sslshadow.Recv.Test.dispatch(wpid, any) end )
    {:noreply, state}
  end

  def dispatch(wpid, {ip, port}) do
    #Logger.debug("Dispatching #{ip} to " <> inspect wpid)
    GenServer.cast(wpid, {:ip, {ip, port}})
  end
end


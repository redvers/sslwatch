require Logger

defmodule Sslshadow.Recv.Test do
  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, nil, [name: Sslshadow.Recv.Test])
  end

  def inject({ip, port}) do
    GenServer.cast(Sslshadow.Recv.Test, {ip, port})
  end

  def nettest do
    File.read!(Application.get_env(:testenv, :dir))
    |> String.split("\n")
    |> Enum.map(&to_char_list/1)
    |> Enum.filter(&validFQDN/1)
    |> Enum.map(&(:inet_res.getbyname(&1, :a)))
    |> Enum.filter(&validResponse?/1)
    |> Enum.map(fn({:ok, {_,_,_,_,_,list}}) -> list end )
    |> List.flatten
    |> Enum.map(&tupleToCharIP/1)
    |> Enum.map(fn(ipchar) -> inject({ipchar, 443}) end)

  end

  def tupleToCharIP({a,b,c,d}) do
    a = Integer.to_string(a)
    b = Integer.to_string(b)
    c = Integer.to_string(c)
    d = Integer.to_string(d)
    Enum.join([a,b,c,d], ".")
    |> to_char_list

  end





  defp validResponse?({:ok, response}) do
    response
  end
  defp validResponse?(response) do
    nil
  end


  defp validFQDN([]) do
    nil
  end
  defp validFQDN(charlist) do
    charlist
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


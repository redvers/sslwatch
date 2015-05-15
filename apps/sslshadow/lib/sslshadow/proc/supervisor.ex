defmodule Sslshadow.Proc.Supervisor do
  use Supervisor

  def start_link do
    Supervisor.start_link(__MODULE__, [], [name: Sslshadow.Proc.Supervisor])
  end

  def init([]) do
    poolsize = Application.get_env(:sslshadow, :poolsize)
    poolover = Application.get_env(:sslshadow, :poolover)
    pool_options = [
      name: {:local, :sslproc},
      worker_module: Sslshadow.Proc,
      size: poolsize,
      max_overflow: poolover
    ]

    children = [
      :poolboy.child_spec(:sslproc, pool_options, [])
    ]

    supervise(children, strategy: :one_for_one)
  end

  def fipin({ip,port}) do
    ip = to_char_list(ip)
    case SSLShadowDB.Cache.inMemCache?({ip,port}) do
      :hit    -> :ok
      :purged -> spawn(Sslshadow.Proc.Supervisor, :dispatch, [{ip,port}])
        :miss -> spawn(Sslshadow.Proc.Supervisor, :dispatch, [{ip,port}])
      #:purged -> :poolboy.transaction(:sslproc, fn(worker)-> :gen_server.call(worker, {ip, port}) end)
      #  :miss -> :poolboy.transaction(:sslproc, fn(worker)-> :gen_server.call(worker, {ip, port}) end)
      #  :miss -> :poolboy.transaction(:sslproc, fn(wpid) -> spawn(GenServer, :call, [wpid, {ip,port}]) end )
      #:purged -> :poolboy.transaction(:sslproc, fn(wpid) -> spawn(GenServer, :call, [wpid, {ip,port}]) end )
      #:miss   -> :poolboy.transaction(:sslproc, fn(wpid) -> spawn(GenServer, :call, [wpid, {ip,port}]) end )
    end
  end

  def dispatch({ip,port}) do
    :poolboy.transaction(:sslproc, fn(worker)-> :gen_server.call(worker, {ip, port}) end, :infinity) 
  end




end

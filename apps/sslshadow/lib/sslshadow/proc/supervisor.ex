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


end

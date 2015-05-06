defmodule Sslshadow.Proc.Supervisor do
  use Supervisor

  def start_link do
    Supervisor.start_link(__MODULE__, [], [name: Sslshadow.Proc.Supervisor])
  end

  def init([]) do
    pool_options = [
      name: {:local, :sslproc},
      worker_module: Sslshadow.Proc,
      size: 10,
      max_overflow: 11
    ]

    children = [
      :poolboy.child_spec(:sslproc, pool_options, [])
    ]

    supervise(children, strategy: :one_for_one)
  end


end

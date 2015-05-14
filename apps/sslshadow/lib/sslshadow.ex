require Logger
defmodule Sslshadow do
  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    case Amnesia.Table.exists?(SSLShadowDB.IPPersist) do
       false -> Amnesia.stop
                Amnesia.Schema.destroy
                Amnesia.Schema.create
                Amnesia.start
                SSLShadowDB.IPPersist.create(disk: [node])
        true -> :ok
    end
    case Amnesia.Table.exists?(SSLShadowDB.CertPersist) do
       false -> SSLShadowDB.CertPersist.create(disk: [node])
        true -> :ok
    end
    case Amnesia.Table.exists?(SSLShadowDB.DomainPersist) do
       false -> SSLShadowDB.DomainPersist.create(disk: [node])
        true -> :ok
    end

    SSLShadowDB.IPMemCache.create
    Amnesia.info

    children = [
      # Define workers and child supervisors to be supervised
      worker(Sslshadow.Recv.Test, []),# , [arg1, arg2, arg3])
      worker(Sslshadow.Proc.Supervisor, [])# , [arg1, arg2, arg3])
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sslshadow.Supervisor]
    Supervisor.start_link(children, opts)


  end
end

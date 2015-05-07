require Logger
defmodule Sslshadow do
  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    case Amnesia.Table.exists?(SSLShadowDB.Certs) do
       false -> Logger.debug("SSLShadowDB.Certs to be created")
                SSLShadowDB.Certs.create(disk: [node])
        true -> Logger.debug("Database already exists on disk... reading...")
    end

    ## Create in-memory cache
    SSLShadowDB.IP.create

    children = [
      # Define workers and child supervisors to be supervised
      worker(Sslshadow.Recv.Test, []),# , [arg1, arg2, arg3])
      worker(Sslshadow.Proc.Supervisor, [])# , [arg1, arg2, arg3])
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sslshadow.Recv.Supervisor]
    Supervisor.start_link(children, opts)


  end
end

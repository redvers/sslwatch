defmodule Sslshadow.Proc.Supervisor do
  use Supervisor

  def start_link do
    Supervisor.start_link(__MODULE__, [], [name: Sslshadow.Proc.Supervisor])
  end

  def init([]) do
    children = []
    supervise(children, strategy: :one_for_one)
  end


end

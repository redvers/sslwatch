use Amnesia
require Logger

defdatabase SSLShadowDB do
  deftable IP, [:ip, :serial, :keyid, :signingkeyid, :state, :cachetime], type: :set do end
  deftable Certs, [:serial, :keyid, :signingkeyid, :state, :firstseen, :blob], type: :set do end
end

defmodule SSLShadowDB.Cache do
  def check(ip) do
    SSLShadowDB.IP.read!(ip)
    |> checkvalid
    |> checkexpired
  end

  def writecache(cacheval = %SSLShadowDB.IP{}) do
    SSLShadowDB.IP.write!(cacheval)
  end






  defp checkvalid(nil) do
    nil
  end
  defp checkvalid(cachedata) do
    cachedata
  end
    
  defp checkexpired(nil) do
    nil
  end
  defp checkexpired(cachedata = %SSLShadowDB.IP{cachetime: cachetime}) do
    cond do
      cachetime < ts -> :expired
      cachetime > ts -> cachedata
    end
  end

  defp ts do
    {ms,s,_} = :os.timestamp
    (ms * 1000000) + s
  end

end



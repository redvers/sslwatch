use Amnesia
require Logger

#  deftable IP, [:ip, :serial, :keyid, :signingkeyid, :state, :cachetime], type: :set do end
#  deftable Certs, [:serial, :keyid, :signingkeyid, :state, :firstseen, :blob], type: :bag do end
#  deftable Domains, [:domain, :serial, :keyid], type: :bag do end
defdatabase SSLShadowDB do
  deftable IP, [:ip, :serial, :keyid, :signingkeyid, :state, :cachetime], type: :set do end
  deftable Certs, [:serial, :keyid, :signingkeyid, :state, :firstseen, :blob], type: :bag do end
  deftable Domains, [:domain, :serial, :keyid], type: :bag do end

  deftable IPMemCache, [:ip, :cachetime, :state], type: :set do end
  deftable IPPersist, [:ip, :issueid, :state, :timestamp], type: :bag do end
  deftable CertPersist, [:issueid, :keyid, :signingkeyid, :blob], type: :set do end
  deftable DomainPersist, [:domain, :issueids], type: :set do end
end

defmodule SSLShadowDB.Cache do
  def inMemCache?({ip,port}) do
    case SSLShadowDB.IPMemCache.read!({ip,port}) do
      nil -> :miss
      %SSLShadowDB.IPMemCache{cachetime: cachetime}
          -> cond do
               cachetime <= ts -> SSLShadowDB.IPMemCache.delete!({ip,port})
                                 :purged
               cachetime > ts -> :hit
             end
    end
  end
  def inCache?({ip,port}) do
    case SSLShadowDB.IP.read!({ip,port}) do
      nil -> :miss
      %SSLShadowDB.IP{cachetime: cachetime}
          -> cond do
               cachetime < ts -> SSLShadowDB.IP.delete!({ip,port})
                                 :purged
               cachetime > ts -> :hit
             end
    end
  end

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



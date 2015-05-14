use Amnesia
require Logger

defdatabase SSLShadowDB do
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

  defp ts do
    {ms,s,_} = :os.timestamp
    (ms * 1000000) + s
  end

end



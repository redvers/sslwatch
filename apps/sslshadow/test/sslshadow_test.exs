defmodule SslshadowTest do
  use ExUnit.Case

  :ok = SSLShadowDB.IP.create()
  :ok = SSLShadowDB.Certs.create()

  {ms,s,_} = :os.timestamp
  utime = (ms*1000000) + s 
  future = utime + 1000
  expire = utime - 1000

  @examplestruct %SSLShadowDB.IP{ip: "127.0.0.1", keyid: 0xbadf00d, signingkeyid: 0xabad1dea, state: :valid, cachetime: future}
  @expiredstruct %SSLShadowDB.IP{ip: "127.0.0.2", keyid: 0xbadf01d, signingkeyid: 0xabad2dea, state: :valid, cachetime: expire}

  SSLShadowDB.Cache.writecache(@examplestruct)
  SSLShadowDB.Cache.writecache(@expiredstruct)
  
  test "no result" do
    assert :nil = SSLShadowDB.Cache.check("invalidip")
  end

  test "cached result" do
    assert @examplestruct = SSLShadowDB.Cache.check("127.0.0.1")
  end

  test "expired result" do
    assert :expired = SSLShadowDB.Cache.check("127.0.0.2")
  end
  



end

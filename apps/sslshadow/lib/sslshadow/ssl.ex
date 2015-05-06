defmodule Sslshadow.SSL do
  require Logger
  def testcon({ip, port}) do
    testcon({:validate, ip, port})
  end
  def testcon({:validate, ip, port}) do
    case :ssl.connect(to_char_list(ip), port, [{:verify, :verify_peer}, {:cacertfile, "/etc/ssl/certs/ca-certificates.crt"}], :infinity) do
      {:ok, sslsock}   -> Logger.debug("Got valid certificate")
                          validcert(:valid, ip,sslsock, :ok)
      {:error, reason} -> failure(ip, reason)
                          Logger.debug("Error detected: " <> inspect reason)
#                          testcon({:novalidate, ip, port, reason})
      reason           -> Logger.debug("I should never happen" <> inspect reason)
                          testcon({:novalidate, ip, port, reason})
    end
  end
  def testcon({:novalidate, ip, port, reason}) do
    case :ssl.connect(to_char_list(ip), port, [], :infinity) do
      {:ok, sslsock}   -> Logger.debug("Got unvalidated certificate and reason: " <> inspect reason)
                          validcert(:failedvalidation, ip, sslsock, reason)
      {:error, reason} -> failure(ip, reason)
      reason           -> Logger.debug("I should never happen" <> inspect reason)
    end
  end

  def validcert(status, ip, sslsock, reason) do
    case :ssl.peercert(sslsock) do
      {:ok, cert} -> :ssl.close(sslsock)
                     processcert({status, ip, cert, status})
      {:error, reason} -> Logger.debug("I don't exist" <> inspect reason)
                          :ssl.close(sslsock)
    end
  end

  def failure(ip,freason = {:tls_alert, _}) do
    Logger.debug("TLS Issue #{ip}: " <> inspect freason)
  end

  def failure(ip, reason) when is_atom(reason) do
    case :erl_posix_msg.message(reason) do
      'unknown POSIX error' -> Logger.debug("I truely have no idea what this is on #{ip}..." <> Atom.to_string(reason))
      humanreadable -> Logger.debug("POSIX error: " <> to_string(humanreadable))
    end
  end

  def failure(ip, reason) do
    Logger.debug("Lost in the wildreness... I dunno bob - notify me " <> inspect reason)
  end

  def processcert({:failedvalidation, _ip, cert, reason}) do
    Logger.debug("Cert failed validation, examine anyways... " <> inspect reason)
    :public_key.pkix_decode_cert(cert, :otp)
    |> IO.inspect 
  end
  def processcert({:valid, _ip, cert, :valid}) do
    Logger.debug("Cert is valid, work to do")
    :public_key.pkix_decode_cert(cert, :otp)
    |> IO.inspect 
  end



#  def failure(ip, :) do
#    Logger.debug("Network Issue: connection refused #{ip}")
#  end





  # :ssl.connect('www.google.com', 443, [], :infinity)
  # {:ok, cert} = :ssl.peercert(sslsocket)
  # :public_key.pkix_decode_cert(cert, :otp)
  # 174.0>}}
  # iex(21)> {:ok, sslsocket} = :ssl.connect('www.pcwebshop.co.uk', 443, [{:verify, :verify_peer}, {:cacertfile, "/Users/red/project s/sslshadow/ca-certificates.crt"}], :infinity)


end

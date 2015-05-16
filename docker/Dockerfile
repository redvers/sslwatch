#FROM nifty/elixir
FROM splattael/elixir
MAINTAINER Redvers Davies <red@infect.me>

RUN useradd -m sslwatch 
USER sslwatch
WORKDIR /home/sslwatch

RUN git clone https://github.com/redvers/sslwatch.git > /home/sslwatch/stdout 2>/home/sslwatch/stderr
WORKDIR /home/sslwatch/sslwatch
RUN yes | mix deps.get
RUN yes | mix deps.compile
RUN mix compile



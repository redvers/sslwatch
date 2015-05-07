use Mix.Config
import_config "../apps/*/config/config.exs"

config :sslshadow, ssltimeout:  3000,   # Number of ms to connect to remote server
                   cafile: "/etc/ssl/certs/ca-certificates.crt", # File containing acceptable CAs
                   ipcache: 3600,        # Number of seconds we should trust the certificate cache
                   negcache: 600,        # Number of seconds we should cache a negative
                   poolsize:  10,        # Number of "pre-forked" ssl server processes
                   poolover:  1000       # Number of extra pool members to be spawned before
                                         # we start queuing


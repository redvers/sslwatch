use Mix.Config
import_config "../apps/*/config/config.exs"

config :sslshadow, ssltimeout:  3000,   # Number of ms to connect to remote server
                   cafile: "/etc/ssl/certs/ca-certificates.crt", # File containing acceptable CAs
                   ipcache: 300,        # Number of seconds we should trust the certificate cache
                   negcache: 20,        # Number of seconds we should cache a negative
                   poolsize: 100,        # Number of "pre-forked" ssl server processes
                   poolover: 5      # Number of extra pool members to be spawned before
                                         # we start queuing
config :mnesia,     dir: '/home/sslwatch/mnesia-data', # Yes, must be single quotes
                    dc_dump_limit:  100,
                    dump_log_write_threshold: 100000 

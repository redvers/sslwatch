use Mix.Config
import_config "../apps/*/config/config.exs"

config :sslshadow, ssltimeout:  3000,   # Number of ms to connect to remote server
                   cafile: "/etc/ssl/certs/ca-certificates.crt", # File containing acceptable CAs
                   ipcache: 300,        # Number of seconds we should trust the certificate cache
                   negcache: 20,        # Number of seconds we should cache a negative
                   poolsize: 100,        # Number of "pre-forked" ssl server processes
                   poolover: 5      # Number of extra pool members to be spawned before
                                         # we start queuing
config :mnesia,     dir: '/home/red/projects/sslwatch/mnesia-data', # Yes, must be single quotes
                    dc_dump_limit:  100,
                    dump_log_write_threshold: 100000 
#config :testenv,    dir: '/home/red/projects/sslwatch/apps/sslshadow/test/testdata' # Yes, MUST be single quotes
config :testenv,    dir: '/home/red/projects/sslwatch/apps/sslshadow/test/testdata-orig' # Yes, MUST be single quotes
config  :sasl,    error_logger_mf_dir: '/home/red/projects/sslwatch/sasl-data',
                  error_logger_mf_maxbytes: 10000,
                  error_logger_mf_maxfiles: 100

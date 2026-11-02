# Durable OpenBao: integrated (raft) storage on a named volume, sealed at rest, initialised and unsealed by
# bin/openbao-bootstrap.sh. Not dev mode: nothing is kept in memory only, and a restart comes back sealed.
ui            = false
disable_mlock = true
api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "selfhost-1"
}

# Plain HTTP stays inside the compose network and the loopback port. Put TLS in front before any other host reaches it.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

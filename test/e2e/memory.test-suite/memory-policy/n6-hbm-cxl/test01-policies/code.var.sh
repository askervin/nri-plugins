helm-terminate
helm_config=$(instantiate helm-config.yaml) helm-launch memory-policy

ANN0="class.memory-policy.nri.io: interleave-all" \
ANN1="policy.memory-policy.nri.io/container.pod0c1: |+
      mode: MPOL_BIND
      nodes: 4,5
      flags:
      - MPOL_F_STATIC_NODES" \
ANN2="class.memory-policy.nri.io/container.pod0c2: interleave-cpu-nodes" \
CONTCOUNT=3 \
create besteffort

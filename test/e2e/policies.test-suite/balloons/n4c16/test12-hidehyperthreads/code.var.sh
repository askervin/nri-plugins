# This test verifies that hideHyperthreads allocates all CPUs into a
# balloon but does not allow containers to run on more than one
# allocated CPU on each physical core.

helm-terminate
helm_config=$TEST_DIR/balloons-hidehyperthreads.cfg helm-launch balloons

POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: quad-core-singlethread"
CONTCOUNT=2 create balloons-busybox
verify 'cpus["pod0c0"] == cpus["pod0c1"]' \
       'len(cpus["pod0c0"]) == 4' \
       'len(cores["pod0c0"]) == 4'

POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: shared-singlethread"
CPUREQ=100m create balloons-busybox
# TODO: get all physical cores from a NUMA

POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: exclusive-singlethread"
CPUREQ=6 create balloons-busybox
# TODO: allocate 6 but use 3 CPUs without hyperthreads


breakpoint

exit 1

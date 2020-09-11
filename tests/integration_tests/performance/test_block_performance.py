# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for block device emulation."""
import json
import logging
import os
import pytest
import shutil

import framework.utils as utils
import host_tools.drive as drive_tools
import host_tools.network as net_tools  # pylint: disable=import-error
import framework.statistics as st


# Block device size in MB.
BLOCK_DEVICE_SIZE = 2048
# Iteration duration in seconds.
ITERATION_DURATION = 60 * 5

FIO_BLOCK_SIZES = [65536, 4096, 1024, 512]
FIO_TEST_MODES = ["randread", "randrw", "read", "readwrite"]

log = logging.getLogger("blk")

cpu_usage = r"""
BEGIN {
  prev_total = 0
  prev_idle = 0
  while (getline < \"/proc/stat\") {
    close(\"/proc/stat\")
    idle = \$5
    total = 0
    for (i=2; i<=NF; i++)
      total += \$i
    print (1.0-(idle-prev_idle)/(total-prev_total))*100
    prev_idle = idle
    prev_total = total
    system(\"sleep 1\")
  }
}
"""


def run_fio(args):
    """Run a fio test in the specified mode with block size bs."""
    # Clear host page cache first.
    os.system("sync; echo 1 > /proc/sys/vm/drop_caches")

    # Use noop scheduler.
    # Depending on the platform, we might write into SCSI disk or NVME disk.
    os.system("echo 'none' > /sys/block/sda/queue/scheduler")
    os.system("echo 'none' > /sys/block/nvme2n1/queue/scheduler")

    # Compute the fio command
    mode = args[1]
    bs = args[2]
    cmd = ("fio --name={mode}-{bs} --rw={mode} --bs={bs} --filename=/dev/vdb "
           "--time_based  --size={block_size}M --direct=1 --ioengine=libaio "
           "--iodepth=32 --numjobs=1  --randrepeat=0 --runtime={duration} "
           "--write_iops_log={mode}{bs} --write_bw_log={mode}{bs} "
           "--write_lat_log={mode}{bs} --log_avg_msec=1000 --status-interval=1 "
           "--output-format=json+").format(
        mode=mode, bs=bs, block_size=BLOCK_DEVICE_SIZE,
        duration=ITERATION_DURATION)

    # Use noop in the guest too
    ssh_connection = args[0]
    ssh_connection.execute_command(
        "echo 'noop' > /sys/block/sda/queue/scheduler")

    # Start the CPU usage parser
    ssh_connection.execute_command(f"echo \"{cpu_usage}\" > ~/cpu_usage.awk")
    rc, cpu_usage_output, stderr = ssh_connection.execute_command(
        f"timeout {ITERATION_DURATION} awk -f ~/cpu_usage.awk")

    # Print the fio command in the log and run it
    rc, stdout, stderr = ssh_connection.execute_command(cmd)
    assert rc == 0
    assert stderr.read() == ""

    if os.path.isdir(f"results/{mode}{bs}"):
        shutil.rmtree(f"results/{mode}{bs}")

    os.makedirs(f"results/{mode}{bs}")

    ssh_connection.scp_get_file("*.log", f"results/{mode}{bs}/")
    rc, stdout, stderr = ssh_connection.execute_command("rm *.log")
    assert rc == 0
    assert stdout

    json_output = stdout.read()
    with open(f"results/{mode}{bs}/output.json", "w") as f:
        f.write(json_output)

    return cpu_usage_output.read()


def extract_metrics(cons, ops, job):
    bw = {}
    bw["min"] = job[ops]["bw_min"]
    bw["max"] = job[ops]["bw_max"]
    bw["mean"] = job[ops]["bw_mean"]
    bw["stddev"] = job[ops]["bw_dev"]
    bw["samples"] = job[ops]["bw_samples"]
    cons.consume_result(f"bw_{ops}", bw)
    iops = {}
    iops["min"] = job[ops]["iops_min"]
    iops["max"] = job[ops]["iops_max"]
    iops["mean"] = job[ops]["iops_mean"]
    iops["samples"] = job[ops]["iops_samples"]
    iops["stddev"] = job[ops]["iops_stddev"]
    cons.consume_result(f"iops_{ops}", iops)

    cons.consume_result(f"slat_{ops}", job[ops]["slat_ns"])
    cons.consume_result(f"clat_{ops}", job[ops]["clat_ns"])
    cons.consume_result(f"lat_{ops}", job[ops]["lat_ns"])


def consume_fio_output(cons, _):
    pass
    # fio_output, cpu_usage = raw_res
    # job0 = fio_output["jobs"][0]
    # cons.consume_custom("fio_version", fio_output["fio version"])
    # cons.consume_custom("timestamp", fio_output["timestamp"])
    # cons.consume_custom("time", fio_output["time"])
    # cons.consume_custom("job_options", job0["job options"])

    # cpu_dict = {}
    # cpu_dict["unit"] = "second->percentage"
    # cpu_dict["result"] = {}
    # for idx, line in enumerate(cpu_usage.split()):
    #     cpu_dict["result"][idx] = line
    # cons.consume_custom("cpu_usage", cpu_dict)

    # extract_metrics(cons, "read", job0)
    # extract_metrics(cons, "write", job0)



def define_metrics():
    ms_defs = [st.consumer.MeasurementDef("iops_read", "io/s"),
               st.consumer.MeasurementDef("iops_write", "io/s"),
               st.consumer.MeasurementDef("bw_read", "KiB/s"),
               st.consumer.MeasurementDef("bw_write", "KiB/s"),
               st.consumer.MeasurementDef("slat_read", "ns"),
               st.consumer.MeasurementDef("slat_write", "ns"),
               st.consumer.MeasurementDef("clat_read", "ns"),
               st.consumer.MeasurementDef("clat_write", "ns"),
               st.consumer.MeasurementDef("lat_read", "ns"),
               st.consumer.MeasurementDef("lat_write", "ns")]
    return ms_defs


def define_stats():
    st_defs = [st.consumer.StatisticDef("iops_read", "iops_read",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("iops_write", "iops_write",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("bw_read", "bw_read",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("bw_write", "bw_write",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("slat_read", "slat_read",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("slat_write", "slat_write",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("clat_read", "clat_read",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("clat_write", "clat_write",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("lat_read", "lat_read",
                                        st.consumer.Method.last),
               st.consumer.StatisticDef("lat_write", "lat_write",
                                        st.consumer.Method.last)]
    return st_defs


@pytest.mark.timeout(ITERATION_DURATION * 1000)
@pytest.mark.nonci
def test_block_performance(test_microvm_with_ssh, network_config):
    """Execute block device emulation benchmarking scenarios."""

    microvm = test_microvm_with_ssh
    microvm.spawn()
    microvm.basic_config(
        mem_size_mib=1024,
        vcpu_count=4,
        boot_args="isolcpus=1-3 nohz_full=1-3 rcu_nocbs=1-3")

    # Add a secondary block device for benchmark tests.
    fs = drive_tools.FilesystemFile(
        os.path.join(microvm.fsfiles, 'scratch'),
        BLOCK_DEVICE_SIZE
    )

    response = microvm.drive.put(
        drive_id='scratch',
        path_on_host=microvm.create_jailed_resource(fs.path),
        is_root_device=False,
        is_read_only=False
    )
    assert microvm.api_session.is_status_no_content(
        response.status_code)

    _tap, _, _ = microvm.ssh_network_config(network_config, '1')

    microvm.start()
    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Get Firecracker PID so we can check the names of threads.
    firecracker_pid = microvm.jailer_clone_pid

    # Get names of threads in Firecracker.
    threads = utils.get_threads(firecracker_pid)
    utils.set_cpu_affinity(threads['firecracker'], [0])
    utils.set_cpu_affinity(threads['fc_api'], [1])
    utils.set_cpu_affinity(threads['fc_vcpu 0'], [2])
    utils.set_cpu_affinity(threads['fc_vcpu 1'], [3])
    utils.set_cpu_affinity(threads['fc_vcpu 2'], [4])
    utils.set_cpu_affinity(threads['fc_vcpu 3'], [5])

    st_core = st.core.Core("block_performance", iterations=1)
    # ms_defs = define_metrics()
    # st_defs = define_stats()
    for mode in FIO_TEST_MODES:
        for bs in FIO_BLOCK_SIZES:
            st_prod = st.producer.LambdaProducer(run_fio, ssh_connection, mode, bs)
            st_cons = st.consumer.LambdaConsumer(consume_fio_output, [], [], True)
            st_core.add_pipe(st_prod, st_cons, tag=f"{mode}-{bs}")
    stats = st_core.run_exercise()
    print(stats)
"""Deploy the verified production DW target, preserving owner configuration."""

import dw_client

with dw_client.pipeline_lock():
    dw_client.deploy()

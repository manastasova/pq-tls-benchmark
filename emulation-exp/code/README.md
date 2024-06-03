# KEX Simulation

1. Run `./install-prereqs-ubuntu.sh` to fetch, build, and install s2n and other
   dependencies
1. Modify `kex/experiment.py` to you liking for the given experiment
1. In one terminal, run the server process: `( cd kex/ && ./setup.sh )`
1. In another, create a virtual env
    ```
    python3 -m virtualenv .venv \
        && . .venv/bin/activate \
        && python3 -m pip install -r requirements.txt
    ```
1. Run the experiment client(s) and process the results
    ```
    pushd kex/ \
        && make \
        && python3 experiment.py \
        && popd \
        && python3 stats.py
    ```

Tested on the below system:
```
$ uname -a && cat /etc/*release | grep DESCRIPTION
Linux ip-172-31-89-138 6.2.0-1014-aws #14~22.04.1-Ubuntu SMP Thu Oct  5 22:43:45 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
```

# 🌷 Tulip

Tulip is a flow analyzer meant for use during Attack / Defence CTF competitions. It allows players to easily find some traffic related to their service and automatically generates python snippets to replicate attacks.
## Origins

This is [Srdnlen's](https://github.com/srdnlen) official fork of Tulip, a tool originally developed by the [European Cybersecurity Team](https://github.com/OpenAttackDefense/tulip).

We would also like to thank [Lorenzo Leonardini](https://github.com/LorenzoLeonardini/tulip) for some of the commits that were merged into this version.

Srdnlen's version of Tulip adds some features to the original tool, namely:

1. The exposition of a metrics endpoint at `/api/stats`, useful for integration with other measurement tools, like Grafana
2. The refactoring of the `api` microservice, to use `uv` instead of `pip`
3. The support for usage of suricata and the assembler microservice with PCAP-Over-IP

## Configuration
Before starting the stack, edit `services/api/configurations.py`:

```
vm_ip = "10.60.4.1"
services = [{"ip": vm_ip, "port": 18080, "name": "BIOMarkt"},
            {"ip": vm_ip, "port": 5555, "name": "SaaS"},
]
```


> After the grace period, be sure to set the correct mappings between flagstores and services in
`services/flagids/flagids.py`.


You can also edit this during the CTF, just rebuild the `api` service in the first case, or the `flagids` service in the second case:
```
docker-compose up --build -d api
docker-compose up --build -d flagids
```


## Usage

The stack can be started with docker-compose, after creating an `.env` file. See `.env.example` as an example of how to configure your environment.
```
cp .env.example .env
# < Edit the .env file with your favourite text editor >
docker-compose up -d --build
```

### Traffic Ingestion (PCAP-Over-IP)

To ingest traffic, the recommended approach requires using [PCAP-Over-IP](https://en.wikipedia.org/wiki/PCAP-over-IP) to dump traffic info directly from a socket. The steps to do this are:

1. Setup a pcap-broker that dumps PCAPs from a machine to a `TCP` port. The suggested tool is [UlisseLab's pcap-broker](https://github.com/UlisseLab/pcap-broker)
2. Configure the `PCAP_OVER_IP` env var under `.env` to point to the `IP:PORT` of the pcap-broker:
```env
PCAP_OVER_IP=10.x.x.x:yyyy
```
3. Start the stack. Tulip should be able to ingest traffic directly from the supplied port


### Traffic Ingestion (File)

If you prefer to read files directly, it is recommended to create a shared bind mount with the docker-compose. One convenient way to set this up is as follows:
1. Create a directory where pcaps will be saved:
```bash
mkdir ./pcaps
```
2. Run the following command:
```bash
ssh -q root@<vulnbox_ip> "tcpdump -i <game_interface> -U -s 0 -w - port <service_1_port> or <service_2_port> ..." | tcpdump -U -r - -G 180 -w "./pcaps/traffic_%H:%M:%S.pcap"
```
3. Change `TRAFFIC_DIR_HOST` in `.env` to match the directory where pcaps are dumped (`./pcaps`)

You can fine-tune the command at `2.` in this way:
1. Change `vulnbox_ip` to the IP of the machine of which you would like to dump the traffic
2. Change `game_interface` to the interface receiving the traffic on the target machine
3. Change `port <X> or port <Y> ...` according to BPF filter rules. For example, if you only care about HTTP(S) traffic, you can edit that part like `port 80 or port 443`
4. If you want, edit `-G 180` to customize pcap file rotation. The default option creates a new pcap dump every 3 minutes.

> [!WARNING]
>
> This configuration won't work if the architectures of the machines running tulip and tcpdump (the vulnbox) differ! In that case, refer to the [original guide](https://github.com/OpenAttackDefenseTools/tulip/tree/master#usage)

> [!WARNING]
>
> Srdnlen's fork does not support using Suricata when pcaps are dumped to files, as it only works in PCAP-over-IP mode. See below for further details.

The ingestor will use inotify to watch for new pcap's and suricata logs. No need to set a chron job.

## Suricata synchronization

### Initial configuration

> [!WARNING]
>
> Srdnlen's fork does not support using Suricata when pcaps are dumped to files, as it only works in PCAP-over-IP mode. See below for further details.

Configure `SURICATA_DIR_HOST` and `PCAP_OVER_IP` in `.env`.

Create the required directories for suricata files:

```bash
. .env
mkdir -p ${SURICATA_DIR_HOST}/{etc,lib/rules,log,socket}
```

You can then store your rules under `${SURICATA_DIR_HOST}/lib/rules`. Then, you can start the stack like normal.

### Ingestion modes

Srdnlen's fork supports alerts ingestion in two ways:

1. The classical mode, via an `eve.json` file
2. A faster and lighter mode using unix sockets.

#### Socket Ingestion Mode

To speed up alert propagation and avoid having too big `eve.json` file, you can switch to the socket mode. In order to do this, you must:

1. Edit `ENRICHER_MODE` to `socket` in your `.env`, as well as tune the values of `ENRICHER_WORKERS` and `ENRICHER_BUFFER_SIZE` (check the comments in `.env.example` for more details)
2. Change your `suricata.yml` to use a `socket` file to propagate alerts:
```yaml
- eve-log:
  enabled: yes
  filetype: unix_steam #regular|syslog|unix_dgram|unix_stream|redis
  filename: /var/run/suricata/eve.sock
```
3. Change your `docker-compose.yml` to edit the `command` section under the enricher's container:
```yaml
volumes:
    - ${TRAFFIC_DIR_HOST}:${TRAFFIC_DIR_DOCKER}:ro,z
    - ${SURICATA_DIR_HOST}/socket:/suricata
command: "./enricher -eve /suricata/eve.sock"
```

#### File Ingestion mode

Suricata alerts are read directly from the `eve.json` file. Because this file can get quite verbose when all extensions are enabled, it is recommended to strip the config down a fair bit. For example:

```yaml
# ...
  - eve-log:
      enabled: yes
      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      pcap-file: false
      community-id: false
      community-id-seed: 0
      types:
        - alert:
            metadata: yes
            # Enable the logging of tagged packets for rules using the
            # "tag" keyword.
            tagged-packets: yes
# ...
```

To enable this mode, set `ENRICHER_MODE` to `file` in your `.env` and specify the following configuration inside your `suricata.yml`:

```yaml
- eve-log:
  enabled: yes
  filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
  filename: /var/log/suricata/eve.json
```

And, inside your `docker-compose.yml`, change the `command` option under the enricher's container:

```yaml
volumes:
    - ${TRAFFIC_DIR_HOST}:${TRAFFIC_DIR_DOCKER}:ro,z
    - ${SURICATA_DIR_HOST}/socket:/suricata
    - ${SURICATA_DIR_HOST}/log:/log
command: "./enricher -eve /log/eve.json"
```

Sessions with matched alerts will be highlighted in the front-end and include which rule was matched.

> [!WARNING]
>
> I/O bottlenecks and file size can significantly slow down Tulip's tagging or crash suricata entirely. If you experience such problems, consider switching to socket mode (described above)

### Metadata
Tags are read from the metadata field of a rule. For example, here's a simple rule to detect a path traversal:
```
alert tcp any any -> any any (msg: "Path Traversal-../"; flow:to_server; content: "../"; metadata: tag path_traversal; sid:1; rev: 1;)
```
Once this rule is seen in traffic, the `path_traversal` tag will automatically be added to the filters in Tulip.

> [!NOTE]
>
> After editing Suricata rules (renaming or id change) please:
>
> Remove old logs: `rm ${SURICATA_DIR_HOST}/log/*` (otherwise old signatures will be repopulated).
>
> Restart Docker containers.
>
> If database was only restarted (not dropped), try cleaning tags/signatures manually.


# Security

Your Tulip instance will probably contain sensitive CTF information, like flags stolen from your machines. If you expose it to the internet and other people find it, you risk losing additional flags. It is recommended to host it on an internal network (for instance behind a VPN) or to put Tulip behind some form of authentication.

# Credits

A special thanks to Tulip's original creator and to pianka for their contribution to this project.
